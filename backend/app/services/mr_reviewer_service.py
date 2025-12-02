"""
MR/PR Reviewer Service for Automated Security Reviews

Provides automated security review functionality for GitLab merge requests
and GitHub pull requests:
- Phase 1: Quick diff analysis with inline comments
- Phase 2: Full security scan of changed files
- Polling mechanism for watching repositories
"""

import asyncio
import logging
import re
import tempfile
import os
import shutil
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union

from sqlalchemy.orm import Session

import fnmatch
from app.models.scanner_models import RepoWatcher, MRReview, ScanProfile, ProfileAnalyzer
from app.models.models import Scan, Finding, ScanStatus
from app.services.gitlab_service import GitLabService, GitLabError
from app.services.github_service import GitHubService, GitHubError
from app.services.llm_provider import llm_provider
from app.services.analysis.parsers import DraftParser
from app.core.database import SessionLocal

logger = logging.getLogger(__name__)


# Security review prompt for analyzing full file content
FILE_REVIEW_PROMPT = """You are a security code reviewer analyzing a source code file from a merge request.

Review the following file for security vulnerabilities. Focus on:
- Injection vulnerabilities (SQL, command, XSS, etc.)
- Authentication and authorization issues
- Sensitive data exposure
- Insecure cryptography
- Buffer overflows and memory safety issues
- Race conditions and concurrency issues
- Input validation issues
- Security misconfigurations

File: {file_path}
Language: {language}

SOURCE CODE:
```
{file_content}
```

=== OUTPUT FORMAT ===
For each security issue found, respond using this marker format:

*DRAFT: descriptive title of the vulnerability
*TYPE: CWE-XXX (e.g., CWE-78, CWE-89, CWE-79)
*SEVERITY: Critical/High/Medium/Low
*LINE: exact line number where the issue occurs
*SNIPPET: the vulnerable code
*REASON: explanation of why this is a vulnerability and how to fix it
*END_DRAFT

Example:
*DRAFT: SQL Injection in User Query
*TYPE: CWE-89
*SEVERITY: High
*LINE: 42
*SNIPPET: query = f"SELECT * FROM users WHERE id = {{user_id}}"
*REASON: User input is directly concatenated into SQL query. Use parameterized queries instead.
*END_DRAFT

If no security issues are found, respond with: *DRAFT:NONE

Only include actual security vulnerabilities, not code style or general quality issues."""


# Security review prompt for analyzing code diffs (marker format)
DIFF_REVIEW_PROMPT = """You are a security code reviewer analyzing a merge request diff.

Review the following code changes for security vulnerabilities. Focus on:
- Injection vulnerabilities (SQL, command, XSS, etc.)
- Authentication and authorization issues
- Sensitive data exposure
- Insecure cryptography
- Buffer overflows and memory safety issues
- Race conditions and concurrency issues
- Input validation issues
- Security misconfigurations

File: {file_path}
Language: {language}

DIFF:
```
{diff_content}
```

=== OUTPUT FORMAT ===
For each security issue found, respond using this marker format:

*DRAFT: descriptive title of the vulnerability
*TYPE: CWE-XXX (e.g., CWE-78, CWE-89, CWE-79)
*SEVERITY: Critical/High/Medium/Low
*LINE: exact line number in the new file
*SNIPPET: the vulnerable code
*REASON: explanation of why this is a vulnerability and how to fix it
*END_DRAFT

Example:
*DRAFT: SQL Injection in User Query
*TYPE: CWE-89
*SEVERITY: High
*LINE: 42
*SNIPPET: query = f"SELECT * FROM users WHERE id = {{user_id}}"
*REASON: User input is directly concatenated into SQL query. Use parameterized queries instead.
*END_DRAFT

If no security issues are found, respond with: *DRAFT:NONE

Only include actual security vulnerabilities, not code style or general quality issues."""


# Summary prompt for generating overall MR review
SUMMARY_PROMPT = """You are a security reviewer summarizing findings from a merge request security scan.

Total files reviewed: {file_count}
Total findings: {finding_count}
Critical: {critical_count}
High: {high_count}
Medium: {medium_count}
Low: {low_count}

Findings summary:
{findings_summary}

Generate a concise security review summary for this merge request. Include:
1. Overall security assessment (Pass with recommendations / Needs attention / Critical issues found)
2. Key findings that require attention
3. Recommendations for the author

Keep the summary under 500 words. Use Markdown formatting.
Do not include the detailed findings list - just summarize the key points."""


class MRReviewerService:
    """Service for automated MR/PR security review"""

    def __init__(self, db: Session):
        """
        Initialize MR/PR Reviewer service.

        Args:
            db: Database session
        """
        self.db = db
        self._gitlab_clients: Dict[int, GitLabService] = {}  # Cache by watcher_id
        self._github_clients: Dict[int, GitHubService] = {}  # Cache by watcher_id

    async def close(self):
        """Close all Git provider clients"""
        for client in self._gitlab_clients.values():
            await client.close()
        self._gitlab_clients.clear()
        for client in self._github_clients.values():
            await client.close()
        self._github_clients.clear()

    def _get_gitlab_client(self, watcher: RepoWatcher) -> GitLabService:
        """Get or create GitLab client for a watcher"""
        if watcher.id not in self._gitlab_clients:
            # Use saved repo if available, otherwise use direct fields
            if watcher.gitlab_repo_id and watcher.gitlab_repo:
                self._gitlab_clients[watcher.id] = GitLabService(
                    gitlab_url=watcher.gitlab_repo.gitlab_url,
                    token=watcher.gitlab_repo.gitlab_token,
                    verify_ssl=watcher.gitlab_repo.verify_ssl,
                )
            else:
                self._gitlab_clients[watcher.id] = GitLabService(
                    gitlab_url=watcher.gitlab_url,
                    token=watcher.gitlab_token,
                )
        return self._gitlab_clients[watcher.id]

    def _get_github_client(self, watcher: RepoWatcher) -> GitHubService:
        """Get or create GitHub client for a watcher"""
        if watcher.id not in self._github_clients:
            # Use saved repo if available, otherwise use direct fields
            if watcher.github_repo_id and watcher.github_repo:
                self._github_clients[watcher.id] = GitHubService(
                    github_url=watcher.github_repo.github_url,
                    token=watcher.github_repo.github_token,
                )
            else:
                self._github_clients[watcher.id] = GitHubService(
                    github_url=watcher.github_url or "https://api.github.com",
                    token=watcher.github_token,
                )
        return self._github_clients[watcher.id]

    def _get_provider(self, watcher: RepoWatcher) -> str:
        """Get the provider type for a watcher (gitlab or github)"""
        return getattr(watcher, 'provider', 'gitlab') or 'gitlab'

    def _get_project_id(self, watcher: RepoWatcher) -> str:
        """Get the project ID/path for a watcher"""
        if watcher.gitlab_repo_id and watcher.gitlab_repo:
            return watcher.gitlab_repo.project_id
        return watcher.project_id or ""

    def _get_github_owner_repo(self, watcher: RepoWatcher) -> Tuple[str, str]:
        """Get the GitHub owner and repo for a watcher"""
        if watcher.github_repo_id and watcher.github_repo:
            return watcher.github_repo.owner, watcher.github_repo.repo
        return watcher.github_owner or "", watcher.github_repo_name or ""

    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension"""
        ext_map = {
            '.py': 'Python',
            '.c': 'C',
            '.cpp': 'C++',
            '.cc': 'C++',
            '.cxx': 'C++',
            '.h': 'C/C++ Header',
            '.hpp': 'C++ Header',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.java': 'Java',
            '.go': 'Go',
            '.rs': 'Rust',
            '.rb': 'Ruby',
            '.php': 'PHP',
        }
        _, ext = os.path.splitext(file_path)
        return ext_map.get(ext.lower(), 'Unknown')

    def _is_scannable_file(self, file_path: str) -> bool:
        """Check if file should be scanned for security issues"""
        scannable_extensions = {
            '.py', '.c', '.cpp', '.cc', '.cxx', '.h', '.hpp',
            '.js', '.ts', '.java', '.go', '.rs', '.rb', '.php',
        }
        _, ext = os.path.splitext(file_path)
        return ext.lower() in scannable_extensions

    def _matches_branch_filter(self, branch: str, filter_pattern: Optional[str]) -> bool:
        """Check if branch matches the filter pattern"""
        if not filter_pattern:
            return True
        try:
            return bool(re.match(filter_pattern, branch))
        except re.error:
            # If invalid regex, treat as glob-style pattern
            pattern = filter_pattern.replace('*', '.*').replace('?', '.')
            return bool(re.match(f'^{pattern}$', branch))

    def _matches_label_filter(self, mr_labels: List[str], filter_labels: Optional[str]) -> bool:
        """Check if MR has any of the required labels"""
        if not filter_labels:
            return True
        required_labels = [l.strip().lower() for l in filter_labels.split(',')]
        mr_labels_lower = [l.lower() for l in mr_labels]
        return any(label in mr_labels_lower for label in required_labels)

    async def _analyze_diff_with_llm(
        self,
        file_path: str,
        diff_content: str,
    ) -> List[Dict[str, Any]]:
        """
        Analyze a file diff using LLM for security issues.

        Args:
            file_path: Path to the file
            diff_content: Unified diff content

        Returns:
            List of findings
        """
        language = self._detect_language(file_path)

        # Escape curly braces in diff content to prevent format() issues
        escaped_diff = diff_content[:8000].replace("{", "{{").replace("}", "}}")

        prompt = DIFF_REVIEW_PROMPT.format(
            file_path=file_path,
            language=language,
            diff_content=escaped_diff,
        )

        try:
            response = await llm_provider.chat_completion([
                {"role": "user", "content": prompt}
            ])

            content = response.get("content", "")

            # Check for "no findings" response
            if "*DRAFT:NONE" in content or not content.strip():
                return []

            # Parse marker format using DraftParser
            parser = DraftParser()
            parsed_findings = parser.parse(content)

            # Transform parsed findings to expected format
            findings = []
            for finding in parsed_findings:
                findings.append({
                    "title": finding.get("title", finding.get("draft", "Unknown Issue")),
                    "type": finding.get("type", "Unknown"),
                    "severity": finding.get("severity", "MEDIUM").upper(),
                    "line": int(finding.get("line", 1)) if finding.get("line") else 1,
                    "snippet": finding.get("snippet", ""),
                    "description": finding.get("reason", "No description provided."),
                    "recommendation": finding.get("reason", "Review this code for security implications."),
                })

            return findings

        except Exception as e:
            logger.error(f"Error analyzing diff for {file_path}: {e}")
            return []

    async def _analyze_file_with_llm(
        self,
        file_path: str,
        file_content: str,
    ) -> List[Dict[str, Any]]:
        """
        Analyze a full file using LLM for security issues.

        Args:
            file_path: Path to the file
            file_content: Complete file content

        Returns:
            List of findings
        """
        language = self._detect_language(file_path)

        # Truncate very large files and escape curly braces
        max_content_size = 50000  # ~50k chars, roughly 12k tokens
        truncated_content = file_content[:max_content_size]
        if len(file_content) > max_content_size:
            truncated_content += f"\n\n... (file truncated, {len(file_content) - max_content_size} chars omitted)"

        escaped_content = truncated_content.replace("{", "{{").replace("}", "}}")

        prompt = FILE_REVIEW_PROMPT.format(
            file_path=file_path,
            language=language,
            file_content=escaped_content,
        )

        try:
            response = await llm_provider.chat_completion([
                {"role": "user", "content": prompt}
            ])

            content = response.get("content", "")

            # Check for "no findings" response
            if "*DRAFT:NONE" in content or not content.strip():
                return []

            # Parse marker format using DraftParser
            parser = DraftParser()
            parsed_findings = parser.parse(content)

            # Transform parsed findings to expected format
            findings = []
            for finding in parsed_findings:
                findings.append({
                    "title": finding.get("title", finding.get("draft", "Unknown Issue")),
                    "type": finding.get("type", "Unknown"),
                    "severity": finding.get("severity", "MEDIUM").upper(),
                    "line": int(finding.get("line", 1)) if finding.get("line") else 1,
                    "snippet": finding.get("snippet", ""),
                    "description": finding.get("reason", "No description provided."),
                    "recommendation": finding.get("reason", "Review this code for security implications."),
                })

            return findings

        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")
            return []

    def _get_applicable_analyzers(
        self,
        profile: ScanProfile,
        file_path: str,
    ) -> List[ProfileAnalyzer]:
        """
        Get analyzers from a profile that are applicable to a file.

        Args:
            profile: Scan profile with analyzers
            file_path: Path to check against file_filter patterns

        Returns:
            List of applicable ProfileAnalyzer objects
        """
        applicable = []
        filename = os.path.basename(file_path)
        language = self._detect_language(file_path)

        for analyzer in profile.analyzers:
            if not analyzer.enabled:
                continue

            # Check file filter
            if analyzer.file_filter:
                patterns = [p.strip() for p in analyzer.file_filter.split(',') if p.strip()]
                matched = False
                for pattern in patterns:
                    if fnmatch.fnmatch(filename, pattern) or fnmatch.fnmatch(file_path, pattern):
                        matched = True
                        break
                if not matched:
                    continue

            # Check language filter
            if analyzer.language_filter:
                if language.lower() not in [lang.lower() for lang in analyzer.language_filter]:
                    continue

            applicable.append(analyzer)

        return applicable

    async def _analyze_file_with_profile(
        self,
        file_path: str,
        file_content: str,
        profile: ScanProfile,
    ) -> List[Dict[str, Any]]:
        """
        Analyze a file using the scan profile's configured analyzers.

        This runs each applicable analyzer from the profile against the file,
        using the analyzer's specific model and prompt template.

        Args:
            file_path: Path to the file
            file_content: Complete file content
            profile: ScanProfile with configured analyzers

        Returns:
            List of findings from all applicable analyzers
        """
        language = self._detect_language(file_path)
        all_findings = []

        # Get applicable analyzers for this file
        analyzers = self._get_applicable_analyzers(profile, file_path)

        if not analyzers:
            logger.info(f"No applicable analyzers for {file_path}, using default analysis")
            return await self._analyze_file_with_llm(file_path, file_content)

        for analyzer in analyzers:
            logger.info(f"Running analyzer '{analyzer.name}' on {file_path}")

            try:
                # Truncate content based on analyzer's chunk_size
                max_chars = (analyzer.chunk_size or 6000) * 4  # Rough token to char conversion
                truncated_content = file_content[:max_chars]
                if len(file_content) > max_chars:
                    truncated_content += f"\n\n... (truncated, {len(file_content) - max_chars} chars omitted)"

                # Escape curly braces in content for format string
                escaped_content = truncated_content.replace("{", "{{").replace("}", "}}")

                # Build prompt from analyzer's template
                if analyzer.prompt_template:
                    # Use the analyzer's custom prompt template
                    prompt = analyzer.prompt_template.format(
                        code=escaped_content,
                        language=language,
                        file_path=file_path,
                    )
                else:
                    # Fallback to default file review prompt
                    prompt = FILE_REVIEW_PROMPT.format(
                        file_path=file_path,
                        language=language,
                        file_content=escaped_content,
                    )

                # Get the model name from the analyzer's linked model
                model_name = analyzer.model.name if analyzer.model else None

                # Call LLM with the specific model
                response = await llm_provider.chat_completion(
                    [{"role": "user", "content": prompt}],
                    model=model_name,
                )

                content = response.get("content", "")

                # Check for "no findings" response
                if "*DRAFT:NONE" in content or not content.strip():
                    continue

                # Parse marker format using DraftParser
                parser = DraftParser()
                parsed_findings = parser.parse(content)

                # Transform parsed findings to expected format
                for finding in parsed_findings:
                    all_findings.append({
                        "title": finding.get("title", finding.get("draft", "Unknown Issue")),
                        "type": finding.get("type", "Unknown"),
                        "severity": finding.get("severity", "MEDIUM").upper(),
                        "line": int(finding.get("line", 1)) if finding.get("line") else 1,
                        "snippet": finding.get("snippet", ""),
                        "description": finding.get("reason", "No description provided."),
                        "recommendation": finding.get("reason", "Review this code for security implications."),
                        "analyzer": analyzer.name,
                        "model": model_name,
                    })

            except Exception as e:
                logger.error(f"Error running analyzer '{analyzer.name}' on {file_path}: {e}")
                continue

        return all_findings

    def _save_findings_to_db(
        self,
        review: MRReview,
        findings: List[Dict[str, Any]],
    ) -> List[Finding]:
        """
        Save findings as Finding records in the database.

        Args:
            review: MRReview object to associate findings with
            findings: List of finding dicts from LLM analysis

        Returns:
            List of created Finding records
        """
        from datetime import datetime, timezone

        # First, delete any existing findings for this review (in case of re-run)
        self.db.query(Finding).filter(Finding.mr_review_id == review.id).delete()

        created_findings = []
        for finding_data in findings:
            # Map severity to proper case
            severity_raw = finding_data.get("severity", "MEDIUM").upper()
            severity_map = {
                "CRITICAL": "Critical",
                "HIGH": "High",
                "MEDIUM": "Medium",
                "LOW": "Low",
            }
            severity = severity_map.get(severity_raw, "Medium")

            finding = Finding(
                mr_review_id=review.id,
                file_path=finding_data.get("file_path", "unknown"),
                line_number=finding_data.get("line"),
                severity=severity,
                category=finding_data.get("type"),  # CWE type
                description=f"{finding_data.get('title', 'Security Issue')}: {finding_data.get('description', '')}",
                snippet=finding_data.get("snippet"),
                remediation=finding_data.get("recommendation"),
                detected_at=datetime.now(timezone.utc),
                source_model="mr_reviewer",
            )
            self.db.add(finding)
            created_findings.append(finding)

        self.db.flush()  # Get IDs assigned
        logger.info(f"Saved {len(created_findings)} findings to database for MR review {review.id}")
        return created_findings

    async def _generate_summary(
        self,
        file_count: int,
        findings: List[Dict[str, Any]],
    ) -> str:
        """
        Generate a summary comment for the MR.

        Args:
            file_count: Number of files reviewed
            findings: List of all findings

        Returns:
            Summary markdown text
        """
        # Count by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in findings:
            severity = finding.get("severity", "MEDIUM").upper()
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Build findings summary
        findings_summary = ""
        for finding in findings[:10]:  # Limit to first 10 for summary
            findings_summary += f"- [{finding.get('severity', 'MEDIUM')}] {finding.get('title', 'Unknown')}: {finding.get('file_path', 'Unknown file')} line {finding.get('line', '?')}\n"

        if len(findings) > 10:
            findings_summary += f"\n... and {len(findings) - 10} more findings\n"

        prompt = SUMMARY_PROMPT.format(
            file_count=file_count,
            finding_count=len(findings),
            critical_count=severity_counts["CRITICAL"],
            high_count=severity_counts["HIGH"],
            medium_count=severity_counts["MEDIUM"],
            low_count=severity_counts["LOW"],
            findings_summary=findings_summary or "No security issues found.",
        )

        try:
            response = await llm_provider.chat_completion([
                {"role": "user", "content": prompt}
            ])
            return response.get("content", "Unable to generate summary.")
        except Exception as e:
            logger.error(f"Error generating summary: {e}")
            return f"Security scan completed with {len(findings)} findings."

    # -------------------------------------------------------------------------
    # Public API: Review Operations
    # -------------------------------------------------------------------------

    async def review_mr_diff(
        self,
        watcher: RepoWatcher,
        mr: Dict[str, Any],
    ) -> MRReview:
        """
        Phase 1: Analyze MR/PR diff and post inline comments.

        Args:
            watcher: Repository watcher configuration
            mr: GitLab MR or GitHub PR object from API

        Returns:
            MRReview database object
        """
        provider = self._get_provider(watcher)

        if provider == "github":
            return await self._review_github_pr(watcher, mr)

        # GitLab review (default)
        return await self._review_gitlab_mr(watcher, mr)

    async def _review_gitlab_mr(
        self,
        watcher: RepoWatcher,
        mr: Dict[str, Any],
    ) -> MRReview:
        """
        Review a GitLab merge request.

        Args:
            watcher: Repository watcher configuration
            mr: GitLab MR object from API

        Returns:
            MRReview database object
        """
        gitlab = self._get_gitlab_client(watcher)
        project_id = self._get_project_id(watcher)
        mr_iid = mr["iid"]

        # Check if we already have a review for this MR
        existing_review = self.db.query(MRReview).filter(
            MRReview.watcher_id == watcher.id,
            MRReview.mr_iid == mr_iid,
        ).first()

        if existing_review and existing_review.status == "completed":
            logger.info(f"MR {mr_iid} already reviewed, skipping")
            return existing_review

        # Create or update review record
        if existing_review:
            review = existing_review
        else:
            review = MRReview(
                watcher_id=watcher.id,
                mr_iid=mr_iid,
                mr_title=mr.get("title"),
                mr_url=mr.get("web_url"),
                mr_author=mr.get("author", {}).get("username"),
                source_branch=mr.get("source_branch"),
                target_branch=mr.get("target_branch"),
                status="reviewing",
            )
            self.db.add(review)
            self.db.flush()

        review.status = "reviewing"
        self.db.commit()

        try:
            # Get MR diff details
            diff_data = await gitlab.get_mr_diff(project_id, mr_iid)
            changes = diff_data.get("changes", [])

            # Count scannable files
            scannable_changes = [c for c in changes if self._is_scannable_file(c.get("new_path", ""))]
            total_scannable = len(scannable_changes)

            # Get max files limit (default to 100 if not set)
            max_files = getattr(watcher, 'max_files_to_review', None) or 100

            # Check if too many files
            if total_scannable > max_files:
                logger.warning(f"MR {mr_iid} has {total_scannable} files (limit: {max_files}), skipping automated review")

                # Create skip comment
                skip_comment = self._format_too_many_files_comment(
                    total_files=total_scannable,
                    max_files=max_files,
                    review_id=review.id,
                )

                # Store the skip status
                review.diff_summary = f"Skipped: {total_scannable} files exceeds limit of {max_files}"
                review.files_reviewed = 0
                review.generated_comments = {
                    "inline_comments": [],
                    "summary_comment": skip_comment,
                    "skipped_reason": "too_many_files",
                    "total_files": total_scannable,
                    "max_files": max_files,
                }
                review.status = "skipped"
                review.diff_reviewed_at = datetime.now(timezone.utc)

                # Post comment to GitLab if enabled
                comments_posted = []
                if watcher.post_comments:
                    try:
                        result = await gitlab.post_mr_comment(
                            project_id=project_id,
                            mr_iid=mr_iid,
                            comment=skip_comment,
                        )
                        comments_posted.append(result.get("id"))
                        logger.info(f"Posted 'too many files' comment to MR {mr_iid}")
                    except GitLabError as e:
                        logger.warning(f"Failed to post skip comment: {e}")

                review.comments_posted = comments_posted
                self.db.commit()
                return review

            all_findings = []
            files_reviewed = 0

            # Get source branch for fetching full file content
            source_branch = mr.get("source_branch")

            # Analyze each changed file - fetch FULL FILE content, not just diff
            for change in scannable_changes:
                file_path = change.get("new_path", "")

                # Skip deleted files
                if change.get("deleted_file"):
                    continue

                files_reviewed += 1
                logger.info(f"Reviewing full file: {file_path}")

                try:
                    # Fetch the complete file content from the source branch
                    file_content = await gitlab.get_file_content(
                        project_id=project_id,
                        file_path=file_path,
                        ref=source_branch,
                    )

                    # Analyze with LLM using full file content
                    # Use scan profile if configured on the watcher
                    if watcher.scan_profile:
                        logger.info(f"Using scan profile '{watcher.scan_profile.name}' for {file_path}")
                        findings = await self._analyze_file_with_profile(file_path, file_content, watcher.scan_profile)
                    else:
                        findings = await self._analyze_file_with_llm(file_path, file_content)

                    # Add file path to each finding
                    for finding in findings:
                        finding["file_path"] = file_path
                        all_findings.append(finding)

                except GitLabError as e:
                    logger.warning(f"Failed to fetch file {file_path}: {e}")
                    # Fall back to diff-based analysis
                    diff_content = change.get("diff", "")
                    if diff_content:
                        findings = await self._analyze_diff_with_llm(file_path, diff_content)
                        for finding in findings:
                            finding["file_path"] = file_path
                            all_findings.append(finding)

            # Store findings in review
            review.diff_findings = all_findings
            review.diff_reviewed_at = datetime.now(timezone.utc)

            # Save findings to database for dashboard integration
            self._save_findings_to_db(review, all_findings)

            # Generate summary (always, for local tracking)
            summary = await self._generate_summary(files_reviewed, all_findings)
            review.diff_summary = summary

            # Always generate and store the formatted comments (even in dry-run mode)
            generated_comments = {
                "inline_comments": [],
                "summary_comment": None
            }

            # Get diff refs for inline comments
            base_sha = diff_data.get("diff_refs", {}).get("base_sha")
            head_sha = diff_data.get("diff_refs", {}).get("head_sha")
            start_sha = diff_data.get("diff_refs", {}).get("start_sha")

            # Generate inline comments for each finding
            for finding in all_findings:
                comment_body = self._format_inline_comment(finding)
                generated_comments["inline_comments"].append({
                    "file_path": finding["file_path"],
                    "line": finding.get("line", 1),
                    "body": comment_body,
                    "base_sha": base_sha,
                    "head_sha": head_sha,
                    "start_sha": start_sha,
                })

            # Generate summary comment
            summary_comment = self._format_summary_comment(
                files_reviewed=files_reviewed,
                findings=all_findings,
                summary=summary,
                review_id=review.id,
            )
            generated_comments["summary_comment"] = summary_comment

            # Store all generated comments (even if not posted)
            review.generated_comments = generated_comments

            # Post comments to GitLab only if post_comments is enabled
            comments_posted = []
            if watcher.post_comments and all_findings:
                for gen_comment in generated_comments["inline_comments"]:
                    try:
                        result = await gitlab.post_inline_comment(
                            project_id=project_id,
                            mr_iid=mr_iid,
                            file_path=gen_comment["file_path"],
                            new_line=gen_comment["line"],
                            comment=gen_comment["body"],
                            base_sha=gen_comment["base_sha"],
                            head_sha=gen_comment["head_sha"],
                            start_sha=gen_comment["start_sha"],
                        )
                        comments_posted.append(result.get("id"))
                    except GitLabError as e:
                        logger.warning(f"Failed to post inline comment: {e}")

                # Post summary comment
                try:
                    result = await gitlab.post_mr_comment(
                        project_id=project_id,
                        mr_iid=mr_iid,
                        comment=generated_comments["summary_comment"],
                    )
                    comments_posted.append(result.get("id"))
                except GitLabError as e:
                    logger.warning(f"Failed to post summary comment: {e}")
            elif not watcher.post_comments:
                logger.info(f"Dry run mode: {len(all_findings)} findings with {len(generated_comments['inline_comments'])} comments stored locally (post_comments=False)")

            review.comments_posted = comments_posted
            review.status = "completed"
            review.approval_status = self._determine_approval_status(all_findings)
            review.last_error = None

        except Exception as e:
            logger.error(f"Error reviewing MR {mr_iid}: {e}")
            review.status = "error"
            review.last_error = str(e)[:500]

        self.db.commit()
        return review

    async def _review_github_pr(
        self,
        watcher: RepoWatcher,
        pr: Dict[str, Any],
    ) -> MRReview:
        """
        Review a GitHub pull request.

        Args:
            watcher: Repository watcher configuration
            pr: GitHub PR object from API

        Returns:
            MRReview database object
        """
        github = self._get_github_client(watcher)
        owner, repo_name = self._get_github_owner_repo(watcher)
        pr_number = pr["number"]

        # Check if we already have a review for this PR
        existing_review = self.db.query(MRReview).filter(
            MRReview.watcher_id == watcher.id,
            MRReview.mr_iid == pr_number,
        ).first()

        if existing_review and existing_review.status == "completed":
            logger.info(f"PR #{pr_number} already reviewed, skipping")
            return existing_review

        # Create or update review record
        if existing_review:
            review = existing_review
        else:
            review = MRReview(
                watcher_id=watcher.id,
                provider="github",
                mr_iid=pr_number,
                mr_title=pr.get("title"),
                mr_url=pr.get("html_url"),
                mr_author=pr.get("user", {}).get("login"),
                source_branch=pr.get("head", {}).get("ref"),
                target_branch=pr.get("base", {}).get("ref"),
                status="reviewing",
            )
            self.db.add(review)
            self.db.flush()

        review.status = "reviewing"
        review.provider = "github"
        self.db.commit()

        try:
            # Get PR files
            files_data = await github.get_pr_files(owner, repo_name, pr_number)

            # Count scannable files
            scannable_files = [f for f in files_data if self._is_scannable_file(f.get("filename", ""))]
            total_scannable = len(scannable_files)

            # Get max files limit
            max_files = getattr(watcher, 'max_files_to_review', None) or 100

            # Check if too many files
            if total_scannable > max_files:
                logger.warning(f"PR #{pr_number} has {total_scannable} files (limit: {max_files}), skipping automated review")

                skip_comment = self._format_too_many_files_comment(
                    total_files=total_scannable,
                    max_files=max_files,
                    review_id=review.id,
                )

                review.diff_summary = f"Skipped: {total_scannable} files exceeds limit of {max_files}"
                review.files_reviewed = 0
                review.generated_comments = {
                    "inline_comments": [],
                    "summary_comment": skip_comment,
                    "skipped_reason": "too_many_files",
                    "total_files": total_scannable,
                    "max_files": max_files,
                }
                review.status = "skipped"
                review.diff_reviewed_at = datetime.now(timezone.utc)

                # Post comment to GitHub if enabled
                comments_posted = []
                if watcher.post_comments:
                    try:
                        result = await github.post_pr_comment(owner, repo_name, pr_number, skip_comment)
                        comments_posted.append(result.get("id"))
                        logger.info(f"Posted 'too many files' comment to PR #{pr_number}")
                    except GitHubError as e:
                        logger.warning(f"Failed to post skip comment: {e}")

                review.comments_posted = comments_posted
                self.db.commit()
                return review

            all_findings = []
            files_reviewed = 0

            # Get source branch for fetching full file content
            source_branch = pr.get("head", {}).get("ref")

            # Analyze each changed file - fetch FULL FILE content
            for file_data in scannable_files:
                file_path = file_data.get("filename", "")

                # Skip deleted files
                if file_data.get("status") == "removed":
                    continue

                files_reviewed += 1
                logger.info(f"Reviewing full file: {file_path}")

                try:
                    # Fetch the complete file content from the source branch
                    file_content = await github.get_file_content(owner, repo_name, file_path, source_branch)

                    # Analyze with LLM using full file content
                    # Use scan profile if configured on the watcher
                    if watcher.scan_profile:
                        logger.info(f"Using scan profile '{watcher.scan_profile.name}' for {file_path}")
                        findings = await self._analyze_file_with_profile(file_path, file_content, watcher.scan_profile)
                    else:
                        findings = await self._analyze_file_with_llm(file_path, file_content)

                    # Add file path to each finding
                    for finding in findings:
                        finding["file_path"] = file_path
                        all_findings.append(finding)

                except GitHubError as e:
                    logger.warning(f"Failed to fetch file {file_path}: {e}")
                    # Fall back to patch-based analysis if available
                    patch = file_data.get("patch", "")
                    if patch:
                        findings = await self._analyze_diff_with_llm(file_path, patch)
                        for finding in findings:
                            finding["file_path"] = file_path
                            all_findings.append(finding)

            # Store findings in review
            review.diff_findings = all_findings
            review.diff_reviewed_at = datetime.now(timezone.utc)
            review.files_reviewed = files_reviewed

            # Save findings to database for dashboard integration
            self._save_findings_to_db(review, all_findings)

            # Generate summary
            summary = await self._generate_summary(files_reviewed, all_findings)
            review.diff_summary = summary

            # Generate and store the formatted comments
            generated_comments = {
                "inline_comments": [],
                "summary_comment": None
            }

            # Get head SHA for inline comments
            head_sha = pr.get("head", {}).get("sha")

            # Generate inline comments for each finding
            for finding in all_findings:
                comment_body = self._format_inline_comment(finding)
                generated_comments["inline_comments"].append({
                    "file_path": finding["file_path"],
                    "line": finding.get("line", 1),
                    "body": comment_body,
                    "commit_sha": head_sha,
                })

            # Generate summary comment
            summary_comment = self._format_summary_comment(
                files_reviewed=files_reviewed,
                findings=all_findings,
                summary=summary,
                review_id=review.id,
            )
            generated_comments["summary_comment"] = summary_comment

            # Store all generated comments
            review.generated_comments = generated_comments

            # Post comments to GitHub only if post_comments is enabled
            comments_posted = []
            if watcher.post_comments and all_findings:
                for gen_comment in generated_comments["inline_comments"]:
                    try:
                        result = await github.post_review_comment(
                            owner=owner,
                            repo=repo_name,
                            pr_number=pr_number,
                            commit_sha=gen_comment["commit_sha"],
                            path=gen_comment["file_path"],
                            line=gen_comment["line"],
                            comment=gen_comment["body"],
                        )
                        comments_posted.append(result.get("id"))
                    except GitHubError as e:
                        logger.warning(f"Failed to post inline comment: {e}")

                # Post summary comment
                try:
                    result = await github.post_pr_comment(
                        owner=owner,
                        repo=repo_name,
                        pr_number=pr_number,
                        comment=generated_comments["summary_comment"],
                    )
                    comments_posted.append(result.get("id"))
                except GitHubError as e:
                    logger.warning(f"Failed to post summary comment: {e}")
            elif not watcher.post_comments:
                logger.info(f"Dry run mode: {len(all_findings)} findings with {len(generated_comments['inline_comments'])} comments stored locally (post_comments=False)")

            review.comments_posted = comments_posted
            review.status = "completed"
            review.approval_status = self._determine_approval_status(all_findings)
            review.last_error = None

        except Exception as e:
            logger.error(f"Error reviewing PR #{pr_number}: {e}")
            review.status = "error"
            review.last_error = str(e)[:500]

        self.db.commit()
        return review

    async def full_scan_changed_files(
        self,
        review: MRReview,
    ) -> None:
        """
        Phase 2: Run full security scan on changed files.

        Args:
            review: MRReview object to scan
        """
        watcher = review.watcher
        provider = self._get_provider(watcher)

        review.scan_started_at = datetime.now(timezone.utc)
        self.db.commit()

        try:
            # Get list of changed files based on provider
            if provider == "github":
                github = self._get_github_client(watcher)
                owner, repo = self._get_github_owner_repo(watcher)
                files_data = await github.get_pr_files(owner, repo, review.mr_iid)
                files = [f["filename"] for f in files_data]
                scannable_files = [f for f in files if self._is_scannable_file(f)]

                if not scannable_files:
                    logger.info(f"No scannable files in PR #{review.mr_iid}")
                    review.scan_completed_at = datetime.now(timezone.utc)
                    self.db.commit()
                    return

                # Create temporary directory for files
                temp_dir = tempfile.mkdtemp(prefix=f"pr_scan_{review.mr_iid}_")

                try:
                    # Download each changed file
                    pr_data = await github.get_pull_request(owner, repo, review.mr_iid)
                    source_branch = pr_data.get("head", {}).get("ref")

                    for file_path in scannable_files:
                        try:
                            content = await github.get_file_content(owner, repo, file_path, source_branch)
                            full_path = os.path.join(temp_dir, file_path)
                            os.makedirs(os.path.dirname(full_path), exist_ok=True)
                            with open(full_path, 'w', encoding='utf-8') as f:
                                f.write(content)
                        except GitHubError as e:
                            logger.warning(f"Failed to download {file_path}: {e}")

                    # Create and run scan
                    scan = Scan(
                        target_url=f"PR #{review.mr_iid} from {watcher.name}",
                        status=ScanStatus.RUNNING,
                    )
                    self.db.add(scan)
                    self.db.flush()
                    review.scan_id = scan.id

                    from app.services.scan_engine import scan_engine
                    await scan_engine.start_scan(scan.id, temp_dir, is_git=False)
                    review.scan_completed_at = datetime.now(timezone.utc)
                finally:
                    shutil.rmtree(temp_dir, ignore_errors=True)

            else:
                # GitLab
                gitlab = self._get_gitlab_client(watcher)
                project_id = self._get_project_id(watcher)
                files = await gitlab.get_mr_files(project_id, review.mr_iid)
                scannable_files = [f for f in files if self._is_scannable_file(f)]

                if not scannable_files:
                    logger.info(f"No scannable files in MR {review.mr_iid}")
                    review.scan_completed_at = datetime.now(timezone.utc)
                    self.db.commit()
                    return

                # Create temporary directory for files
                temp_dir = tempfile.mkdtemp(prefix=f"mr_scan_{review.mr_iid}_")

                try:
                    # Download each changed file
                    mr_data = await gitlab.get_merge_request(project_id, review.mr_iid)
                    source_branch = mr_data.get("source_branch")

                    for file_path in scannable_files:
                        try:
                            content = await gitlab.get_file_content(
                                project_id=project_id,
                                file_path=file_path,
                                ref=source_branch,
                            )

                            # Write to temp directory
                            full_path = os.path.join(temp_dir, file_path)
                            os.makedirs(os.path.dirname(full_path), exist_ok=True)
                            with open(full_path, 'w', encoding='utf-8') as f:
                                f.write(content)

                        except GitLabError as e:
                            logger.warning(f"Failed to download {file_path}: {e}")

                    # Create a scan record
                    scan = Scan(
                        target_url=f"MR !{review.mr_iid} from {watcher.name}",
                        status=ScanStatus.RUNNING,
                    )
                    self.db.add(scan)
                    self.db.flush()

                    review.scan_id = scan.id

                    # Run the scan (simplified - would integrate with full scan engine)
                    from app.services.scan_engine import scan_engine
                    await scan_engine.start_scan(scan.id, temp_dir, is_git=False)
                    review.scan_completed_at = datetime.now(timezone.utc)

                finally:
                    # Cleanup temp directory
                    shutil.rmtree(temp_dir, ignore_errors=True)

        except Exception as e:
            logger.error(f"Error in full scan for MR {review.mr_iid}: {e}")
            review.last_error = str(e)[:500]

        self.db.commit()

    async def poll_watcher(
        self,
        watcher: RepoWatcher,
    ) -> List[MRReview]:
        """
        Check for new MRs/PRs and process them.

        Args:
            watcher: Repository watcher to poll

        Returns:
            List of new/updated MRReview objects
        """
        if not watcher.enabled or watcher.status == "error":
            return []

        provider = self._get_provider(watcher)
        reviews = []

        # Parse label filter
        labels = None
        if watcher.label_filter:
            labels = [l.strip() for l in watcher.label_filter.split(',')]

        # Calculate lookback date filter (default 7 days, 0 = no limit)
        created_after = None
        lookback_days = getattr(watcher, 'mr_lookback_days', None) or 7
        if lookback_days > 0:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=lookback_days)
            created_after = cutoff_date.isoformat()
            logger.info(f"Filtering MRs/PRs created after {cutoff_date.strftime('%Y-%m-%d')}")

        try:
            if provider == "github":
                # GitHub polling
                github = self._get_github_client(watcher)
                owner, repo = self._get_github_owner_repo(watcher)

                # Get open PRs
                prs = await github.get_open_pull_requests(owner, repo)

                # Apply label filter
                if labels:
                    prs = github.filter_prs_by_labels(prs, labels)

                # Apply date filter
                if created_after:
                    prs = github.filter_prs_by_created_date(prs, created_after)

                for pr in prs:
                    # Check branch filter (GitHub uses "base" for target branch)
                    target_branch = pr.get("base", {}).get("ref", "")
                    if not self._matches_branch_filter(target_branch, watcher.branch_filter):
                        continue

                    pr_number = pr["number"]

                    # Check if already reviewed
                    existing = self.db.query(MRReview).filter(
                        MRReview.watcher_id == watcher.id,
                        MRReview.mr_iid == pr_number,
                    ).first()

                    if existing and existing.status == "completed":
                        if existing.diff_reviewed_at:
                            continue

                    # Review this PR
                    logger.info(f"Processing PR #{pr_number} for watcher {watcher.name}")
                    review = await self.review_mr_diff(watcher, pr)
                    reviews.append(review)

            else:
                # GitLab polling (default)
                gitlab = self._get_gitlab_client(watcher)
                project_id = self._get_project_id(watcher)

                # Get open MRs
                mrs = await gitlab.get_open_merge_requests(
                    project_id=project_id,
                    labels=labels,
                    created_after=created_after,
                )

                for mr in mrs:
                    # Check branch filter
                    target_branch = mr.get("target_branch", "")
                    if not self._matches_branch_filter(target_branch, watcher.branch_filter):
                        continue

                    # Check if MR has required labels
                    mr_labels = [l.get("title", "") for l in mr.get("labels", [])]
                    if not self._matches_label_filter(mr_labels, watcher.label_filter):
                        continue

                    # Check if already reviewed
                    existing = self.db.query(MRReview).filter(
                        MRReview.watcher_id == watcher.id,
                        MRReview.mr_iid == mr["iid"],
                    ).first()

                    if existing and existing.status == "completed":
                        mr_updated_at = mr.get("updated_at")
                        if existing.diff_reviewed_at:
                            continue

                    # Review this MR
                    logger.info(f"Processing MR !{mr['iid']} for watcher {watcher.name}")
                    review = await self.review_mr_diff(watcher, mr)
                    reviews.append(review)

            # Update watcher status
            watcher.last_check = datetime.now(timezone.utc)
            watcher.last_error = None
            watcher.status = "running"

        except GitHubError as e:
            logger.error(f"GitHub error polling watcher {watcher.name}: {e}")
            watcher.last_error = str(e)[:500]
            watcher.status = "error"

        except GitLabError as e:
            logger.error(f"GitLab error polling watcher {watcher.name}: {e}")
            watcher.last_error = str(e)[:500]
            watcher.status = "error"

        except Exception as e:
            logger.error(f"Error polling watcher {watcher.name}: {e}")
            watcher.last_error = str(e)[:500]
            watcher.status = "error"

        self.db.commit()
        return reviews

    # -------------------------------------------------------------------------
    # Formatting Helpers
    # -------------------------------------------------------------------------

    def _format_too_many_files_comment(
        self,
        total_files: int,
        max_files: int,
        review_id: Optional[int] = None,
    ) -> str:
        """Format a comment explaining the MR was skipped due to too many changed files"""
        from app.core.config import settings

        review_link = ""
        if review_id and settings.SCANNER_URL_PREFIX:
            review_url = f"{settings.SCANNER_URL_PREFIX}/mr-reviews?review={review_id}"
            review_link = f"\n:link: [View review details]({review_url})\n"

        return f"""## :warning: Security Scan Skipped

This merge request contains **{total_files} changed files**, which exceeds the configured limit of **{max_files} files** for automated security review.

### Why was this skipped?
Large MRs (often from rebases or major refactors) can overwhelm the security scanner and cause delays for other reviews. To ensure timely feedback on focused changes, we skip automated review when MRs exceed the file limit.

### What should you do?
- **If this is a rebase**: Consider squashing commits or ensuring the target branch is up to date
- **If this needs review**: Submit a manual scan request through the security scanner dashboard
- **For critical changes**: Contact the security team directly
{review_link}
---
*Automated security review by Security Scanner*
"""

    def _format_inline_comment(self, finding: Dict[str, Any]) -> str:
        """Format a finding as an inline comment"""
        severity = finding.get("severity", "MEDIUM")
        severity_emoji = {
            "CRITICAL": ":rotating_light:",
            "HIGH": ":warning:",
            "MEDIUM": ":yellow_circle:",
            "LOW": ":information_source:",
        }.get(severity, ":yellow_circle:")

        return f"""{severity_emoji} **Security Issue: {finding.get('title', 'Potential Vulnerability')}**

**Severity:** {severity}

{finding.get('description', 'No description provided.')}

**Recommendation:** {finding.get('recommendation', 'Review this code for security implications.')}

---
*Automated security review by Security Scanner*"""

    def _format_summary_comment(
        self,
        files_reviewed: int,
        findings: List[Dict[str, Any]],
        summary: str,
        review_id: Optional[int] = None,
    ) -> str:
        """Format the summary comment for the MR"""
        from app.core.config import settings

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in findings:
            severity = finding.get("severity", "MEDIUM").upper()
            if severity in severity_counts:
                severity_counts[severity] += 1

        total = len(findings)

        header = "## :shield: Security Scan Results\n\n"

        if total == 0:
            status = ":white_check_mark: **No security issues found**"
        elif severity_counts["CRITICAL"] > 0 or severity_counts["HIGH"] > 0:
            status = ":rotating_light: **Critical/High severity issues found - please review**"
        else:
            status = ":warning: **Security issues found - please review**"

        stats = f"""
| Metric | Value |
|--------|-------|
| Files Reviewed | {files_reviewed} |
| Total Findings | {total} |
| Critical | {severity_counts['CRITICAL']} |
| High | {severity_counts['HIGH']} |
| Medium | {severity_counts['MEDIUM']} |
| Low | {severity_counts['LOW']} |
"""

        # Build the review link if we have a review_id
        review_link = ""
        if review_id and settings.SCANNER_URL_PREFIX:
            review_url = f"{settings.SCANNER_URL_PREFIX}/mr-reviews?review={review_id}"
            review_link = f"\n:link: [View full review details]({review_url})\n"

        return f"""{header}{status}

{stats}

### Summary

{summary}
{review_link}
---
*Automated security review by Security Scanner*
"""

    def _determine_approval_status(self, findings: List[Dict[str, Any]]) -> str:
        """Determine approval status based on findings"""
        for finding in findings:
            severity = finding.get("severity", "").upper()
            if severity in ("CRITICAL", "HIGH"):
                return "changes_requested"

        if findings:
            return "pending"

        return "approved"


# Singleton instance
_mr_reviewer_service: Optional[MRReviewerService] = None


def get_mr_reviewer_service(db: Session) -> MRReviewerService:
    """Get or create MR reviewer service instance"""
    global _mr_reviewer_service
    if _mr_reviewer_service is None:
        _mr_reviewer_service = MRReviewerService(db)
    return _mr_reviewer_service


# Background polling task
async def run_watcher_polling():
    """
    Background task to poll all active watchers.
    Should be called periodically by the application scheduler.
    """
    db = SessionLocal()
    try:
        service = MRReviewerService(db)

        # Get all enabled watchers
        watchers = db.query(RepoWatcher).filter(
            RepoWatcher.enabled == True,
            RepoWatcher.status != "error",
        ).all()

        for watcher in watchers:
            # Check if it's time to poll
            if watcher.last_check:
                elapsed = (datetime.now(timezone.utc) - watcher.last_check).total_seconds()
                if elapsed < watcher.poll_interval:
                    continue

            logger.info(f"Polling watcher: {watcher.name}")
            await service.poll_watcher(watcher)

        await service.close()

    finally:
        db.close()
