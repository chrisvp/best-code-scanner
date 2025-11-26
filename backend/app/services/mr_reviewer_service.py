"""
MR Reviewer Service for Automated Security Reviews

Provides automated security review functionality for GitLab merge requests:
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
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.scanner_models import RepoWatcher, MRReview, ScanProfile
from app.models.models import Scan, Finding, ScanStatus
from app.services.gitlab_service import GitLabService, GitLabError
from app.services.llm_provider import llm_provider
from app.core.database import SessionLocal

logger = logging.getLogger(__name__)


# Security review prompt for analyzing code diffs
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

For each security issue found, respond with a JSON array of findings:
[
  {{
    "line": <line_number in new file>,
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "title": "<brief title>",
    "description": "<detailed description of the vulnerability>",
    "recommendation": "<how to fix>"
  }}
]

If no security issues are found, respond with an empty array: []

Only include actual security vulnerabilities, not code style or general quality issues.
Respond ONLY with the JSON array, no other text."""


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
    """Service for automated MR security review"""

    def __init__(self, db: Session):
        """
        Initialize MR Reviewer service.

        Args:
            db: Database session
        """
        self.db = db
        self._gitlab_clients: Dict[int, GitLabService] = {}  # Cache by watcher_id

    async def close(self):
        """Close all GitLab clients"""
        for client in self._gitlab_clients.values():
            await client.close()
        self._gitlab_clients.clear()

    def _get_gitlab_client(self, watcher: RepoWatcher) -> GitLabService:
        """Get or create GitLab client for a watcher"""
        if watcher.id not in self._gitlab_clients:
            self._gitlab_clients[watcher.id] = GitLabService(
                gitlab_url=watcher.gitlab_url,
                token=watcher.gitlab_token,
            )
        return self._gitlab_clients[watcher.id]

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

        prompt = DIFF_REVIEW_PROMPT.format(
            file_path=file_path,
            language=language,
            diff_content=diff_content[:8000],  # Limit diff size
        )

        try:
            response = await llm_provider.chat_completion([
                {"role": "user", "content": prompt}
            ])

            # Parse JSON response
            import json
            content = response.get("content", "[]")

            # Extract JSON array from response
            # Handle cases where LLM adds extra text
            json_match = re.search(r'\[.*\]', content, re.DOTALL)
            if json_match:
                findings = json.loads(json_match.group())
                return findings if isinstance(findings, list) else []

            return []

        except Exception as e:
            logger.error(f"Error analyzing diff for {file_path}: {e}")
            return []

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
        Phase 1: Analyze MR diff and post inline comments.

        Args:
            watcher: Repository watcher configuration
            mr: GitLab MR object from API

        Returns:
            MRReview database object
        """
        gitlab = self._get_gitlab_client(watcher)
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
            diff_data = await gitlab.get_mr_diff(watcher.project_id, mr_iid)
            changes = diff_data.get("changes", [])

            all_findings = []
            files_reviewed = 0

            # Analyze each changed file
            for change in changes:
                file_path = change.get("new_path", "")

                if not self._is_scannable_file(file_path):
                    continue

                diff_content = change.get("diff", "")
                if not diff_content:
                    continue

                files_reviewed += 1
                logger.info(f"Reviewing diff for {file_path}")

                # Analyze with LLM
                findings = await self._analyze_diff_with_llm(file_path, diff_content)

                # Add file path to each finding
                for finding in findings:
                    finding["file_path"] = file_path
                    all_findings.append(finding)

            # Store findings in review
            review.diff_findings = all_findings
            review.diff_reviewed_at = datetime.now(timezone.utc)

            # Generate summary (always, for local tracking)
            summary = await self._generate_summary(files_reviewed, all_findings)
            review.diff_summary = summary

            # Post comments to GitLab only if post_comments is enabled
            comments_posted = []
            if watcher.post_comments and all_findings:
                # Get diff refs for inline comments
                base_sha = diff_data.get("diff_refs", {}).get("base_sha")
                head_sha = diff_data.get("diff_refs", {}).get("head_sha")
                start_sha = diff_data.get("diff_refs", {}).get("start_sha")

                for finding in all_findings:
                    try:
                        comment_body = self._format_inline_comment(finding)
                        result = await gitlab.post_inline_comment(
                            project_id=watcher.project_id,
                            mr_iid=mr_iid,
                            file_path=finding["file_path"],
                            new_line=finding.get("line", 1),
                            comment=comment_body,
                            base_sha=base_sha,
                            head_sha=head_sha,
                            start_sha=start_sha,
                        )
                        comments_posted.append(result.get("id"))
                    except GitLabError as e:
                        logger.warning(f"Failed to post inline comment: {e}")

                # Post summary comment
                try:
                    summary_comment = self._format_summary_comment(
                        files_reviewed=files_reviewed,
                        findings=all_findings,
                        summary=summary,
                    )
                    result = await gitlab.post_mr_comment(
                        project_id=watcher.project_id,
                        mr_iid=mr_iid,
                        comment=summary_comment,
                    )
                    comments_posted.append(result.get("id"))
                except GitLabError as e:
                    logger.warning(f"Failed to post summary comment: {e}")
            elif not watcher.post_comments:
                logger.info(f"Dry run mode: {len(all_findings)} findings tracked locally (post_comments=False)")

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
        gitlab = self._get_gitlab_client(watcher)

        review.scan_started_at = datetime.now(timezone.utc)
        self.db.commit()

        try:
            # Get list of changed files
            files = await gitlab.get_mr_files(watcher.project_id, review.mr_iid)
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
                mr_data = await gitlab.get_merge_request(watcher.project_id, review.mr_iid)
                source_branch = mr_data.get("source_branch")

                for file_path in scannable_files:
                    try:
                        content = await gitlab.get_file_content(
                            project_id=watcher.project_id,
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
                # For now, we'll use the existing scan engine pattern
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
        Check for new MRs and process them.

        Args:
            watcher: Repository watcher to poll

        Returns:
            List of new/updated MRReview objects
        """
        if not watcher.enabled or watcher.status == "error":
            return []

        gitlab = self._get_gitlab_client(watcher)
        reviews = []

        try:
            # Parse label filter
            labels = None
            if watcher.label_filter:
                labels = [l.strip() for l in watcher.label_filter.split(',')]

            # Get open MRs
            mrs = await gitlab.get_open_merge_requests(
                project_id=watcher.project_id,
                labels=labels,
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
                    # Check if MR has been updated since review
                    mr_updated_at = mr.get("updated_at")
                    if existing.diff_reviewed_at:
                        # Skip if not updated
                        continue

                # Review this MR
                logger.info(f"Processing MR !{mr['iid']} for watcher {watcher.name}")
                review = await self.review_mr_diff(watcher, mr)
                reviews.append(review)

            # Update watcher status
            watcher.last_check = datetime.now(timezone.utc)
            watcher.last_error = None
            watcher.status = "running"

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
    ) -> str:
        """Format the summary comment for the MR"""
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

        return f"""{header}{status}

{stats}

### Summary

{summary}

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
