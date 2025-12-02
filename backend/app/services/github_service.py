"""
GitHub Service for PR Security Reviews

Provides API interactions with GitHub for:
- Fetching open pull requests
- Getting PR diffs and changed files
- Posting comments (general and inline)
- Managing PR reviews
"""

import re
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx

logger = logging.getLogger(__name__)


class GitHubError(Exception):
    """Base exception for GitHub API errors"""

    def __init__(self, message: str, status_code: Optional[int] = None, response_body: Optional[str] = None):
        self.message = message
        self.status_code = status_code
        self.response_body = response_body
        super().__init__(self.message)


class GitHubAuthError(GitHubError):
    """Authentication/authorization error"""
    pass


class GitHubNotFoundError(GitHubError):
    """Resource not found error"""
    pass


class GitHubRateLimitError(GitHubError):
    """Rate limit exceeded error"""
    pass


class GitHubService:
    """Service for interacting with GitHub API"""

    def __init__(self, github_url: str, token: Optional[str] = None, timeout: float = 30.0):
        """
        Initialize GitHub service.

        Args:
            github_url: GitHub API URL (e.g., https://api.github.com)
            token: GitHub personal access token or fine-grained token (optional for public repos)
            timeout: HTTP request timeout in seconds
        """
        self.base_url = github_url.rstrip('/')
        self.token = token
        self.headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        # Only add Authorization header if token is provided
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
        self.client = httpx.AsyncClient(timeout=timeout, headers=self.headers)

    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()

    async def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        accept_header: Optional[str] = None,
    ) -> Any:
        """
        Make an authenticated request to GitHub API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, PATCH)
            endpoint: API endpoint (without base URL)
            params: Query parameters
            json_data: JSON body data
            accept_header: Optional custom Accept header

        Returns:
            Parsed JSON response

        Raises:
            GitHubError: On API errors
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        headers = dict(self.headers)
        if accept_header:
            headers["Accept"] = accept_header

        try:
            response = await self.client.request(
                method,
                url,
                params=params,
                json=json_data,
                headers=headers,
            )

            # Handle error responses
            if response.status_code == 401:
                raise GitHubAuthError(
                    "Authentication failed. Check your GitHub token.",
                    status_code=401,
                    response_body=response.text
                )
            elif response.status_code == 403:
                # Check if rate limited
                if "rate limit" in response.text.lower():
                    raise GitHubRateLimitError(
                        "GitHub API rate limit exceeded",
                        status_code=403,
                        response_body=response.text
                    )
                raise GitHubAuthError(
                    "Access forbidden. Check token permissions.",
                    status_code=403,
                    response_body=response.text
                )
            elif response.status_code == 404:
                raise GitHubNotFoundError(
                    f"Resource not found: {endpoint}",
                    status_code=404,
                    response_body=response.text
                )
            elif response.status_code == 429:
                raise GitHubRateLimitError(
                    "GitHub API rate limit exceeded",
                    status_code=429,
                    response_body=response.text
                )
            elif response.status_code >= 400:
                raise GitHubError(
                    f"GitHub API error: {response.status_code}",
                    status_code=response.status_code,
                    response_body=response.text
                )

            # Return empty dict for 204 No Content
            if response.status_code == 204:
                return {}

            # Handle empty response body
            if not response.content:
                return {}

            # Try to parse JSON (unless expecting raw content)
            content_type = response.headers.get("content-type", "")
            if "application/json" in content_type or accept_header is None:
                try:
                    return response.json()
                except Exception:
                    # Return raw text if JSON parsing fails
                    return response.text
            else:
                return response.text

        except httpx.RequestError as e:
            raise GitHubError(f"Network error connecting to GitHub: {str(e)}")

    # -------------------------------------------------------------------------
    # Repository Information
    # -------------------------------------------------------------------------

    async def get_repository(self, owner: str, repo: str) -> Dict[str, Any]:
        """
        Get repository information.

        Args:
            owner: Repository owner (user or organization)
            repo: Repository name

        Returns:
            Repository data dictionary
        """
        return await self._request("GET", f"repos/{owner}/{repo}")

    async def test_connection(self, owner: str, repo: str) -> Dict[str, Any]:
        """
        Test connection to GitHub and verify access to repository.

        Args:
            owner: Repository owner
            repo: Repository name

        Returns:
            Dict with connection status and repository info
        """
        try:
            repository = await self.get_repository(owner, repo)
            return {
                "success": True,
                "repo_name": repository.get("name"),
                "full_name": repository.get("full_name"),
                "default_branch": repository.get("default_branch"),
                "html_url": repository.get("html_url"),
                "private": repository.get("private"),
            }
        except GitHubError as e:
            return {
                "success": False,
                "error": e.message,
                "status_code": e.status_code,
            }

    # -------------------------------------------------------------------------
    # Pull Request Operations
    # -------------------------------------------------------------------------

    async def get_open_pull_requests(
        self,
        owner: str,
        repo: str,
        base: Optional[str] = None,
        sort: str = "created",
        direction: str = "desc",
        per_page: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Get all open PRs for a repository.

        Args:
            owner: Repository owner
            repo: Repository name
            base: Filter by base branch
            sort: Sort by created, updated, popularity, long-running
            direction: Sort direction (asc or desc)
            per_page: Number of results per page (max 100)

        Returns:
            List of pull request objects
        """
        params = {
            "state": "open",
            "sort": sort,
            "direction": direction,
            "per_page": min(per_page, 100),
        }

        if base:
            params["base"] = base

        return await self._request(
            "GET",
            f"repos/{owner}/{repo}/pulls",
            params=params
        )

    async def get_pull_request(
        self,
        owner: str,
        repo: str,
        pr_number: int,
    ) -> Dict[str, Any]:
        """
        Get details of a specific pull request.

        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: Pull request number

        Returns:
            Pull request data
        """
        return await self._request(
            "GET",
            f"repos/{owner}/{repo}/pulls/{pr_number}"
        )

    async def get_pr_diff(
        self,
        owner: str,
        repo: str,
        pr_number: int,
    ) -> str:
        """
        Get the raw diff for a PR.

        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: Pull request number

        Returns:
            Raw diff string
        """
        return await self._request(
            "GET",
            f"repos/{owner}/{repo}/pulls/{pr_number}",
            accept_header="application/vnd.github.diff"
        )

    async def get_pr_files(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        per_page: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Get list of changed files in a PR.

        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: Pull request number
            per_page: Number of results per page

        Returns:
            List of file change objects with filename, status, additions, deletions, patch
        """
        return await self._request(
            "GET",
            f"repos/{owner}/{repo}/pulls/{pr_number}/files",
            params={"per_page": min(per_page, 100)}
        )

    async def get_file_content(
        self,
        owner: str,
        repo: str,
        path: str,
        ref: str,
    ) -> str:
        """
        Get the content of a file at a specific ref.

        Args:
            owner: Repository owner
            repo: Repository name
            path: Path to the file in the repository
            ref: Branch name, tag, or commit SHA

        Returns:
            File content as string
        """
        import base64

        result = await self._request(
            "GET",
            f"repos/{owner}/{repo}/contents/{path}",
            params={"ref": ref}
        )

        # GitHub returns base64 encoded content
        if isinstance(result, dict) and "content" in result:
            content = result["content"]
            # Remove newlines that GitHub adds
            content = content.replace("\n", "")
            return base64.b64decode(content).decode("utf-8")

        return str(result)

    # -------------------------------------------------------------------------
    # Comment Operations
    # -------------------------------------------------------------------------

    async def post_pr_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        comment: str,
    ) -> Dict[str, Any]:
        """
        Post a general comment on a PR (issue comment).

        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: Pull request number
            comment: Comment text (supports Markdown)

        Returns:
            Created comment object
        """
        return await self._request(
            "POST",
            f"repos/{owner}/{repo}/issues/{pr_number}/comments",
            json_data={"body": comment}
        )

    async def post_review_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        commit_sha: str,
        path: str,
        line: int,
        comment: str,
        side: str = "RIGHT",
    ) -> Dict[str, Any]:
        """
        Post an inline comment on a specific line in the PR diff.

        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: Pull request number
            commit_sha: The SHA of the commit needing a comment
            path: Path to the file being commented on
            line: Line number in the diff
            comment: Comment text (supports Markdown)
            side: Which side of the diff (LEFT or RIGHT)

        Returns:
            Created review comment object
        """
        return await self._request(
            "POST",
            f"repos/{owner}/{repo}/pulls/{pr_number}/comments",
            json_data={
                "body": comment,
                "commit_id": commit_sha,
                "path": path,
                "line": line,
                "side": side,
            }
        )

    async def create_review(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        event: str = "COMMENT",
        body: Optional[str] = None,
        comments: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Create a PR review with optional inline comments.

        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: Pull request number
            event: Review event (APPROVE, REQUEST_CHANGES, COMMENT)
            body: Overall review body text
            comments: List of inline comments with path, line, body

        Returns:
            Created review object
        """
        json_data = {"event": event}
        if body:
            json_data["body"] = body
        if comments:
            json_data["comments"] = comments

        return await self._request(
            "POST",
            f"repos/{owner}/{repo}/pulls/{pr_number}/reviews",
            json_data=json_data
        )

    async def update_comment(
        self,
        owner: str,
        repo: str,
        comment_id: int,
        comment: str,
    ) -> Dict[str, Any]:
        """
        Update an existing PR review comment.

        Args:
            owner: Repository owner
            repo: Repository name
            comment_id: Comment ID to update
            comment: New comment text

        Returns:
            Updated comment object
        """
        return await self._request(
            "PATCH",
            f"repos/{owner}/{repo}/pulls/comments/{comment_id}",
            json_data={"body": comment}
        )

    async def delete_comment(
        self,
        owner: str,
        repo: str,
        comment_id: int,
    ) -> Dict[str, Any]:
        """
        Delete a PR review comment.

        Args:
            owner: Repository owner
            repo: Repository name
            comment_id: Comment ID to delete

        Returns:
            Empty dict on success
        """
        return await self._request(
            "DELETE",
            f"repos/{owner}/{repo}/pulls/comments/{comment_id}"
        )

    # -------------------------------------------------------------------------
    # Label Operations
    # -------------------------------------------------------------------------

    async def get_pr_labels(
        self,
        owner: str,
        repo: str,
        pr_number: int,
    ) -> List[Dict[str, Any]]:
        """
        Get labels on a PR.

        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: Pull request number

        Returns:
            List of label objects
        """
        return await self._request(
            "GET",
            f"repos/{owner}/{repo}/issues/{pr_number}/labels"
        )

    # -------------------------------------------------------------------------
    # Utility Methods
    # -------------------------------------------------------------------------

    def parse_diff_hunks(self, diff: str) -> List[Dict[str, Any]]:
        """
        Parse a unified diff into hunks with line numbers.

        Args:
            diff: Unified diff string

        Returns:
            List of hunks with old_start, old_lines, new_start, new_lines, and content
        """
        hunks = []
        hunk_pattern = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$')

        current_hunk = None
        lines = diff.split('\n')

        for line in lines:
            match = hunk_pattern.match(line)
            if match:
                if current_hunk:
                    hunks.append(current_hunk)

                current_hunk = {
                    "old_start": int(match.group(1)),
                    "old_lines": int(match.group(2) or 1),
                    "new_start": int(match.group(3)),
                    "new_lines": int(match.group(4) or 1),
                    "header": match.group(5).strip(),
                    "content": [],
                }
            elif current_hunk is not None:
                current_hunk["content"].append(line)

        if current_hunk:
            hunks.append(current_hunk)

        return hunks

    def extract_added_lines(self, diff: str) -> List[Dict[str, Any]]:
        """
        Extract only added lines from a diff with their line numbers.

        Args:
            diff: Unified diff string

        Returns:
            List of dicts with 'line_number' and 'content' for each added line
        """
        added_lines = []
        hunks = self.parse_diff_hunks(diff)

        for hunk in hunks:
            new_line = hunk["new_start"]
            for line in hunk["content"]:
                if line.startswith('+') and not line.startswith('+++'):
                    added_lines.append({
                        "line_number": new_line,
                        "content": line[1:],  # Remove the '+' prefix
                    })
                    new_line += 1
                elif line.startswith('-') and not line.startswith('---'):
                    # Deleted line, don't increment new_line
                    pass
                else:
                    # Context line
                    new_line += 1

        return added_lines

    def filter_files_by_pattern(
        self,
        files: List[str],
        include_pattern: Optional[str] = None,
        exclude_pattern: Optional[str] = None,
    ) -> List[str]:
        """
        Filter file list by include/exclude patterns.

        Args:
            files: List of file paths
            include_pattern: Regex pattern for files to include
            exclude_pattern: Regex pattern for files to exclude

        Returns:
            Filtered list of file paths
        """
        result = files

        if include_pattern:
            include_re = re.compile(include_pattern)
            result = [f for f in result if include_re.search(f)]

        if exclude_pattern:
            exclude_re = re.compile(exclude_pattern)
            result = [f for f in result if not exclude_re.search(f)]

        return result

    def filter_prs_by_labels(
        self,
        prs: List[Dict[str, Any]],
        required_labels: List[str],
    ) -> List[Dict[str, Any]]:
        """
        Filter PRs to only those with at least one of the required labels.

        Args:
            prs: List of PR objects from GitHub API
            required_labels: List of label names (at least one must match)

        Returns:
            Filtered list of PRs
        """
        if not required_labels:
            return prs

        required_labels_lower = [l.lower() for l in required_labels]
        filtered = []

        for pr in prs:
            pr_labels = [label["name"].lower() for label in pr.get("labels", [])]
            if any(req in pr_labels for req in required_labels_lower):
                filtered.append(pr)

        return filtered

    def filter_prs_by_created_date(
        self,
        prs: List[Dict[str, Any]],
        created_after: str,
    ) -> List[Dict[str, Any]]:
        """
        Filter PRs to only those created after a specific date.

        Args:
            prs: List of PR objects from GitHub API
            created_after: ISO 8601 datetime string

        Returns:
            Filtered list of PRs
        """
        from datetime import datetime

        cutoff = datetime.fromisoformat(created_after.replace("Z", "+00:00"))
        filtered = []

        for pr in prs:
            created_at = pr.get("created_at", "")
            if created_at:
                pr_created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                if pr_created >= cutoff:
                    filtered.append(pr)

        return filtered
