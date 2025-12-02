"""
GitLab Service for MR Security Reviews

Provides API interactions with GitLab for:
- Fetching open merge requests
- Getting MR diffs and changed files
- Posting comments (general and inline)
- Managing MR approvals
"""

import re
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus

import httpx

logger = logging.getLogger(__name__)


class GitLabError(Exception):
    """Base exception for GitLab API errors"""

    def __init__(self, message: str, status_code: Optional[int] = None, response_body: Optional[str] = None):
        self.message = message
        self.status_code = status_code
        self.response_body = response_body
        super().__init__(self.message)


class GitLabAuthError(GitLabError):
    """Authentication/authorization error"""
    pass


class GitLabNotFoundError(GitLabError):
    """Resource not found error"""
    pass


class GitLabRateLimitError(GitLabError):
    """Rate limit exceeded error"""
    pass


class GitLabService:
    """Service for interacting with GitLab API"""

    def __init__(self, gitlab_url: str, token: str, timeout: float = 30.0, verify_ssl: bool = False):
        """
        Initialize GitLab service.

        Args:
            gitlab_url: Base GitLab URL (e.g., https://gitlab.com)
            token: GitLab personal access token or project access token
            timeout: HTTP request timeout in seconds
            verify_ssl: Whether to verify SSL certificates (default False for self-hosted GitLab)
        """
        self.base_url = gitlab_url.rstrip('/')
        self.api_url = f"{self.base_url}/api/v4"
        self.token = token
        self.headers = {
            "PRIVATE-TOKEN": token,
            "Content-Type": "application/json",
        }
        self.client = httpx.AsyncClient(timeout=timeout, headers=self.headers, verify=verify_ssl)

    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()

    def _encode_project_id(self, project_id: str) -> str:
        """URL-encode project ID if it's a path (e.g., 'group/project')"""
        if '/' in project_id:
            return quote_plus(project_id)
        return project_id

    async def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """
        Make an authenticated request to GitLab API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (without base URL)
            params: Query parameters
            json_data: JSON body data

        Returns:
            Parsed JSON response

        Raises:
            GitLabError: On API errors
        """
        url = f"{self.api_url}/{endpoint.lstrip('/')}"

        try:
            response = await self.client.request(
                method,
                url,
                params=params,
                json=json_data,
            )

            # Handle error responses
            if response.status_code == 401:
                raise GitLabAuthError(
                    "Authentication failed. Check your GitLab token.",
                    status_code=401,
                    response_body=response.text
                )
            elif response.status_code == 403:
                raise GitLabAuthError(
                    "Access forbidden. Check token permissions.",
                    status_code=403,
                    response_body=response.text
                )
            elif response.status_code == 404:
                raise GitLabNotFoundError(
                    f"Resource not found: {endpoint}",
                    status_code=404,
                    response_body=response.text
                )
            elif response.status_code == 429:
                raise GitLabRateLimitError(
                    "GitLab API rate limit exceeded",
                    status_code=429,
                    response_body=response.text
                )
            elif response.status_code >= 400:
                raise GitLabError(
                    f"GitLab API error: {response.status_code}",
                    status_code=response.status_code,
                    response_body=response.text
                )

            # Return empty dict for 204 No Content
            if response.status_code == 204:
                return {}

            # Handle empty response body
            if not response.content:
                raise GitLabError(
                    f"Empty response from GitLab API (status {response.status_code}). Check GitLab connectivity.",
                    status_code=response.status_code,
                    response_body=""
                )

            # Try to parse JSON
            try:
                return response.json()
            except Exception as json_err:
                raise GitLabError(
                    f"Invalid JSON response from GitLab: {str(json_err)[:100]}",
                    status_code=response.status_code,
                    response_body=response.text[:500] if response.text else ""
                )

        except httpx.RequestError as e:
            raise GitLabError(f"Network error connecting to GitLab: {str(e)}")

    # -------------------------------------------------------------------------
    # Project Information
    # -------------------------------------------------------------------------

    async def get_project(self, project_id: str) -> Dict[str, Any]:
        """
        Get project information.

        Args:
            project_id: Project ID or URL-encoded path

        Returns:
            Project data dictionary
        """
        encoded_id = self._encode_project_id(project_id)
        return await self._request("GET", f"projects/{encoded_id}")

    async def test_connection(self, project_id: str) -> Dict[str, Any]:
        """
        Test connection to GitLab and verify access to project.

        Args:
            project_id: Project ID or URL-encoded path

        Returns:
            Dict with connection status and project info
        """
        try:
            project = await self.get_project(project_id)
            return {
                "success": True,
                "project_name": project.get("name"),
                "project_path": project.get("path_with_namespace"),
                "default_branch": project.get("default_branch"),
                "web_url": project.get("web_url"),
            }
        except GitLabError as e:
            return {
                "success": False,
                "error": e.message,
                "status_code": e.status_code,
            }

    # -------------------------------------------------------------------------
    # Merge Request Operations
    # -------------------------------------------------------------------------

    async def get_open_merge_requests(
        self,
        project_id: str,
        labels: Optional[List[str]] = None,
        target_branch: Optional[str] = None,
        created_after: Optional[str] = None,
        per_page: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Get all open MRs for a project.

        Args:
            project_id: Project ID or URL-encoded path
            labels: Filter by labels (comma-separated)
            target_branch: Filter by target branch
            created_after: ISO 8601 datetime - only return MRs created after this date
            per_page: Number of results per page

        Returns:
            List of merge request objects
        """
        encoded_id = self._encode_project_id(project_id)

        params = {
            "state": "opened",
            "per_page": per_page,
        }

        if labels:
            params["labels"] = ",".join(labels)
        if target_branch:
            params["target_branch"] = target_branch
        if created_after:
            params["created_after"] = created_after

        return await self._request(
            "GET",
            f"projects/{encoded_id}/merge_requests",
            params=params
        )

    async def get_merge_request(
        self,
        project_id: str,
        mr_iid: int,
    ) -> Dict[str, Any]:
        """
        Get details of a specific merge request.

        Args:
            project_id: Project ID or URL-encoded path
            mr_iid: Merge request internal ID

        Returns:
            Merge request data
        """
        encoded_id = self._encode_project_id(project_id)
        return await self._request(
            "GET",
            f"projects/{encoded_id}/merge_requests/{mr_iid}"
        )

    async def get_mr_diff(
        self,
        project_id: str,
        mr_iid: int,
    ) -> Dict[str, Any]:
        """
        Get the diff/changes for an MR.

        Args:
            project_id: Project ID or URL-encoded path
            mr_iid: Merge request internal ID

        Returns:
            Dict with 'changes' key containing list of file diffs
        """
        encoded_id = self._encode_project_id(project_id)
        return await self._request(
            "GET",
            f"projects/{encoded_id}/merge_requests/{mr_iid}/changes"
        )

    async def get_mr_files(
        self,
        project_id: str,
        mr_iid: int,
    ) -> List[str]:
        """
        Get list of changed files in an MR.

        Args:
            project_id: Project ID or URL-encoded path
            mr_iid: Merge request internal ID

        Returns:
            List of file paths that were modified
        """
        diff_data = await self.get_mr_diff(project_id, mr_iid)
        changes = diff_data.get("changes", [])
        return [change.get("new_path") for change in changes if change.get("new_path")]

    async def get_file_content(
        self,
        project_id: str,
        file_path: str,
        ref: str,
    ) -> str:
        """
        Get the content of a file at a specific ref.

        Args:
            project_id: Project ID or URL-encoded path
            file_path: Path to the file in the repository
            ref: Branch name, tag, or commit SHA

        Returns:
            File content as string
        """
        encoded_id = self._encode_project_id(project_id)
        encoded_path = quote_plus(file_path)

        response = await self._request(
            "GET",
            f"projects/{encoded_id}/repository/files/{encoded_path}/raw",
            params={"ref": ref}
        )

        # Raw endpoint returns text, not JSON
        return response if isinstance(response, str) else str(response)

    # -------------------------------------------------------------------------
    # Comment Operations
    # -------------------------------------------------------------------------

    async def post_mr_comment(
        self,
        project_id: str,
        mr_iid: int,
        comment: str,
    ) -> Dict[str, Any]:
        """
        Post a general comment on an MR.

        Args:
            project_id: Project ID or URL-encoded path
            mr_iid: Merge request internal ID
            comment: Comment text (supports Markdown)

        Returns:
            Created note object
        """
        encoded_id = self._encode_project_id(project_id)

        return await self._request(
            "POST",
            f"projects/{encoded_id}/merge_requests/{mr_iid}/notes",
            json_data={"body": comment}
        )

    async def post_inline_comment(
        self,
        project_id: str,
        mr_iid: int,
        file_path: str,
        new_line: int,
        comment: str,
        base_sha: str,
        head_sha: str,
        start_sha: str,
        old_line: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Post an inline comment on a specific line in the diff.

        Args:
            project_id: Project ID or URL-encoded path
            mr_iid: Merge request internal ID
            file_path: Path to the file being commented on
            new_line: Line number in the new version of the file
            comment: Comment text (supports Markdown)
            base_sha: SHA of the merge request base commit
            head_sha: SHA of the merge request head commit
            start_sha: SHA of the diff start commit
            old_line: Line number in the old version (for modified lines)

        Returns:
            Created discussion object
        """
        encoded_id = self._encode_project_id(project_id)

        position = {
            "base_sha": base_sha,
            "head_sha": head_sha,
            "start_sha": start_sha,
            "position_type": "text",
            "new_path": file_path,
            "new_line": new_line,
        }

        if old_line:
            position["old_path"] = file_path
            position["old_line"] = old_line

        return await self._request(
            "POST",
            f"projects/{encoded_id}/merge_requests/{mr_iid}/discussions",
            json_data={
                "body": comment,
                "position": position,
            }
        )

    async def update_comment(
        self,
        project_id: str,
        mr_iid: int,
        note_id: int,
        comment: str,
    ) -> Dict[str, Any]:
        """
        Update an existing comment.

        Args:
            project_id: Project ID or URL-encoded path
            mr_iid: Merge request internal ID
            note_id: Note ID to update
            comment: New comment text

        Returns:
            Updated note object
        """
        encoded_id = self._encode_project_id(project_id)

        return await self._request(
            "PUT",
            f"projects/{encoded_id}/merge_requests/{mr_iid}/notes/{note_id}",
            json_data={"body": comment}
        )

    async def delete_comment(
        self,
        project_id: str,
        mr_iid: int,
        note_id: int,
    ) -> Dict[str, Any]:
        """
        Delete a comment.

        Args:
            project_id: Project ID or URL-encoded path
            mr_iid: Merge request internal ID
            note_id: Note ID to delete

        Returns:
            Empty dict on success
        """
        encoded_id = self._encode_project_id(project_id)

        return await self._request(
            "DELETE",
            f"projects/{encoded_id}/merge_requests/{mr_iid}/notes/{note_id}"
        )

    # -------------------------------------------------------------------------
    # Approval Operations
    # -------------------------------------------------------------------------

    async def approve_mr(
        self,
        project_id: str,
        mr_iid: int,
        sha: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Approve a merge request.

        Args:
            project_id: Project ID or URL-encoded path
            mr_iid: Merge request internal ID
            sha: Optional SHA of the commit to approve

        Returns:
            Approval data
        """
        encoded_id = self._encode_project_id(project_id)

        json_data = {}
        if sha:
            json_data["sha"] = sha

        return await self._request(
            "POST",
            f"projects/{encoded_id}/merge_requests/{mr_iid}/approve",
            json_data=json_data if json_data else None
        )

    async def unapprove_mr(
        self,
        project_id: str,
        mr_iid: int,
    ) -> Dict[str, Any]:
        """
        Remove approval from a merge request.

        Args:
            project_id: Project ID or URL-encoded path
            mr_iid: Merge request internal ID

        Returns:
            Empty dict on success
        """
        encoded_id = self._encode_project_id(project_id)

        return await self._request(
            "POST",
            f"projects/{encoded_id}/merge_requests/{mr_iid}/unapprove"
        )

    async def get_mr_approvals(
        self,
        project_id: str,
        mr_iid: int,
    ) -> Dict[str, Any]:
        """
        Get approval status of an MR.

        Args:
            project_id: Project ID or URL-encoded path
            mr_iid: Merge request internal ID

        Returns:
            Approval rules and status
        """
        encoded_id = self._encode_project_id(project_id)

        return await self._request(
            "GET",
            f"projects/{encoded_id}/merge_requests/{mr_iid}/approvals"
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
