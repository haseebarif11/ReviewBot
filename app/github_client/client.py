"""
GitHub REST API client supporting both Personal Access Tokens and GitHub Apps.
Provides methods to fetch PR metadata, diffs, file contents, and submit structured reviews.
"""

import logging
import time
from typing import Any, Dict, List, Optional
import httpx
import jwt

from app.config import settings

logger = logging.getLogger("reviewbot.github_client")


class GitHubAPIError(Exception):
    """Raised when a GitHub API request fails."""
    def __init__(self, status_code: int, message: str, response_body: Optional[str] = None):
        super().__init__(f"GitHub API Error [{status_code}]: {message}")
        self.status_code = status_code
        self.message = message
        self.response_body = response_body


class GitHubClient:
    """
    Async client for GitHub REST API v3.
    Supports:
      1. Personal Access Token (PAT)
      2. GitHub App (JWT -> Installation Access Token exchange)
    """

    BASE_URL = "https://api.github.com"

    def __init__(
        self,
        token: Optional[str] = None,
        app_id: Optional[int] = None,
        app_private_key: Optional[str] = None,
        app_private_key_path: Optional[str] = None,
        installation_id: Optional[int] = None,
    ):
        self.token = token or settings.GITHUB_TOKEN
        self.app_id = app_id or settings.GITHUB_APP_ID
        self.app_private_key = app_private_key or settings.GITHUB_APP_PRIVATE_KEY
        self.app_private_key_path = app_private_key_path or settings.GITHUB_APP_PRIVATE_KEY_PATH
        self.installation_id = installation_id or settings.GITHUB_APP_INSTALLATION_ID

        # Token caching for GitHub App
        self._cached_app_token: Optional[str] = None
        self._app_token_expiry: float = 0

    def _get_private_key_content(self) -> Optional[str]:
        """Loads the private key from string or filepath."""
        if self.app_private_key:
            return self.app_private_key
        if self.app_private_key_path:
            try:
                with open(self.app_private_key_path, "r", encoding="utf-8") as f:
                    return f.read()
            except Exception as e:
                logger.error(f"Failed to read GitHub App private key from {self.app_private_key_path}: {e}")
        return None

    def _generate_app_jwt(self) -> str:
        """Generates a RS256 JWT for GitHub App authentication."""
        private_key = self._get_private_key_content()
        if not private_key or not self.app_id:
            raise ValueError("GitHub App ID and Private Key are required to generate App JWT.")

        now = int(time.time())
        payload = {
            "iat": now - 60,       # Issued 60s ago to allow clock skew
            "exp": now + (10 * 60), # 10 minute expiration
            "iss": self.app_id,
        }
        encoded_jwt = jwt.encode(payload, private_key, algorithm="RS256")
        return encoded_jwt

    async def _get_installation_token(self, installation_id: Optional[int] = None) -> str:
        """
        Exchanges GitHub App JWT for a repository installation access token.
        Caches the token until near expiration.
        """
        target_inst_id = installation_id or self.installation_id
        if not target_inst_id:
            raise ValueError("Installation ID required for GitHub App token exchange.")

        # Check cache (renew 60s before expiry)
        now = time.time()
        if self._cached_app_token and now < (self._app_token_expiry - 60):
            return self._cached_app_token

        app_jwt = self._generate_app_jwt()
        headers = {
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        url = f"{self.BASE_URL}/app/installations/{target_inst_id}/access_tokens"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, headers=headers)
            if resp.status_code != 201:
                raise GitHubAPIError(resp.status_code, "Failed to create installation access token", resp.text)

            data = resp.json()
            token = data["token"]
            # Typically expires in 1 hour
            self._cached_app_token = token
            self._app_token_expiry = now + 3500
            return token

    async def get_auth_token(self, installation_id: Optional[int] = None) -> str:
        """
        Resolves auth token: uses PAT if available, otherwise retrieves GitHub App token.
        """
        if self.token:
            return self.token
        if self.app_id and (self.app_private_key or self.app_private_key_path):
            return await self._get_installation_token(installation_id)
        raise ValueError("No GitHub credentials configured (set GITHUB_TOKEN or GITHUB_APP_* settings).")

    async def _request(
        self,
        method: str,
        endpoint: str,
        installation_id: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Any] = None,
    ) -> httpx.Response:
        """Helper to send authenticated HTTP requests to GitHub REST API."""
        token = await self.get_auth_token(installation_id)
        req_headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ReviewBot-AI-Reviewer",
        }
        if headers:
            req_headers.update(headers)

        url = f"{self.BASE_URL}/{endpoint.lstrip('/')}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.request(
                method=method,
                url=url,
                headers=req_headers,
                params=params,
                json=json_data
            )
            if response.status_code >= 400:
                logger.error(f"GitHub API Error on {method} {url}: {response.status_code} - {response.text}")
                raise GitHubAPIError(response.status_code, response.reason_phrase, response.text)
            return response

    async def get_pull_request(self, owner: str, repo: str, pull_number: int, installation_id: Optional[int] = None) -> Dict[str, Any]:
        """Fetches PR metadata."""
        resp = await self._request("GET", f"/repos/{owner}/{repo}/pulls/{pull_number}", installation_id)
        return resp.json()

    async def get_pull_request_files(self, owner: str, repo: str, pull_number: int, installation_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Fetches list of changed files with patches, handling pagination.
        """
        files = []
        page = 1
        per_page = 100

        while True:
            resp = await self._request(
                "GET",
                f"/repos/{owner}/{repo}/pulls/{pull_number}/files",
                installation_id,
                params={"page": page, "per_page": per_page}
            )
            page_files = resp.json()
            if not page_files:
                break
            files.extend(page_files)
            if len(page_files) < per_page:
                break
            page += 1

        return files

    async def get_pull_request_diff(self, owner: str, repo: str, pull_number: int, installation_id: Optional[int] = None) -> str:
        """Fetches the raw full unified diff for the PR."""
        resp = await self._request(
            "GET",
            f"/repos/{owner}/{repo}/pulls/{pull_number}",
            installation_id,
            headers={"Accept": "application/vnd.github.v3.diff"}
        )
        return resp.text

    async def get_file_content(self, owner: str, repo: str, path: str, ref: str, installation_id: Optional[int] = None) -> Optional[str]:
        """Fetches the full text content of a file at a specific git ref/commit."""
        try:
            resp = await self._request(
                "GET",
                f"/repos/{owner}/{repo}/contents/{path}",
                installation_id,
                params={"ref": ref},
                headers={"Accept": "application/vnd.github.raw"}
            )
            return resp.text
        except GitHubAPIError as e:
            logger.warning(f"Could not fetch full content for {path} at {ref}: {e}")
            return None

    async def get_existing_review_comments(self, owner: str, repo: str, pull_number: int, installation_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Fetches existing inline review comments on the PR."""
        resp = await self._request(
            "GET",
            f"/repos/{owner}/{repo}/pulls/{pull_number}/comments",
            installation_id,
            params={"per_page": 100}
        )
        return resp.json()

    async def post_review(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        commit_id: str,
        body: str,
        event: str = "COMMENT",
        comments: Optional[List[Dict[str, Any]]] = None,
        installation_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Posts a complete review (verdict summary + inline comments) to GitHub.
        Event options:
          - 'APPROVE'
          - 'REQUEST_CHANGES'
          - 'COMMENT'
        """
        payload: Dict[str, Any] = {
            "commit_id": commit_id,
            "body": body,
            "event": event.upper(),
        }
        if comments:
            payload["comments"] = comments

        resp = await self._request(
            "POST",
            f"/repos/{owner}/{repo}/pulls/{pull_number}/reviews",
            installation_id,
            json_data=payload
        )
        return resp.json()

    async def post_issue_comment(self, owner: str, repo: str, issue_number: int, body: str, installation_id: Optional[int] = None) -> Dict[str, Any]:
        """Posts a standard comment on a PR or issue."""
        payload = {"body": body}
        resp = await self._request(
            "POST",
            f"/repos/{owner}/{repo}/issues/{issue_number}/comments",
            installation_id,
            json_data=payload
        )
        return resp.json()

    async def get_review_comment(
        self,
        owner: str,
        repo: str,
        comment_id: int,
        installation_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Fetches a specific pull request review comment by ID."""
        resp = await self._request(
            "GET",
            f"/repos/{owner}/{repo}/pulls/comments/{comment_id}",
            installation_id,
        )
        return resp.json()

    async def create_review_comment_reaction(
        self,
        owner: str,
        repo: str,
        comment_id: int,
        content: str = "+1",
        installation_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Adds a reaction to a pull request review comment."""
        payload = {"content": content}
        resp = await self._request(
            "POST",
            f"/repos/{owner}/{repo}/pulls/comments/{comment_id}/reactions",
            installation_id,
            headers={"Accept": "application/vnd.github.squirrel-girl-preview+json"},
            json_data=payload,
        )
        return resp.json()

    async def create_reaction(self, owner: str, repo: str, comment_id: int, content: str = "+1", installation_id: Optional[int] = None) -> Dict[str, Any]:
        """Adds a reaction (+1, eyes, heart, etc.) to an issue comment."""
        payload = {"content": content}
        resp = await self._request(
            "POST",
            f"/repos/{owner}/{repo}/issues/comments/{comment_id}/reactions",
            installation_id,
            headers={"Accept": "application/vnd.github.squirrel-girl-preview+json"},
            json_data=payload
        )
        return resp.json()

