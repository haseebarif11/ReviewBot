"""
Unit tests for GitHubClient with mocked API interactions.
"""

import asyncio
import pytest
import httpx
from app.github_client.client import GitHubClient, GitHubAPIError


def test_client_auth_token_resolution():
    async def run():
        # Test PAT resolution
        client = GitHubClient(token="ghp_test123456789")
        token = await client.get_auth_token()
        assert token == "ghp_test123456789"

        # Test error when no auth configured
        client_empty = GitHubClient(token="")
        client_empty.token = None
        client_empty.app_id = None
        with pytest.raises(ValueError, match="No GitHub credentials configured"):
            await client_empty.get_auth_token()

    asyncio.run(run())


def test_get_pull_request():
    async def run():
        def handler(request: httpx.Request):
            assert request.url.path == "/repos/owner/repo/pulls/42"
            assert request.headers["authorization"] == "Bearer ghp_validtoken"
            return httpx.Response(
                200,
                json={
                    "number": 42,
                    "title": "Fix security vulnerability",
                    "head": {"sha": "abc1234"},
                    "base": {"sha": "def5678"},
                }
            )

        transport = httpx.MockTransport(handler)
        client = GitHubClient(token="ghp_validtoken")

        async with httpx.AsyncClient(transport=transport) as mock_http:
            async def mock_req(method, endpoint, *args, **kwargs):
                token = await client.get_auth_token()
                headers = {"Authorization": f"Bearer {token}"}
                return await mock_http.request(
                    method,
                    f"https://api.github.com/{endpoint.lstrip('/')}",
                    headers=headers
                )

            client._request = mock_req
            pr = await client.get_pull_request("owner", "repo", 42)
            assert pr["number"] == 42
            assert pr["head"]["sha"] == "abc1234"

    asyncio.run(run())


def test_post_review_payload():
    async def run():
        captured_payload = {}

        def handler(request: httpx.Request):
            import json
            nonlocal captured_payload
            captured_payload = json.loads(request.content)
            return httpx.Response(200, json={"id": 999, "state": "COMMENTED"})

        transport = httpx.MockTransport(handler)
        client = GitHubClient(token="ghp_validtoken")

        async with httpx.AsyncClient(transport=transport) as mock_http:
            async def mock_req(method, endpoint, *args, **kwargs):
                token = await client.get_auth_token()
                headers = {"Authorization": f"Bearer {token}"}
                return await mock_http.request(
                    method,
                    f"https://api.github.com/{endpoint.lstrip('/')}",
                    headers=headers,
                    json=kwargs.get("json_data")
                )

            client._request = mock_req
            comments = [
                {"path": "app/main.py", "line": 15, "side": "RIGHT", "body": "Potential SQL injection"}
            ]
            resp = await client.post_review(
                owner="owner",
                repo="repo",
                pull_number=42,
                commit_id="abc1234",
                body="ReviewBot analysis completed.",
                event="REQUEST_CHANGES",
                comments=comments
            )
            assert resp["id"] == 999
            assert captured_payload["commit_id"] == "abc1234"
            assert captured_payload["event"] == "REQUEST_CHANGES"
            assert len(captured_payload["comments"]) == 1
            assert captured_payload["comments"][0]["line"] == 15

    asyncio.run(run())
