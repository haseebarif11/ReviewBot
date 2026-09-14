"""
Integration and unit tests for webhook signature verification and endpoints.
"""

import hashlib
import hmac
import json
from fastapi.testclient import TestClient
from app.main import app, verify_signature


def generate_test_signature(secret: str, payload_bytes: bytes) -> str:
    mac = hmac.new(secret.encode("utf-8"), msg=payload_bytes, digestmod=hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def test_verify_signature_direct():
    secret = "super_secret_webhook_key"
    payload = b'{"action": "opened"}'

    valid_sig = generate_test_signature(secret, payload)
    assert verify_signature(payload, valid_sig, secret) is True

    # Tampered payload
    assert verify_signature(b'{"action": "closed"}', valid_sig, secret) is False

    # Bad prefix
    assert verify_signature(payload, "invalid_sig", secret) is False

    # Missing signature
    assert verify_signature(payload, None, secret) is False


def test_health_endpoint():
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["service"] == "ReviewBot"


def test_dashboard_endpoint():
    client = TestClient(app)
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "ReviewBot" in resp.text
    assert "PRs Reviewed" in resp.text


def test_dashboard_xss_escaping():
    from app.review_agent.history import history_tracker
    history_tracker.record_review(
        owner="attacker",
        repo="xss-repo<script>",
        pull_number=1337,
        commit_sha="c0ffee<script>alert(1)</script>",
        pr_title="PR <script>alert('xss')</script> Injection",
        verdict="APPROVE",
        total_findings=0,
        findings_by_severity={},
    )
    client = TestClient(app)
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "<script>alert('xss')</script>" not in resp.text
    assert "&lt;script&gt;" in resp.text


def test_webhook_unauthorized_with_wrong_sig():
    from app.config import settings
    orig_secret = settings.GITHUB_WEBHOOK_SECRET
    settings.GITHUB_WEBHOOK_SECRET = "test_secret_123"

    try:
        client = TestClient(app)
        payload = {"action": "opened"}
        payload_bytes = json.dumps(payload).encode()

        resp = client.post(
            "/webhook",
            content=payload_bytes,
            headers={
                "X-Hub-Signature-256": "sha256=wrongsignature",
                "X-GitHub-Event": "pull_request",
                "Content-Type": "application/json"
            }
        )
        assert resp.status_code == 401
    finally:
        settings.GITHUB_WEBHOOK_SECRET = orig_secret


def test_webhook_pr_opened_accepted():
    from app.config import settings
    secret = "test_secret_123"
    orig_secret = settings.GITHUB_WEBHOOK_SECRET
    settings.GITHUB_WEBHOOK_SECRET = secret

    try:
        client = TestClient(app)
        payload = {
            "action": "opened",
            "pull_request": {
                "number": 101,
                "title": "Add feature",
                "body": "PR description",
                "head": {"sha": "c0ffee123456"}
            },
            "repository": {
                "name": "my-repo",
                "owner": {"login": "octocat"}
            }
        }
        payload_bytes = json.dumps(payload).encode()
        sig = generate_test_signature(secret, payload_bytes)

        resp = client.post(
            "/webhook",
            content=payload_bytes,
            headers={
                "X-Hub-Signature-256": sig,
                "X-GitHub-Event": "pull_request",
                "Content-Type": "application/json"
            }
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["pr"] == 101
        assert data["repo"] == "octocat/my-repo"
    finally:
        settings.GITHUB_WEBHOOK_SECRET = orig_secret


def test_pull_request_review_comment_ignore_dismissal(monkeypatch):
    from unittest.mock import AsyncMock
    from app.config import settings
    from app.github_client.client import GitHubClient
    from app.review_agent.history import history_tracker
    from app.review_agent.schemas import Category, FileReviewFinding, FileReviewResult, Severity

    secret = "test_secret_123"
    orig_secret = settings.GITHUB_WEBHOOK_SECRET
    settings.GITHUB_WEBHOOK_SECRET = secret

    mock_orig_comment = {
        "id": 555,
        "path": "app/vuln.py",
        "line": 42,
        "body": "### 🚨 **CRITICAL** | SECURITY\n**SQL Injection Risk**\nUnsanitized input formatted into query."
    }

    mock_get_comment = AsyncMock(return_value=mock_orig_comment)
    mock_react = AsyncMock(return_value={"id": 1})
    monkeypatch.setattr(GitHubClient, "get_review_comment", mock_get_comment)
    monkeypatch.setattr(GitHubClient, "create_review_comment_reaction", mock_react)

    try:
        client = TestClient(app)
        payload = {
            "action": "created",
            "comment": {
                "id": 999,
                "in_reply_to_id": 555,
                "body": "/reviewbot ignore This is intentional for test fixture",
            },
            "pull_request": {
                "number": 77
            },
            "repository": {
                "name": "sec-repo",
                "owner": {"login": "sec-org"}
            }
        }
        payload_bytes = json.dumps(payload).encode()
        sig = generate_test_signature(secret, payload_bytes)

        resp = client.post(
            "/webhook",
            content=payload_bytes,
            headers={
                "X-Hub-Signature-256": sig,
                "X-GitHub-Event": "pull_request_review_comment",
                "Content-Type": "application/json"
            }
        )
        assert resp.status_code == 200
        assert resp.json()["message"] == "Dismissed finding via review comment."

        # Verify finding was recorded as dismissed in history
        expected_hash = history_tracker.finding_hash("app/vuln.py", 42, "SQL Injection Risk")
        assert history_tracker.is_finding_dismissed("sec-org", "sec-repo", 77, expected_hash) is True

        # Verify on subsequent review of the same PR, dismissed finding is filtered out
        finding_dismissed = FileReviewFinding(
            file="app/vuln.py",
            line=42,
            severity=Severity.CRITICAL,
            category=Category.SECURITY,
            title="SQL Injection Risk",
            comment="Old issue"
        )
        finding_new = FileReviewFinding(
            file="app/vuln.py",
            line=50,
            severity=Severity.HIGH,
            category=Category.LOGIC_BUG,
            title="Resource Leak",
            comment="Unclosed file"
        )

        res = FileReviewResult(file="app/vuln.py", summary="Test", findings=[finding_dismissed, finding_new])
        filtered = [
            f for f in res.findings
            if not history_tracker.is_finding_dismissed(
                "sec-org", "sec-repo", 77, history_tracker.finding_hash(f.file, f.line, f.title)
            )
        ]
        assert len(filtered) == 1
        assert filtered[0].title == "Resource Leak"
        assert filtered[0].line == 50
    finally:
        settings.GITHUB_WEBHOOK_SECRET = orig_secret


def test_guardrail_file_count_exceeded(monkeypatch, caplog):
    import asyncio
    import logging
    from unittest.mock import AsyncMock
    from app.config import settings
    from app.github_client.client import GitHubClient
    from app.main import process_pull_request_review

    mock_files = [{"filename": f"file_{i}.py", "patch": "+x"} for i in range(35)]
    mock_get_files = AsyncMock(return_value=mock_files)
    mock_post_comment = AsyncMock(return_value={"id": 123})
    mock_post_review = AsyncMock()

    monkeypatch.setattr(GitHubClient, "get_pull_request_files", mock_get_files)
    monkeypatch.setattr(GitHubClient, "post_issue_comment", mock_post_comment)
    monkeypatch.setattr(GitHubClient, "post_review", mock_post_review)

    orig_limit = settings.MAX_FILES_PER_REVIEW
    settings.MAX_FILES_PER_REVIEW = 30

    try:
        with caplog.at_level(logging.WARNING):
            asyncio.run(
                process_pull_request_review(
                    owner="org",
                    repo="large-repo",
                    pull_number=10,
                    commit_sha="abcdef9999",
                    pr_title="Huge PR",
                    pr_body="Body",
                    force_review=True,
                )
            )

        assert mock_post_comment.called
        call_body = mock_post_comment.call_args.kwargs["body"]
        assert "This PR is too large for automated review" in call_body
        assert "35 files changed, limit is 30" in call_body
        assert not mock_post_review.called
        assert "Cost guardrail triggered" in caplog.text

    finally:
        settings.MAX_FILES_PER_REVIEW = orig_limit


def test_guardrail_diff_size_exceeded(monkeypatch, caplog):
    import asyncio
    import logging
    from unittest.mock import AsyncMock
    from app.config import settings
    from app.github_client.client import GitHubClient
    from app.main import process_pull_request_review

    huge_patch = "+" + ("x" * 600_000)
    mock_files = [{"filename": "huge_file.py", "patch": huge_patch}]
    mock_get_files = AsyncMock(return_value=mock_files)
    mock_post_comment = AsyncMock(return_value={"id": 124})
    mock_post_review = AsyncMock()

    monkeypatch.setattr(GitHubClient, "get_pull_request_files", mock_get_files)
    monkeypatch.setattr(GitHubClient, "post_issue_comment", mock_post_comment)
    monkeypatch.setattr(GitHubClient, "post_review", mock_post_review)

    orig_limit = settings.MAX_DIFF_SIZE_BYTES
    settings.MAX_DIFF_SIZE_BYTES = 500_000

    try:
        with caplog.at_level(logging.WARNING):
            asyncio.run(
                process_pull_request_review(
                    owner="org",
                    repo="large-repo",
                    pull_number=11,
                    commit_sha="abcdef8888",
                    pr_title="Big Diff PR",
                    pr_body="Body",
                    force_review=True,
                )
            )

        assert mock_post_comment.called
        call_body = mock_post_comment.call_args.kwargs["body"]
        assert "This PR is too large for automated review" in call_body
        assert "diff bytes, limit is 500000 bytes" in call_body
        assert not mock_post_review.called
        assert "Cost guardrail triggered" in caplog.text

    finally:
        settings.MAX_DIFF_SIZE_BYTES = orig_limit


