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
