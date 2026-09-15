"""
Unit tests for ReviewBot dashboard, health, and stats API routes.
"""

import pytest
from unittest import mock
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_dashboard_renders_successfully(client):
    """Ensure the GET /dashboard endpoint returns HTTP 200 with HTML response."""
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "ReviewBot" in response.text


def test_dashboard_xss_protection(client):
    """Ensure PR title and metadata containing HTML are safely escaped to prevent XSS."""
    mock_stats = {
        "total_prs": 1,
        "total_reviews": 1,
        "bugs_caught": 2,
        "verdicts": {"APPROVE": 0, "REQUEST_CHANGES": 1, "COMMENT": 0},
        "recent_reviews": [
            {
                "pr_key": "owner/repo#42",
                "title": "<script>alert('xss')</script>",
                "commit_sha": "abc1234<img src=x onerror=alert(1)>",
                "verdict": "REQUEST_CHANGES",
                "findings_by_severity": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0},
                "timestamp": "2026-09-16 00:00:00",
            }
        ],
    }

    with mock.patch("app.main.history_tracker.get_stats", return_value=mock_stats):
        response = client.get("/dashboard")
        assert response.status_code == 200
        # Check that dangerous script tag is escaped
        assert "<script>alert('xss')</script>" not in response.text
        assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in response.text


def test_api_stats_endpoint(client):
    """Verify GET /api/stats returns structured JSON metrics from HistoryTracker."""
    mock_stats = {
        "total_prs": 3,
        "total_reviews": 5,
        "bugs_caught": 10,
        "verdicts": {"APPROVE": 3, "REQUEST_CHANGES": 1, "COMMENT": 1},
        "recent_reviews": [],
    }
    with mock.patch("app.main.history_tracker.get_stats", return_value=mock_stats):
        response = client.get("/api/stats")
        assert response.status_code == 200
        data = response.json()
        assert data["total_prs"] == 3
        assert data["total_reviews"] == 5
        assert data["bugs_caught"] == 10
        assert data["verdicts"]["APPROVE"] == 3


def test_health_check_endpoint(client):
    """Verify GET /health returns service status and configuration."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "ReviewBot"
    assert "version" in data
