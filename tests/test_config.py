"""
Unit tests for configuration loading and environment variable parsing in app.config.
"""

import os
from unittest import mock
from app.config import Settings


def test_default_ignore_lists():
    """Verify default ignore extensions and files when env vars are unset."""
    with mock.patch.dict(os.environ, {}, clear=True):
        settings = Settings()
        assert ".lock" in settings.IGNORE_EXTENSIONS
        assert ".min.js" in settings.IGNORE_EXTENSIONS
        assert "package-lock.json" in settings.IGNORE_FILES

def test_comma_separated_env_vars_parsed_without_json_decode_error():
    """Verify comma-separated env vars from .env.example parse correctly without json.loads crashing."""
    env_overrides = {
        "IGNORE_EXTENSIONS": ".lock, .min.js, .min.css, .map",
        "IGNORE_FILES": "package-lock.json, yarn.lock, Cargo.lock",
    }
    with mock.patch.dict(os.environ, env_overrides, clear=True):
        settings = Settings()
        assert settings.IGNORE_EXTENSIONS == [".lock", ".min.js", ".min.css", ".map"]
        assert settings.IGNORE_FILES == ["package-lock.json", "yarn.lock", "Cargo.lock"]

def test_json_array_env_vars_parsed():
    """Verify JSON-formatted array env vars also parse properly."""
    env_overrides = {
        "IGNORE_EXTENSIONS": '["*.tmp", "*.bak"]',
        "IGNORE_FILES": '["secrets.txt", "credentials.json"]',
    }
    with mock.patch.dict(os.environ, env_overrides, clear=True):
        settings = Settings()
        assert settings.IGNORE_EXTENSIONS == ["*.tmp", "*.bak"]
        assert settings.IGNORE_FILES == ["secrets.txt", "credentials.json"]


def test_severity_threshold_validation():
    """Verify valid severity levels and fallback to MEDIUM for invalid ones."""
    with mock.patch.dict(os.environ, {"SEVERITY_THRESHOLD": "high"}, clear=True):
        assert Settings().SEVERITY_THRESHOLD == "HIGH"

    with mock.patch.dict(os.environ, {"SEVERITY_THRESHOLD": "INVALID_LEVEL"}, clear=True):
        assert Settings().SEVERITY_THRESHOLD == "MEDIUM"
