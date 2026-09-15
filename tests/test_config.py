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


def test_severity_threshold_validation():
    """Verify valid severity levels and fallback to MEDIUM for invalid ones."""
    with mock.patch.dict(os.environ, {"SEVERITY_THRESHOLD": "high"}, clear=True):
        assert Settings().SEVERITY_THRESHOLD == "HIGH"

    with mock.patch.dict(os.environ, {"SEVERITY_THRESHOLD": "INVALID_LEVEL"}, clear=True):
        assert Settings().SEVERITY_THRESHOLD == "MEDIUM"
