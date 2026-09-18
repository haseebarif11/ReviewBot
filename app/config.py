"""
Configuration management for ReviewBot using Pydantic Settings.
Reads configuration from environment variables or .env file.
"""

import json
from typing import Annotated, List, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Server settings
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False

    # GitHub Webhook Secret
    GITHUB_WEBHOOK_SECRET: str = Field(
        default="",
        description="Secret used to verify GitHub X-Hub-Signature-256 HMAC header"
    )

    # GitHub Auth - Personal Access Token (PAT)
    GITHUB_TOKEN: Optional[str] = Field(
        default=None,
        description="GitHub Personal Access Token for API requests"
    )

    # GitHub Auth - GitHub App
    GITHUB_APP_ID: Optional[int] = Field(
        default=None,
        description="GitHub App ID"
    )
    GITHUB_APP_PRIVATE_KEY: Optional[str] = Field(
        default=None,
        description="GitHub App Private Key (PEM format string)"
    )
    GITHUB_APP_PRIVATE_KEY_PATH: Optional[str] = Field(
        default=None,
        description="Path to GitHub App Private Key PEM file"
    )
    GITHUB_APP_INSTALLATION_ID: Optional[int] = Field(
        default=None,
        description="GitHub App Installation ID"
    )

    # Google Gemini configuration
    GEMINI_API_KEY: Optional[str] = Field(
        default=None,
        description="Google Gemini API Key for code review"
    )
    GEMINI_MODEL: str = Field(
        default="gemini-2.5-flash",
        description="Gemini model to use for reviews"
    )
    MAX_TOKENS_PER_FILE: int = Field(
        default=4000,
        description="Maximum tokens allowed in prompt per file"
    )
    MAX_RESPONSE_TOKENS: int = Field(
        default=4096,
        description="Maximum tokens allowed for Gemini review response"
    )

    # Review Bot Behavior
    SEVERITY_THRESHOLD: str = Field(
        default="MEDIUM",
        description="Minimum severity to include as inline comments: INFO, LOW, MEDIUM, HIGH, CRITICAL"
    )
    AUTO_APPROVE_CLEAN_PR: bool = Field(
        default=True,
        description="Whether to submit an APPROVE review if no critical/high issues are found"
    )
    MAX_FILE_SIZE_BYTES: int = Field(
        default=100_000,
        description="Max file size in bytes to review (skip huge files)"
    )
    MAX_FILES_PER_REVIEW: int = Field(
        default=30,
        description="Maximum changed files allowed in a single PR review"
    )
    MAX_DIFF_SIZE_BYTES: int = Field(
        default=500_000,
        description="Maximum cumulative diff size in bytes to review"
    )
    REVIEW_CONCURRENCY_LIMIT: int = Field(
        default=5,
        description="Maximum concurrent file review calls to Google Gemini API"
    )

    # Ignored extensions & filenames
    IGNORE_EXTENSIONS: Annotated[List[str], NoDecode] = Field(
        default=[
            ".lock", ".min.js", ".min.css", ".map", ".svg", ".png",
            ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".eot"
        ],
        description="File extensions to skip during review"
    )
    IGNORE_FILES: Annotated[List[str], NoDecode] = Field(
        default=[
            "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
            "Cargo.lock", "Pipfile.lock", "composer.lock"
        ],
        description="Filenames to skip during review"
    )

    @field_validator("IGNORE_EXTENSIONS", mode="before")
    @classmethod
    def parse_ignore_extensions(cls, v):
        if isinstance(v, str):
            v_s = v.strip()
            if v_s.startswith("[") and v_s.endswith("]"):
                try:
                    parsed = json.loads(v_s)
                    if isinstance(parsed, list):
                        return [str(ext).strip() for ext in parsed if str(ext).strip()]
                except Exception:
                    pass
            return [ext.strip() for ext in v_s.split(",") if ext.strip()]
        return v

    @field_validator("IGNORE_FILES", mode="before")
    @classmethod
    def parse_ignore_files(cls, v):
        if isinstance(v, str):
            v_s = v.strip()
            if v_s.startswith("[") and v_s.endswith("]"):
                try:
                    parsed = json.loads(v_s)
                    if isinstance(parsed, list):
                        return [str(f).strip() for f in parsed if str(f).strip()]
                except Exception:
                    pass
            return [f.strip() for f in v_s.split(",") if f.strip()]
        return v

    @field_validator("SEVERITY_THRESHOLD")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        valid = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        upper_v = v.upper()
        if upper_v not in valid:
            return "MEDIUM"
        return upper_v


# Singleton instance
settings = Settings()
