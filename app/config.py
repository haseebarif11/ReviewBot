"""
Configuration management for ReviewBot using Pydantic Settings.
Reads configuration from environment variables or .env file.
"""

from typing import List, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    # Anthropic Claude configuration
    ANTHROPIC_API_KEY: Optional[str] = Field(
        default=None,
        description="Anthropic API Key for Claude code review"
    )
    ANTHROPIC_MODEL: str = Field(
        default="claude-3-5-sonnet-20241022",
        description="Claude model to use for reviews"
    )
    MAX_TOKENS_PER_FILE: int = Field(
        default=4000,
        description="Maximum tokens allowed in prompt per file"
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
    REVIEW_CONCURRENCY_LIMIT: int = Field(
        default=5,
        description="Maximum concurrent file review calls to Anthropic API"
    )

    # Ignored extensions & filenames
    IGNORE_EXTENSIONS: List[str] = Field(
        default=[
            ".lock", ".min.js", ".min.css", ".map", ".svg", ".png",
            ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".eot"
        ]
    )
    IGNORE_FILES: List[str] = Field(
        default=[
            "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
            "Cargo.lock", "Pipfile.lock", "composer.lock"
        ]
    )

    @field_validator("IGNORE_EXTENSIONS", mode="before")
    @classmethod
    def parse_ignore_extensions(cls, v):
        if isinstance(v, str):
            return [ext.strip() for ext in v.split(",") if ext.strip()]
        return v

    @field_validator("IGNORE_FILES", mode="before")
    @classmethod
    def parse_ignore_files(cls, v):
        if isinstance(v, str):
            return [f.strip() for f in v.split(",") if f.strip()]
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
