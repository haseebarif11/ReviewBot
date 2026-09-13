"""
Pydantic schemas for review findings, categories, severities, and verdicts.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def rank(cls, val: str) -> int:
        levels = {
            cls.INFO.value: 1,
            cls.LOW.value: 2,
            cls.MEDIUM.value: 3,
            cls.HIGH.value: 4,
            cls.CRITICAL.value: 5,
        }
        return levels.get(val.upper(), 0)

    def is_at_least(self, threshold: "Severity | str") -> bool:
        thresh_str = threshold.value if isinstance(threshold, Severity) else str(threshold)
        return self.rank(self.value) >= self.rank(thresh_str)


class Category(str, Enum):
    LOGIC_BUG = "LOGIC_BUG"
    SECURITY = "SECURITY"
    ERROR_HANDLING = "ERROR_HANDLING"
    PERFORMANCE = "PERFORMANCE"
    STYLE_READABILITY = "STYLE_READABILITY"
    TESTING = "TESTING"
    MAINTAINABILITY = "MAINTAINABILITY"


class Verdict(str, Enum):
    APPROVE = "APPROVE"
    REQUEST_CHANGES = "REQUEST_CHANGES"
    COMMENT = "COMMENT"


class FileReviewFinding(BaseModel):
    """A single finding/issue identified by the reviewer."""
    file: str = Field(description="File path")
    line: int = Field(description="Line number in the new file")
    severity: Severity = Field(default=Severity.MEDIUM, description="Severity level")
    category: Category = Field(default=Category.LOGIC_BUG, description="Issue category")
    title: str = Field(description="Short one-line title of the issue")
    comment: str = Field(description="Detailed explanation of what the issue is and why it matters")
    suggestion: Optional[str] = Field(default=None, description="Recommended fix or replacement code snippet")
    cwe_id: Optional[str] = Field(default=None, description="CWE identifier if security related (e.g. CWE-89)")


class FileReviewResult(BaseModel):
    """Review results for a single file."""
    file: str
    summary: str = ""
    findings: List[FileReviewFinding] = Field(default_factory=list)


class GitHubInlineComment(BaseModel):
    """Structure expected by GitHub POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews comments list."""
    path: str
    line: int
    side: str = "RIGHT"
    body: str


class AggregateReview(BaseModel):
    """Aggregated review ready to be posted to GitHub."""
    verdict: Verdict
    summary_markdown: str
    total_findings: int
    findings_by_severity: Dict[str, int] = Field(default_factory=dict)
    findings: List[FileReviewFinding] = Field(default_factory=list)
    github_comments: List[GitHubInlineComment] = Field(default_factory=list)
