"""
Unit tests for ReviewAgent: JSON extraction, severity filtering,
verdict calculation, and review aggregation.
"""

from app.github_client.diff_parser import DiffParser
from app.review_agent.agent import ReviewAgent
from app.review_agent.schemas import (
    Category,
    FileReviewFinding,
    FileReviewResult,
    Severity,
    Verdict,
)


def test_extract_json_direct():
    agent = ReviewAgent()
    raw = '{"summary": "Looks good", "findings": []}'
    parsed = agent._extract_json(raw)
    assert parsed["summary"] == "Looks good"
    assert parsed["findings"] == []


def test_extract_json_with_markdown_fences():
    agent = ReviewAgent()
    raw = """Here is the review result:
```json
{
    "summary": "Found an issue",
    "findings": [
        {
            "line": 15,
            "severity": "HIGH",
            "category": "SECURITY",
            "title": "SQL Injection",
            "comment": "Unsanitized user input formatted into query."
        }
    ]
}
```
Hope this helps!
"""
    parsed = agent._extract_json(raw)
    assert parsed["summary"] == "Found an issue"
    assert len(parsed["findings"]) == 1
    assert parsed["findings"][0]["title"] == "SQL Injection"


def test_aggregate_reviews_critical_verdict():
    parser = DiffParser()
    patch = "@@ -1,5 +1,5 @@\n-old\n+new\n"
    diff = parser.parse_patch("db/query.py", "modified", patch)
    diff.valid_new_lines.add(2)

    agent = ReviewAgent(severity_threshold="MEDIUM", auto_approve_clean_pr=True)
    file_result = FileReviewResult(
        file="db/query.py",
        summary="Changes to query builder",
        findings=[
            FileReviewFinding(
                file="db/query.py",
                line=2,
                severity=Severity.CRITICAL,
                category=Category.SECURITY,
                title="Remote Code Execution",
                comment="Unsafe eval on user input.",
                cwe_id="CWE-94"
            )
        ]
    )

    agg = agent.aggregate_reviews(
        file_results=[file_result],
        file_diffs={"db/query.py": diff}
    )

    assert agg.verdict == Verdict.REQUEST_CHANGES
    assert agg.findings_by_severity["CRITICAL"] == 1
    assert len(agg.github_comments) == 1
    assert agg.github_comments[0].line == 2
    assert "CRITICAL" in agg.github_comments[0].body
    assert "CWE-94" in agg.github_comments[0].body


def test_aggregate_reviews_clean_auto_approve():
    agent = ReviewAgent(severity_threshold="MEDIUM", auto_approve_clean_pr=True)
    file_result = FileReviewResult(
        file="main.py",
        summary="Clean refactor",
        findings=[]
    )

    agg = agent.aggregate_reviews(
        file_results=[file_result],
        file_diffs={}
    )

    assert agg.verdict == Verdict.APPROVE
    assert agg.total_findings == 0
    assert len(agg.github_comments) == 0
    assert "Approved" in agg.summary_markdown


def test_severity_threshold_filtering():
    parser = DiffParser()
    patch = "@@ -1,5 +1,5 @@\n+line1\n+line2\n"
    diff = parser.parse_patch("utils.py", "modified", patch)
    diff.valid_new_lines = {1, 2}

    # Threshold is HIGH
    agent = ReviewAgent(severity_threshold="HIGH")
    file_result = FileReviewResult(
        file="utils.py",
        summary="Utility updates",
        findings=[
            FileReviewFinding(
                file="utils.py",
                line=1,
                severity=Severity.LOW,
                category=Category.STYLE_READABILITY,
                title="Naming style",
                comment="Consider snake_case."
            ),
            FileReviewFinding(
                file="utils.py",
                line=2,
                severity=Severity.HIGH,
                category=Category.LOGIC_BUG,
                title="Null pointer risk",
                comment="Variable can be None."
            )
        ]
    )

    agg = agent.aggregate_reviews(
        file_results=[file_result],
        file_diffs={"utils.py": diff},
        severity_threshold="HIGH"
    )

    # Total findings is 2, but only HIGH (1 comment) posted inline
    assert agg.total_findings == 2
    assert len(agg.github_comments) == 1
    assert agg.github_comments[0].line == 2
    assert "Null pointer risk" in agg.github_comments[0].body
