"""
Review Agent orchestrating LLM calls, diff analysis, JSON extraction,
severity filtering, and GitHub review payload synthesis.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional
import anthropic
from tenacity import AsyncRetrying, retry_if_exception, stop_after_attempt, wait_exponential

from app.config import settings
from app.github_client.diff_parser import ParsedFileDiff
from app.prompts.review_prompt import build_file_review_prompt
from app.prompts.system_prompt import REVIEWER_SYSTEM_PROMPT
from app.review_agent.schemas import (
    AggregateReview,
    Category,
    FileReviewFinding,
    FileReviewResult,
    GitHubInlineComment,
    Severity,
    Verdict,
)

logger = logging.getLogger("reviewbot.agent")


def _is_retryable_anthropic_error(exc: BaseException) -> bool:
    """Identifies transient Anthropic API and HTTP status errors suitable for retry."""
    if isinstance(exc, (anthropic.RateLimitError, anthropic.InternalServerError, anthropic.APITimeoutError, anthropic.APIConnectionError)):
        return True
    if isinstance(exc, anthropic.APIStatusError) and exc.status_code in (429, 500, 502, 503, 504, 529):
        return True
    return False


class ReviewAgent:
    """
    AI-powered review agent using Anthropic's Claude to review PR diffs.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        severity_threshold: Optional[str] = None,
        auto_approve_clean_pr: Optional[bool] = None,
    ):
        self.api_key = api_key or settings.ANTHROPIC_API_KEY
        self.model = model or settings.ANTHROPIC_MODEL
        self.severity_threshold = (severity_threshold or settings.SEVERITY_THRESHOLD).upper()
        self.auto_approve_clean_pr = (
            auto_approve_clean_pr if auto_approve_clean_pr is not None else settings.AUTO_APPROVE_CLEAN_PR
        )
        self.client: Optional[anthropic.AsyncAnthropic] = None
        if self.api_key:
            self.client = anthropic.AsyncAnthropic(api_key=self.api_key)

    def _extract_json(self, raw_text: str) -> Dict[str, Any]:
        """
        Extracts and parses JSON from the LLM response, handling markdown fences
        or surrounding text. Distinguishes truncated responses from malformed JSON.
        """
        text = raw_text.strip()

        # Handle ```json ... ``` or ``` ... ```
        fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
        if fence_match:
            text = fence_match.group(1).strip()

        # Try direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Fallback: extract substring between first { and last }
        brace_match = re.search(r"(\{[\s\S]*\})", text)
        if brace_match:
            try:
                return json.loads(brace_match.group(1))
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse extracted JSON substring: {e}")

        # Distinguish truncated response from malformed JSON
        stripped = text.rstrip()
        if not (stripped.endswith("}") or stripped.endswith("```")):
            logger.warning(
                f"Anthropic response appears to have been truncated before completing JSON object "
                f"(length {len(raw_text)} chars, ends with: {stripped[-50:]!r})"
            )
        else:
            logger.error(f"Could not parse LLM output as JSON (malformed JSON):\n{raw_text[:500]}")

        return {"summary": "Unable to parse review findings.", "findings": []}

    async def review_file(
        self,
        file_diff: ParsedFileDiff,
        pr_title: str = "",
        pr_body: str = "",
    ) -> FileReviewResult:
        """
        Analyzes a single changed file diff using Claude.
        """
        if file_diff.is_ignored:
            return FileReviewResult(
                file=file_diff.filename,
                summary=f"Skipped: {file_diff.ignore_reason}",
                findings=[]
            )

        if not self.client:
            raise ValueError("Anthropic API Key is not configured. Set ANTHROPIC_API_KEY.")

        prompt = build_file_review_prompt(
            file_diff=file_diff,
            pr_title=pr_title,
            pr_body=pr_body,
            max_tokens_budget=settings.MAX_TOKENS_PER_FILE,
        )

        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(3),
                wait=wait_exponential(multiplier=1, min=1, max=10),
                retry=retry_if_exception(_is_retryable_anthropic_error),
                reraise=True,
            ):
                with attempt:
                    response = await self.client.messages.create(
                        model=self.model,
                        max_tokens=settings.MAX_RESPONSE_TOKENS,
                        system=REVIEWER_SYSTEM_PROMPT,
                        messages=[{"role": "user", "content": prompt}],
                        temperature=0.1,
                    )
            raw_response = response.content[0].text
        except Exception as e:
            logger.error(f"Anthropic API call failed for file {file_diff.filename} after retries: {e}")
            return FileReviewResult(
                file=file_diff.filename,
                summary=f"Analysis failed: {str(e)}",
                findings=[]
            )

        parsed_json = self._extract_json(raw_response)
        summary = parsed_json.get("summary", "")
        raw_findings = parsed_json.get("findings", [])

        findings: List[FileReviewFinding] = []
        for item in raw_findings:
            try:
                # Normalize severity
                sev_raw = str(item.get("severity", "MEDIUM")).upper()
                sev = Severity(sev_raw) if sev_raw in Severity.__members__ else Severity.MEDIUM

                # Normalize category
                cat_raw = str(item.get("category", "LOGIC_BUG")).upper()
                cat = Category(cat_raw) if cat_raw in Category.__members__ else Category.LOGIC_BUG

                line = int(item.get("line", 1))

                finding = FileReviewFinding(
                    file=file_diff.filename,
                    line=line,
                    severity=sev,
                    category=cat,
                    title=item.get("title", "Review Finding"),
                    comment=item.get("comment", ""),
                    suggestion=item.get("suggestion"),
                    cwe_id=item.get("cwe_id"),
                )
                findings.append(finding)
            except Exception as ex:
                logger.warning(f"Error parsing finding item for {file_diff.filename}: {ex}")

        return FileReviewResult(file=file_diff.filename, summary=summary, findings=findings)

    def format_inline_comment_body(self, finding: FileReviewFinding, line_note: Optional[str] = None) -> str:
        """
        Formats a structured Markdown comment body for GitHub inline comments.
        """
        sev_emoji = {
            Severity.CRITICAL: "🚨 **CRITICAL**",
            Severity.HIGH: "⚠️ **HIGH**",
            Severity.MEDIUM: "⚡ **MEDIUM**",
            Severity.LOW: "ℹ️ **LOW**",
            Severity.INFO: "💡 **INFO**",
        }.get(finding.severity, "🔍 **NOTE**")

        cwe_tag = f" `[{finding.cwe_id}]`" if finding.cwe_id else ""
        lines = [
            f"### {sev_emoji} | {finding.category.value}{cwe_tag}",
            f"**{finding.title}**\n",
            finding.comment,
        ]

        if line_note:
            lines.append(f"\n> _{line_note}_")

        if finding.suggestion:
            lines.append(f"\n**Suggested Fix:**\n```suggestion\n{finding.suggestion.strip()}\n```")

        return "\n".join(lines)

    def aggregate_reviews(
        self,
        file_results: List[FileReviewResult],
        file_diffs: Dict[str, ParsedFileDiff],
        severity_threshold: Optional[str] = None,
    ) -> AggregateReview:
        """
        Aggregates individual file results into a unified PR review with
        verdict, executive summary markdown, and valid GitHub inline comments.
        """
        threshold = (severity_threshold or self.severity_threshold).upper()

        all_findings: List[FileReviewFinding] = []
        counts: Dict[str, int] = {s.value: 0 for s in Severity}
        for res in file_results:
            for f in res.findings:
                all_findings.append(f)
                counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

        # Determine Verdict
        has_critical = counts.get(Severity.CRITICAL.value, 0) > 0
        has_high = counts.get(Severity.HIGH.value, 0) > 0
        has_any_findings = len(all_findings) > 0

        if has_critical or has_high:
            verdict = Verdict.REQUEST_CHANGES
        elif not has_any_findings and self.auto_approve_clean_pr:
            verdict = Verdict.APPROVE
        else:
            verdict = Verdict.COMMENT

        # Build GitHub Inline Comments (filtered by severity threshold & valid hunk lines)
        github_comments: List[GitHubInlineComment] = []
        out_of_hunk_findings: List[FileReviewFinding] = []

        for f in all_findings:
            if not f.severity.is_at_least(threshold):
                continue

            diff_info = file_diffs.get(f.file)
            if not diff_info or diff_info.is_ignored:
                out_of_hunk_findings.append(f)
                continue

            # Validate line in diff hunk
            if diff_info.is_line_commentable(f.line, side="RIGHT"):
                comment_body = self.format_inline_comment_body(f)
                github_comments.append(
                    GitHubInlineComment(path=f.file, line=f.line, side="RIGHT", body=comment_body)
                )
            else:
                # Find nearest commentable line within ±3 lines
                nearest = diff_info.find_nearest_commentable_line(f.line, side="RIGHT")
                if nearest is not None and abs(nearest - f.line) <= 3:
                    note = f"Note: This issue was flagged at line {f.line}."
                    comment_body = self.format_inline_comment_body(f, line_note=note)
                    github_comments.append(
                        GitHubInlineComment(path=f.file, line=nearest, side="RIGHT", body=comment_body)
                    )
                else:
                    out_of_hunk_findings.append(f)

        # Build Markdown Summary
        summary_md = self._build_summary_markdown(
            verdict=verdict,
            counts=counts,
            file_results=file_results,
            threshold=threshold,
            out_of_hunk_findings=out_of_hunk_findings,
        )

        return AggregateReview(
            verdict=verdict,
            summary_markdown=summary_md,
            total_findings=len(all_findings),
            findings_by_severity=counts,
            findings=all_findings,
            github_comments=github_comments,
        )

    def _build_summary_markdown(
        self,
        verdict: Verdict,
        counts: Dict[str, int],
        file_results: List[FileReviewResult],
        threshold: str,
        out_of_hunk_findings: List[FileReviewFinding],
    ) -> str:
        """Constructs an executive PR review summary formatted in GitHub Markdown."""
        verdict_banner = {
            Verdict.APPROVE: "## ✅ ReviewBot: Approved\nNo blocking issues detected. The changes appear safe, clean, and well-structured.",
            Verdict.REQUEST_CHANGES: "## ❌ ReviewBot: Changes Requested\nCritical or High-severity issues were found that should be addressed prior to merging.",
            Verdict.COMMENT: "## 💬 ReviewBot: Review Completed\nObservations and recommendations were identified for your consideration.",
        }.get(verdict, "## 🤖 ReviewBot: Review")

        # Stats Table
        stats = (
            f"| 🚨 Critical | ⚠️ High | ⚡ Medium | ℹ️ Low | 💡 Info |\n"
            f"| :---: | :---: | :---: | :---: | :---: |\n"
            f"| **{counts[Severity.CRITICAL.value]}** | "
            f"**{counts[Severity.HIGH.value]}** | "
            f"**{counts[Severity.MEDIUM.value]}** | "
            f"**{counts[Severity.LOW.value]}** | "
            f"**{counts[Severity.INFO.value]}** |\n"
        )

        lines = [
            verdict_banner,
            "",
            "### 📊 Review Overview",
            stats,
            f"> _Inline comments posted for issues with severity **{threshold}** or higher._",
            "",
        ]

        # File summaries
        lines.append("### 📁 File Summaries")
        for res in file_results:
            if not res.findings and not res.summary:
                continue
            finding_count = len(res.findings)
            status_badge = f"`{finding_count} issue(s)`" if finding_count > 0 else "`Clean`"
            lines.append(f"- **`{res.file}`** ({status_badge}): {res.summary or 'Reviewed.'}")

        # Out-of-hunk findings (placed here so they are not lost)
        if out_of_hunk_findings:
            lines.append("\n### 📌 Additional Findings (Outside Changed Lines)")
            for f in out_of_hunk_findings:
                lines.append(
                    f"- **`{f.file}:{f.line}`** [{f.severity.value}] **{f.title}**: {f.comment}"
                )

        lines.append("\n---\n*Automated review generated by [ReviewBot](https://github.com/haseebarif11/ReviewBot)*")
        return "\n".join(lines)
