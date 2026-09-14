"""
Prompt builder for per-file pull request reviews.
Annotates diff hunks with line numbers to enable exact line references.
"""

from typing import Optional
from app.github_client.diff_parser import ParsedFileDiff


def build_file_review_prompt(
    file_diff: ParsedFileDiff,
    pr_title: str = "",
    pr_body: str = "",
    max_tokens_budget: int = 4000
) -> str:
    """
    Constructs the review prompt for a single changed file.
    Includes PR context, change type, and line-annotated diff.
    """
    lines_annotated = []

    for hunk_idx, hunk in enumerate(file_diff.hunks, 1):
        lines_annotated.append(f"--- Hunk {hunk_idx} [{hunk.header}] ---")
        for hl in hunk.lines:
            if hl.line_type == "addition":
                prefix = f"+ [Line {hl.new_line_number:>4}] "
            elif hl.line_type == "deletion":
                prefix = f"- [Old  {hl.old_line_number:>4}] "
            else:
                prefix = f"  [Line {hl.new_line_number:>4}] "

            lines_annotated.append(f"{prefix}{hl.content}")

    diff_body = "\n".join(lines_annotated)

    # Truncate if diff is excessively long
    if len(diff_body) > (max_tokens_budget * 4):
        diff_body = diff_body[: max_tokens_budget * 4] + "\n\n... [DIFF TRUNCATED DUE TO SIZE LIMIT] ..."

    prompt = f"""Review the following pull request file changes:

File: `{file_diff.filename}`
Change status: {file_diff.status} (+{file_diff.additions} / -{file_diff.deletions})

<untrusted_pr_context>
<untrusted_pr_title>
{pr_title or "N/A"}
</untrusted_pr_title>

<untrusted_pr_description>
{pr_body or "No description provided."}
</untrusted_pr_description>
</untrusted_pr_context>

### Annotated Diff:
<untrusted_diff>
```diff
{diff_body}
```
</untrusted_diff>

Please analyze this file diff according to the review instructions. Return your findings as the specified JSON object.
"""
    return prompt
