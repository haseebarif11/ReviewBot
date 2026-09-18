#!/usr/bin/env python3
"""
CLI test utility to run ReviewBot directly on a GitHub Pull Request URL or local diff file.
Supports --dry-run to test Gemini review output without posting comments to GitHub.

Examples:
  python scripts/test_pr_review.py --pr https://github.com/owner/repo/pull/42 --dry-run
  python scripts/test_pr_review.py --repo owner/repo --pr-number 42
  python scripts/test_pr_review.py --diff-file fixtures/vulnerable_code.diff --dry-run
"""

import argparse
import asyncio
from pathlib import Path
import re
import sys
from typing import Optional

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from app.config import settings
from app.github_client.client import GitHubClient
from app.github_client.diff_parser import DiffParser, ParsedFileDiff
from app.review_agent.agent import ReviewAgent


def parse_pr_url(url: str):
    """Extracts owner, repo, pull_number from a GitHub PR URL."""
    pattern = r"github\.com/([^/]+)/([^/]+)/pull/(\d+)"
    match = re.search(pattern, url)
    if not match:
        raise ValueError(f"Invalid GitHub PR URL: {url}. Expected format: https://github.com/owner/repo/pull/123")
    return match.group(1), match.group(2), int(match.group(3))


async def run_review_on_pr(
    owner: str,
    repo: str,
    pull_number: int,
    dry_run: bool = False,
    severity_threshold: Optional[str] = None,
):
    print(f"\n🚀 Fetching PR #{pull_number} from {owner}/{repo}...")
    client = GitHubClient()
    diff_parser = DiffParser()
    agent = ReviewAgent(severity_threshold=severity_threshold)

    # 1. Fetch PR details
    pr_data = await client.get_pull_request(owner, repo, pull_number)
    title = pr_data.get("title", "")
    body = pr_data.get("body", "") or ""
    head_sha = pr_data.get("head", {}).get("sha", "")
    print(f"📌 PR Title: {title}")
    print(f"📌 Head SHA: {head_sha[:8]}")

    # 2. Fetch files
    files_payload = await client.get_pull_request_files(owner, repo, pull_number)
    print(f"📁 Found {len(files_payload)} changed file(s).")

    # 3. Parse diffs
    parsed_files = diff_parser.parse_github_files(files_payload)
    file_diffs_map = {f.filename: f for f in parsed_files}

    # 4. Analyze each file
    file_results = []
    for pf in parsed_files:
        if pf.is_ignored:
            print(f"⏩ Skipping ignored file: {pf.filename} ({pf.ignore_reason})")
            continue

        print(f"🧠 Analyzing {pf.filename} with Gemini ({agent.model})...")
        res = await agent.review_file(pf, pr_title=title, pr_body=body)
        print(f"   ↳ Found {len(res.findings)} finding(s). Summary: {res.summary}")
        file_results.append(res)

    # 5. Aggregate review
    aggregate = agent.aggregate_reviews(file_results, file_diffs_map, severity_threshold=severity_threshold)
    print("\n" + "=" * 60)
    print(f"🎯 OVERALL VERDICT: {aggregate.verdict.value}")
    print(f"📊 Total Findings: {aggregate.total_findings}")
    print(f"💬 Inline Comments to post: {len(aggregate.github_comments)}")
    print("=" * 60)

    print("\n📝 EXECUTIVE SUMMARY PREVIEW:\n")
    print(aggregate.summary_markdown)

    if aggregate.github_comments:
        print("\n💬 INLINE COMMENTS PREVIEW:\n")
        for idx, c in enumerate(aggregate.github_comments, 1):
            print(f"--- Comment #{idx} on {c.path}:{c.line} ---")
            print(c.body)
            print("-" * 40)

    # 6. Post back to GitHub if not dry run
    if dry_run:
        print("\n✨ Dry run complete! No comments were posted to GitHub.")
    else:
        print(f"\n📤 Posting review to GitHub ({aggregate.verdict.value})...")
        comments_payload = [
            {"path": c.path, "line": c.line, "side": c.side, "body": c.body}
            for c in aggregate.github_comments
        ]
        result = await client.post_review(
            owner=owner,
            repo=repo,
            pull_number=pull_number,
            commit_id=head_sha,
            body=aggregate.summary_markdown,
            event=aggregate.verdict.value,
            comments=comments_payload if comments_payload else None,
        )
        print(f"✅ Successfully posted review! GitHub Review ID: {result.get('id')}")


async def run_review_on_diff_file(diff_path: str, filename: str = "sample_file.py", severity_threshold: Optional[str] = None):
    print(f"\n🚀 Reading local diff from {diff_path}...")
    with open(diff_path, "r", encoding="utf-8") as f:
        patch_content = f.read()

    diff_parser = DiffParser()
    agent = ReviewAgent(severity_threshold=severity_threshold)

    parsed_file = diff_parser.parse_patch(
        filename=filename,
        status="modified",
        patch=patch_content,
    )

    print(f"🧠 Analyzing {filename} with Gemini ({agent.model})...")
    res = await agent.review_file(parsed_file, pr_title="Local Diff Test", pr_body="Testing with local diff file")

    aggregate = agent.aggregate_reviews([res], {filename: parsed_file}, severity_threshold=severity_threshold)

    print("\n" + "=" * 60)
    print(f"🎯 OVERALL VERDICT: {aggregate.verdict.value}")
    print(f"📊 Total Findings: {aggregate.total_findings}")
    print("=" * 60)
    print("\n📝 EXECUTIVE SUMMARY:\n")
    print(aggregate.summary_markdown)

    if aggregate.github_comments:
        print("\n💬 INLINE COMMENTS:\n")
        for idx, c in enumerate(aggregate.github_comments, 1):
            print(f"--- Comment #{idx} on {c.path}:{c.line} ---")
            print(c.body)
            print("-" * 40)


def main():
    parser = argparse.ArgumentParser(description="ReviewBot CLI Test Runner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pr", type=str, help="Full GitHub PR URL (e.g. https://github.com/owner/repo/pull/12)")
    group.add_argument("--repo", type=str, help="GitHub repo in owner/repo format")
    group.add_argument("--diff-file", type=str, help="Path to local diff file")

    parser.add_argument("--pr-number", type=int, help="PR number (required if --repo is used)")
    parser.add_argument("--dry-run", action="store_true", help="Print findings without posting to GitHub")
    parser.add_argument(
        "--severity-threshold",
        type=str,
        default="MEDIUM",
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Minimum severity threshold for inline comments",
    )

    args = parser.parse_args()

    if args.diff_file:
        asyncio.run(run_review_on_diff_file(args.diff_file, severity_threshold=args.severity_threshold))
    elif args.pr:
        owner, repo, pr_num = parse_pr_url(args.pr)
        asyncio.run(run_review_on_pr(owner, repo, pr_num, dry_run=args.dry_run, severity_threshold=args.severity_threshold))
    elif args.repo:
        if not args.pr_number:
            print("Error: --pr-number is required when --repo is specified.", file=sys.stderr)
            sys.exit(1)
        owner, repo = args.repo.split("/", 1)
        asyncio.run(run_review_on_pr(owner, repo, args.pr_number, dry_run=args.dry_run, severity_threshold=args.severity_threshold))


if __name__ == "__main__":
    main()
