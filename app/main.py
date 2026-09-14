"""
FastAPI application for ReviewBot.
Receives GitHub webhooks, verifies HMAC signatures, runs AI reviews in the background,
handles slash commands, and provides a monitoring dashboard.
"""

import asyncio
import hashlib
import hmac
import html
import logging
import re
from typing import Any, Dict, Optional
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from app.config import settings
from app.github_client.client import GitHubClient
from app.github_client.diff_parser import DiffParser
from app.review_agent.agent import ReviewAgent
from app.review_agent.history import history_tracker
from app.review_agent.schemas import FileReviewResult

# Setup logging
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("reviewbot.server")

app = FastAPI(
    title="ReviewBot",
    description="Automated AI-Powered GitHub Pull Request Code Review Agent",
    version="0.1.0",
)

templates = Jinja2Templates(directory="templates")


def verify_signature(payload_bytes: bytes, signature_header: Optional[str], secret: str) -> bool:
    """
    Verifies that the webhook payload was sent by GitHub using HMAC SHA-256.
    """
    if not secret:
        logger.warning("GITHUB_WEBHOOK_SECRET is not configured; skipping signature verification.")
        return True

    if not signature_header:
        logger.error("Missing X-Hub-Signature-256 header in webhook request.")
        return False

    if not signature_header.startswith("sha256="):
        logger.error("Invalid X-Hub-Signature-256 prefix.")
        return False

    expected_sig = signature_header.split("sha256=", 1)[1]
    mac = hmac.new(secret.encode("utf-8"), msg=payload_bytes, digestmod=hashlib.sha256)
    computed_sig = mac.hexdigest()

    return hmac.compare_digest(expected_sig, computed_sig)


async def process_pull_request_review(
    owner: str,
    repo: str,
    pull_number: int,
    commit_sha: str,
    pr_title: str,
    pr_body: str,
    installation_id: Optional[int] = None,
    force_review: bool = False,
):
    """
    Background worker that runs the full end-to-end review pipeline:
    1. Check deduplication history
    2. Fetch PR files and patches
    3. Parse diff hunks and valid line mappings
    4. Review files with Claude (Anthropic SDK)
    5. Aggregate and post review to GitHub
    6. Record metrics in history tracker
    """
    logger.info(f"Starting review for {owner}/{repo}#{pull_number} at commit {commit_sha[:8]}...")

    # Deduplication check
    if not force_review and history_tracker.has_commit_been_reviewed(owner, repo, pull_number, commit_sha):
        logger.info(f"Commit {commit_sha[:8]} for {owner}/{repo}#{pull_number} was already reviewed. Skipping.")
        return

    try:
        github_client = GitHubClient(installation_id=installation_id)
        diff_parser = DiffParser()
        review_agent = ReviewAgent()

        # Step 1: Fetch changed files
        files_payload = await github_client.get_pull_request_files(owner, repo, pull_number, installation_id)
        logger.info(f"Fetched {len(files_payload)} changed file(s) for PR #{pull_number}.")

        # Step 2: Parse diffs
        parsed_files = diff_parser.parse_github_files(files_payload)
        file_diffs_map = {f.filename: f for f in parsed_files}

        # Step 3: Review each file concurrently with Claude (bounded by semaphore)
        semaphore = asyncio.Semaphore(settings.REVIEW_CONCURRENCY_LIMIT)

        async def _review_worker(pf):
            if pf.is_ignored:
                logger.debug(f"Skipping ignored file {pf.filename} ({pf.ignore_reason})")
                return None

            async with semaphore:
                logger.info(f"Analyzing {pf.filename} with Claude (concurrency limit: {settings.REVIEW_CONCURRENCY_LIMIT})...")
                try:
                    res = await review_agent.review_file(pf, pr_title=pr_title, pr_body=pr_body)
                except Exception as e:
                    logger.error(f"Failed to review file {pf.filename}: {e}")
                    return FileReviewResult(
                        file=pf.filename,
                        summary=f"Analysis failed: {str(e)}",
                        findings=[],
                    )

                # Filter out findings previously dismissed via /reviewbot ignore
                filtered_findings = []
                for finding in res.findings:
                    f_hash = history_tracker.finding_hash(finding.file, finding.line, finding.title)
                    if not history_tracker.is_finding_dismissed(owner, repo, pull_number, f_hash):
                        filtered_findings.append(finding)
                    else:
                        logger.info(f"Filtered out dismissed finding: {finding.title} in {finding.file}")

                res.findings = filtered_findings
                return res

        gathered_results = await asyncio.gather(*(_review_worker(pf) for pf in parsed_files), return_exceptions=True)
        file_results = []
        for res, pf in zip(gathered_results, parsed_files):
            if isinstance(res, Exception):
                logger.error(f"Unhandled exception reviewing {pf.filename}: {res}")
                file_results.append(
                    FileReviewResult(file=pf.filename, summary=f"Analysis failed: {str(res)}", findings=[])
                )
            elif res is not None:
                file_results.append(res)

        # Step 4: Aggregate review findings
        aggregate = review_agent.aggregate_reviews(file_results, file_diffs_map)
        logger.info(
            f"Review aggregated for PR #{pull_number}: Verdict={aggregate.verdict.value}, "
            f"Total Findings={aggregate.total_findings}, Inline Comments={len(aggregate.github_comments)}"
        )

        # Step 5: Post review back to GitHub
        inline_comments_payload = [
            {"path": c.path, "line": c.line, "side": c.side, "body": c.body}
            for c in aggregate.github_comments
        ]

        await github_client.post_review(
            owner=owner,
            repo=repo,
            pull_number=pull_number,
            commit_id=commit_sha,
            body=aggregate.summary_markdown,
            event=aggregate.verdict.value,
            comments=inline_comments_payload if inline_comments_payload else None,
            installation_id=installation_id,
        )

        # Step 6: Record in history
        history_tracker.record_review(
            owner=owner,
            repo=repo,
            pull_number=pull_number,
            commit_sha=commit_sha,
            pr_title=pr_title,
            verdict=aggregate.verdict.value,
            total_findings=aggregate.total_findings,
            findings_by_severity=aggregate.findings_by_severity,
        )

        logger.info(f"Successfully posted review for {owner}/{repo}#{pull_number}!")

    except Exception as e:
        logger.exception(f"Failed to complete review for PR #{pull_number}: {e}")


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring and ngrok tunnels."""
    return {
        "status": "healthy",
        "service": "ReviewBot",
        "version": "0.1.0",
        "claude_model": settings.ANTHROPIC_MODEL,
        "severity_threshold": settings.SEVERITY_THRESHOLD,
    }


@app.post("/webhook")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: Optional[str] = Header(None),
    x_github_event: Optional[str] = Header(None),
):
    """
    Main webhook receiver for GitHub events.
    Verifies HMAC-SHA256 signature and offloads processing to background tasks.
    """
    raw_body = await request.body()

    # Verify signature
    if not verify_signature(raw_body, x_hub_signature_256, settings.GITHUB_WEBHOOK_SECRET):
        logger.warning("Rejected webhook request with invalid HMAC signature.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid signature.")

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Malformed JSON.")

    event_type = x_github_event or "unknown"
    logger.info(f"Received GitHub webhook event: '{event_type}'")

    # Handle Pull Request events
    if event_type == "pull_request":
        action = payload.get("action")
        if action in ("opened", "synchronize", "reopened"):
            pr = payload.get("pull_request", {})
            repository = payload.get("repository", {})
            installation = payload.get("installation", {})

            owner = repository.get("owner", {}).get("login")
            repo = repository.get("name")
            pull_number = pr.get("number")
            commit_sha = pr.get("head", {}).get("sha")
            pr_title = pr.get("title", "")
            pr_body = pr.get("body", "") or ""
            installation_id = installation.get("id")

            if not owner or not repo or not pull_number or not commit_sha:
                return JSONResponse(status_code=400, content={"message": "Incomplete PR payload."})

            # Offload heavy AI review to background task so GitHub webhook responds <1s
            background_tasks.add_task(
                process_pull_request_review,
                owner=owner,
                repo=repo,
                pull_number=pull_number,
                commit_sha=commit_sha,
                pr_title=pr_title,
                pr_body=pr_body,
                installation_id=installation_id,
            )

            return JSONResponse(
                status_code=status.HTTP_202_ACCEPTED,
                content={
                    "message": "Pull request review queued.",
                    "repo": f"{owner}/{repo}",
                    "pr": pull_number,
                    "commit": commit_sha[:8],
                },
            )

    # Handle Issue Comment commands (e.g. /reviewbot review, /reviewbot ignore)
    elif event_type == "issue_comment":
        action = payload.get("action")
        comment_body = payload.get("comment", {}).get("body", "").strip()
        issue = payload.get("issue", {})
        is_pr = "pull_request" in issue

        if action == "created" and is_pr and comment_body.startswith("/reviewbot"):
            repository = payload.get("repository", {})
            installation = payload.get("installation", {})
            owner = repository.get("owner", {}).get("login")
            repo = repository.get("name")
            pull_number = issue.get("number")
            comment_id = payload.get("comment", {}).get("id")
            installation_id = installation.get("id")

            cmd_parts = comment_body.split()
            command = cmd_parts[1].lower() if len(cmd_parts) > 1 else "help"

            github_client = GitHubClient(installation_id=installation_id)

            if command == "review":
                # React with eyes and trigger review
                if comment_id:
                    background_tasks.add_task(github_client.create_reaction, owner, repo, comment_id, "eyes")

                # Fetch PR to get latest commit sha
                pr_data = await github_client.get_pull_request(owner, repo, pull_number, installation_id)
                commit_sha = pr_data.get("head", {}).get("sha")
                pr_title = pr_data.get("title", "")
                pr_body = pr_data.get("body", "") or ""

                background_tasks.add_task(
                    process_pull_request_review,
                    owner=owner,
                    repo=repo,
                    pull_number=pull_number,
                    commit_sha=commit_sha,
                    pr_title=pr_title,
                    pr_body=pr_body,
                    installation_id=installation_id,
                    force_review=True,
                )
                return JSONResponse(status_code=202, content={"message": "Manual re-review triggered."})

            elif command == "ignore":
                # React with +1
                if comment_id:
                    background_tasks.add_task(github_client.create_reaction, owner, repo, comment_id, "+1")
                return JSONResponse(status_code=200, content={"message": "Ignored finding acknowledged."})

            elif command == "help":
                help_msg = (
                    "### 🤖 ReviewBot Commands\n"
                    "- `/reviewbot review`: Force trigger a fresh automated code review.\n"
                    "- `/reviewbot ignore`: Acknowledge or dismiss a false positive.\n"
                    "- `/reviewbot help`: Display available commands."
                )
                background_tasks.add_task(github_client.post_issue_comment, owner, repo, pull_number, help_msg)
                return JSONResponse(status_code=200, content={"message": "Help comment queued."})

    # Handle inline PR Review Comment commands (e.g. /reviewbot ignore replying to an inline finding)
    elif event_type == "pull_request_review_comment":
        action = payload.get("action")
        comment = payload.get("comment", {})
        comment_body = comment.get("body", "").strip()

        if action == "created" and comment_body.startswith("/reviewbot"):
            cmd_parts = comment_body.split()
            command = cmd_parts[1].lower() if len(cmd_parts) > 1 else "help"

            repository = payload.get("repository", {})
            installation = payload.get("installation", {})
            pr = payload.get("pull_request", {})
            owner = repository.get("owner", {}).get("login")
            repo = repository.get("name")
            pull_number = pr.get("number")
            comment_id = comment.get("id")
            in_reply_to_id = comment.get("in_reply_to_id")
            installation_id = installation.get("id")

            github_client = GitHubClient(installation_id=installation_id)

            if command == "ignore":
                if in_reply_to_id and owner and repo and pull_number:
                    try:
                        orig_comment = await github_client.get_review_comment(
                            owner, repo, in_reply_to_id, installation_id
                        )
                        path = orig_comment.get("path") or comment.get("path", "")
                        raw_line = orig_comment.get("line") or orig_comment.get("original_line") or comment.get("line") or 1
                        line = int(raw_line)
                        orig_body = orig_comment.get("body", "")

                        # Extract finding title (appears as **{title}** on its own line)
                        title_match = re.search(r"^\*\*([^\*\n]+)\*\*", orig_body, re.MULTILINE)
                        if title_match:
                            title = title_match.group(1).strip()
                        else:
                            tokens = re.findall(r"\*\*([^\*\n]+)\*\*", orig_body)
                            title = ""
                            for tok in tokens:
                                if tok.strip().upper() not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NOTE"):
                                    title = tok.strip()
                                    break
                            if not title and tokens:
                                title = tokens[0].strip()

                        f_hash = history_tracker.finding_hash(path, line, title)
                        history_tracker.dismiss_finding(owner, repo, pull_number, f_hash)
                        logger.info(
                            f"Dismissed finding {f_hash} ({title} in {path}:{line}) for PR {owner}/{repo}#{pull_number}"
                        )
                    except Exception as e:
                        logger.error(f"Failed to lookup original review comment {in_reply_to_id}: {e}")

                if comment_id and owner and repo:
                    background_tasks.add_task(
                        github_client.create_review_comment_reaction,
                        owner,
                        repo,
                        comment_id,
                        "+1",
                        installation_id,
                    )
                return JSONResponse(status_code=200, content={"message": "Dismissed finding via review comment."})

            elif command == "help":
                help_msg = (
                    "### 🤖 ReviewBot Commands\n"
                    "- `/reviewbot ignore`: Reply to an inline finding to dismiss it.\n"
                    "- `/reviewbot review`: Force trigger a fresh automated code review.\n"
                    "- `/reviewbot help`: Display available commands."
                )
                if pull_number and owner and repo:
                    background_tasks.add_task(github_client.post_issue_comment, owner, repo, pull_number, help_msg)
                return JSONResponse(status_code=200, content={"message": "Help comment queued."})

    return JSONResponse(status_code=200, content={"message": f"Event '{event_type}' received and ignored."})


@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """
    Modern web dashboard displaying ReviewBot statistics, verdicts, and recent review activity.
    Uses Jinja2 templates and HTML escaping to prevent XSS vulnerabilities.
    """
    stats = history_tracker.get_stats()
    recent = stats.get("recent_reviews", [])

    processed_recent = []
    for r in recent:
        v = str(r.get("verdict", "COMMENT"))
        if v == "APPROVE":
            badge_class = "badge-success"
            badge_text = "APPROVED"
        elif v == "REQUEST_CHANGES":
            badge_class = "badge-danger"
            badge_text = "CHANGES REQUESTED"
        else:
            badge_class = "badge-info"
            badge_text = "COMMENTED"

        findings = r.get("findings_by_severity", {})
        processed_recent.append({
            "pr_key": html.escape(str(r.get("pr_key", ""))),
            "title": html.escape(str(r.get("title", "N/A"))),
            "commit_sha": html.escape(str(r.get("commit_sha", ""))),
            "badge_class": badge_class,
            "badge_text": badge_text,
            "crit": int(findings.get("CRITICAL", 0)),
            "high": int(findings.get("HIGH", 0)),
            "med": int(findings.get("MEDIUM", 0)),
            "timestamp": html.escape(str(r.get("timestamp", ""))),
        })

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "stats": stats,
            "recent_reviews": processed_recent,
        },
    )

