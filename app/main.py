"""
FastAPI application for ReviewBot.
Receives GitHub webhooks, verifies HMAC signatures, runs AI reviews in the background,
handles slash commands, and provides a monitoring dashboard.
"""

import hashlib
import hmac
import logging
from typing import Any, Dict, Optional
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse

from app.config import settings
from app.github_client.client import GitHubClient
from app.github_client.diff_parser import DiffParser
from app.review_agent.agent import ReviewAgent
from app.review_agent.history import history_tracker

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

        # Step 3: Review each file with Claude
        file_results = []
        for pf in parsed_files:
            if pf.is_ignored:
                logger.debug(f"Skipping ignored file {pf.filename} ({pf.ignore_reason})")
                continue

            logger.info(f"Analyzing {pf.filename} with Claude...")
            res = await review_agent.review_file(pf, pr_title=pr_title, pr_body=pr_body)

            # Filter out findings previously dismissed via /reviewbot ignore
            filtered_findings = []
            for finding in res.findings:
                f_hash = history_tracker.finding_hash(finding.file, finding.line, finding.title)
                if not history_tracker.is_finding_dismissed(owner, repo, pull_number, f_hash):
                    filtered_findings.append(finding)
                else:
                    logger.info(f"Filtered out dismissed finding: {finding.title} in {finding.file}")

            res.findings = filtered_findings
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

    return JSONResponse(status_code=200, content={"message": f"Event '{event_type}' received and ignored."})


@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """
    Modern web dashboard displaying ReviewBot statistics, verdicts, and recent review activity.
    """
    stats = history_tracker.get_stats()
    verdicts = stats["verdicts"]
    recent = stats["recent_reviews"]

    rows_html = ""
    for r in recent:
        v = r.get("verdict", "COMMENT")
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
        crit = findings.get("CRITICAL", 0)
        high = findings.get("HIGH", 0)
        med = findings.get("MEDIUM", 0)

        rows_html += f"""
        <tr>
            <td class="pr-name">{r.get('pr_key', '')}</td>
            <td>{r.get('title', 'N/A')}</td>
            <td><code>{r.get('commit_sha', '')}</code></td>
            <td><span class="badge {badge_class}">{badge_text}</span></td>
            <td>
                <span class="pill crit">{crit} crit</span>
                <span class="pill high">{high} high</span>
                <span class="pill med">{med} med</span>
            </td>
            <td class="timestamp">{r.get('timestamp', '')}</td>
        </tr>
        """

    if not rows_html:
        rows_html = '<tr><td colspan="6" style="text-align: center; color: #8b949e; padding: 2rem;">No pull requests reviewed yet. Connect a GitHub repository to begin!</td></tr>'

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReviewBot - AI Code Review Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #0d1117;
            --surface: #161b22;
            --border: #30363d;
            --text-primary: #f0f6fc;
            --text-secondary: #8b949e;
            --accent: #58a6ff;
            --success: #3fb950;
            --danger: #f85149;
            --warning: #d29922;
            --info: #a371f7;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg);
            color: var(--text-primary);
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            min-height: 100vh;
            padding: 2.5rem 1.5rem;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2.5rem;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border);
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 0.8rem;
        }}
        .brand h1 {{
            font-size: 1.75rem;
            font-weight: 700;
            letter-spacing: -0.02em;
            background: linear-gradient(135deg, #58a6ff 0%, #a371f7 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .status-badge {{
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            padding: 0.4rem 0.8rem;
            border-radius: 999px;
            background: rgba(63, 185, 80, 0.15);
            border: 1px solid rgba(63, 185, 80, 0.3);
            color: var(--success);
            font-size: 0.85rem;
            font-weight: 600;
        }}
        .status-dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--success);
            box-shadow: 0 0 8px var(--success);
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 1.25rem;
            margin-bottom: 2.5rem;
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
            transition: transform 0.2s ease, border-color 0.2s ease;
        }}
        .card:hover {{
            border-color: #58a6ff66;
            transform: translateY(-2px);
        }}
        .card-title {{
            font-size: 0.85rem;
            font-weight: 500;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }}
        .card-value {{
            font-size: 2.25rem;
            font-weight: 700;
            letter-spacing: -0.02em;
        }}
        .section-title {{
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        .table-container {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }}
        th {{
            background: rgba(255, 255, 255, 0.02);
            text-align: left;
            padding: 1rem;
            color: var(--text-secondary);
            font-weight: 600;
            border-bottom: 1px solid var(--border);
        }}
        td {{
            padding: 1rem;
            border-bottom: 1px solid var(--border);
            vertical-align: middle;
        }}
        tr:last-child td {{
            border-bottom: none;
        }}
        code {{
            font-family: 'JetBrains Mono', monospace;
            background: rgba(255, 255, 255, 0.06);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-size: 0.85rem;
        }}
        .badge {{
            display: inline-block;
            padding: 0.3rem 0.6rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 0.03em;
        }}
        .badge-success {{ background: rgba(63, 185, 80, 0.15); color: var(--success); border: 1px solid rgba(63, 185, 80, 0.3); }}
        .badge-danger {{ background: rgba(248, 81, 73, 0.15); color: var(--danger); border: 1px solid rgba(248, 81, 73, 0.3); }}
        .badge-info {{ background: rgba(163, 113, 247, 0.15); color: var(--info); border: 1px solid rgba(163, 113, 247, 0.3); }}
        .pill {{
            display: inline-block;
            padding: 0.15rem 0.45rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 500;
            margin-right: 0.25rem;
        }}
        .pill.crit {{ background: rgba(248, 81, 73, 0.2); color: #ff7b72; }}
        .pill.high {{ background: rgba(210, 153, 34, 0.2); color: #e3b341; }}
        .pill.med {{ background: rgba(88, 166, 255, 0.2); color: #79c0ff; }}
        .timestamp {{ color: var(--text-secondary); font-size: 0.8rem; }}
        .pr-name {{ font-weight: 600; color: var(--accent); }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="brand">
                <h1>ReviewBot</h1>
                <span style="color: var(--text-secondary); font-size: 0.9rem;">AI Pull Request Reviewer</span>
            </div>
            <div class="status-badge">
                <span class="status-dot"></span>
                Webhook Receiver Active
            </div>
        </header>

        <div class="grid">
            <div class="card">
                <div class="card-title">PRs Reviewed</div>
                <div class="card-value" style="color: var(--accent);">{stats['total_prs']}</div>
            </div>
            <div class="card">
                <div class="card-title">Total Reviews Executed</div>
                <div class="card-value" style="color: #a371f7;">{stats['total_reviews']}</div>
            </div>
            <div class="card">
                <div class="card-title">Bugs & Issues Caught</div>
                <div class="card-value" style="color: var(--danger);">{stats['bugs_caught']}</div>
            </div>
            <div class="card">
                <div class="card-title">Approvals Granted</div>
                <div class="card-value" style="color: var(--success);">{verdicts.get('APPROVE', 0)}</div>
            </div>
        </div>

        <h2 class="section-title">🕒 Recent Pull Request Reviews</h2>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Repository / PR</th>
                        <th>Title</th>
                        <th>Commit</th>
                        <th>Verdict</th>
                        <th>Findings</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""
    return HTMLResponse(content=html_content)
