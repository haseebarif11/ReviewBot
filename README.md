# ReviewBot 🤖

[![CI](https://github.com/haseebarif11/ReviewBot/actions/workflows/ci.yml/badge.svg)](https://github.com/haseebarif11/ReviewBot/actions/workflows/ci.yml)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11-blue.svg?logo=python)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Automated AI-Powered GitHub Pull Request Code Review Agent built in Python, FastAPI, and Anthropic Claude.**

ReviewBot listens to GitHub Pull Request webhooks, analyzes code diff hunks with senior-engineer-level scrutiny (detecting bugs, security flaws, missing error handling, and performance bottlenecks), and automatically posts structured reviews—including inline comments anchored to specific lines and an executive summary verdict.

---

## 🌟 Features

- **⚡ Instant Webhook Processing**: FastAPI endpoint verifies HMAC-SHA256 signatures (`X-Hub-Signature-256`) and processes reviews asynchronously in background tasks to comply with GitHub's strict 10s webhook timeout.
- **🧠 Anthropic Claude Integration**: Uses Claude 3.5 Sonnet to perform deep semantic code reviews. Focuses on actionable issues:
  - Logic bugs & edge cases
  - Security vulnerabilities (OWASP Top 10, CWE IDs, hardcoded secrets, injection risks, unsafe deserialization)
  - Error handling & resource leaks (unclosed sockets/connections, swallowed exceptions)
  - Code readability & maintainability
  - Missing or incomplete test coverage
- **📍 Precise Diff Line Mapping**: Parses unified diff hunks, verifies commentable line numbers in the new file, and prevents GitHub 422 errors by safely binding comments to hunk boundaries.
- **🛡️ Noise Reduction & Cost Guardrails**: Configurable severity threshold (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), ignored extensions/lockfiles, plus guardrails for `MAX_FILES_PER_REVIEW` and `MAX_DIFF_SIZE_BYTES` to prevent runaway token spend.
- **🔒 Security & Prompt Injection Hardening**: All diffs, titles, and bodies are strictly delimited as `<untrusted_*>` data with explicit system instructions to ignore prompt injections and never obey untrusted instructions in PR content.
- **⚡ Parallel File Reviews**: Reviews PR files concurrently with `asyncio.gather()` bounded by a configurable `asyncio.Semaphore` to optimize throughput without exceeding rate limits.
- **🔁 Resilient API Calls**: Anthropic Claude API calls are wrapped in exponential backoff retry (3 attempts) using `tenacity` for transient rate limits (429) or server overloads (529).
- **💬 Slash Command & Dismissal Support**:
  - `/reviewbot review` - Force trigger a fresh review on a PR
  - `/reviewbot ignore` - Reply to an inline finding to dismiss it so it never reappears on subsequent reviews of that PR
  - `/reviewbot help` - Display available commands
- **🔄 Concurrency-Safe SQLite History Tracker**: Tracks reviewed commits, dismissed findings, and review statistics in SQLite with WAL mode and thread locks.
- **📊 XSS-Protected Real-Time Web Dashboard**: Built-in modern web dashboard at `/dashboard` powered by Jinja2 templates with auto-escaping to safely display review statistics and PR history.
- **🛠️ Standalone CLI Tool**: Review any PR URL directly (`python scripts/test_pr_review.py --pr <url> --dry-run`) without waiting for webhooks.

---

## 🏗️ Architecture

```mermaid
flowchart TD
    GH[GitHub PR Event: opened / synchronize] -->|POST /webhook with HMAC| FA[FastAPI Server]
    FA -->|Verify X-Hub-Signature-256| SEC[HMAC Verifier]
    SEC -->|Fetch Changed Files & Patches| GHC[GitHub Client]
    GHC --> DP[Diff Parser & Line Mapper]
    DP -->|Token-Budgeted File Chunks| RA[Review Agent - Anthropic Claude]
    RA -->|Structured Findings JSON| AGG[Aggregator & Deduplicator]
    AGG -->|Filter by Severity Threshold| REV[Review Formatter]
    REV -->|POST /pulls/{id}/reviews| GHAPI[GitHub Review API]
    GHAPI -->|Inline Comments + Verdict Summary| PR[GitHub Pull Request]
```

---

## 📂 Project Structure

```text
ReviewBot/
├── app/
│   ├── __init__.py
│   ├── config.py                 # Pydantic Settings & environment config
│   ├── main.py                   # FastAPI server, webhook receiver, dashboard UI
│   ├── github_client/
│   │   ├── __init__.py
│   │   ├── client.py             # Dual auth GitHub REST API client (PAT & App)
│   │   └── diff_parser.py        # Unified diff parser & hunk line mapper
│   ├── prompts/
│   │   ├── __init__.py
│   │   ├── system_prompt.py      # Senior reviewer & security auditor system prompt
│   │   └── review_prompt.py      # Line-annotated diff prompt builder
│   └── review_agent/
│       ├── __init__.py
│       ├── agent.py              # LLM review orchestration, JSON parser & aggregator
│       ├── history.py            # Deduplication tracker & dashboard metrics
│       └── schemas.py            # Pydantic models for findings, severities & reviews
├── fixtures/
│   ├── clean_diff.diff           # Sample clean diff fixture
│   └── vulnerable_diff.diff      # Sample diff with SQLi, secrets, and leaks
├── scripts/
│   └── test_pr_review.py         # Standalone CLI tool to review any PR URL
├── tests/
│   ├── test_cli.py               # CLI runner & URL parser tests
│   ├── test_diff_parser.py       # Diff parser & line mapping tests
│   ├── test_github_client.py     # GitHub REST client unit tests
│   ├── test_review_agent.py      # Claude response parser & aggregation tests
│   └── test_webhook_flow.py      # HMAC signature & webhook flow integration tests
├── .env.example                  # Environment configuration template
├── .gitignore
├── requirements.txt
└── README.md
```

---

## 🚀 Quickstart Guide

### 1. Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/haseebarif11/ReviewBot.git
cd ReviewBot

# Optional: Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

### 2. Configure Environment Variables

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Configure the following variables in `.env`:

| Variable | Description |
| :--- | :--- |
| `ANTHROPIC_API_KEY` | Your Anthropic API key (`sk-ant-...`) |
| `ANTHROPIC_MODEL` | Claude model (default: `claude-3-5-sonnet-latest`) |
| `MAX_TOKENS_PER_FILE` | Max tokens budget in prompt per file (default: `4000`) |
| `MAX_RESPONSE_TOKENS` | Max tokens for Claude review response (default: `4096`) |
| `GITHUB_WEBHOOK_SECRET` | Secret token configured in GitHub webhook settings |
| `GITHUB_TOKEN` | GitHub Personal Access Token (with `repo` / `pull_requests` write permissions) |
| `SEVERITY_THRESHOLD` | Minimum severity for inline comments (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) |
| `AUTO_APPROVE_CLEAN_PR` | Automatically submit `APPROVE` verdict if no issues found (`true`/`false`) |
| `MAX_FILES_PER_REVIEW` | Max changed files allowed in a single PR review before guardrail triggers (default: `30`) |
| `MAX_DIFF_SIZE_BYTES` | Max cumulative diff size in bytes before guardrail triggers (default: `500000`) |
| `REVIEW_CONCURRENCY_LIMIT` | Max concurrent file reviews dispatched to Claude via asyncio.gather (default: `5`) |

### 🗄️ Storage Migration Note (JSON to SQLite)

ReviewBot has migrated its deduplication, dismissal, and metrics persistence from a flat file (`review_history.json`) to a high-concurrency **SQLite database** (`review_history.db`).
- **Concurrent Safety**: Employs SQLite WAL (Write-Ahead Logging) mode alongside re-entrant threading locks to guarantee safe concurrent writes when multiple PR reviews run concurrently.
- **Automatic Migration**: Any existing `review_history.json` file is automatically detected and migrated into SQLite on first startup without data loss.

#### GitHub App Auth (Alternative for Multi-Repo Production):
```env
GITHUB_APP_ID=123456
GITHUB_APP_PRIVATE_KEY_PATH=/path/to/private-key.pem
GITHUB_APP_INSTALLATION_ID=7891011
```

---

## 🧪 Testing with the Standalone CLI

You can test ReviewBot immediately on any real GitHub PR or local diff file without setting up webhooks:

### Review a GitHub PR (Dry Run):
```bash
python scripts/test_pr_review.py --pr https://github.com/owner/repo/pull/42 --dry-run
```

### Review and Post Directly to GitHub:
```bash
python scripts/test_pr_review.py --pr https://github.com/owner/repo/pull/42
```

### Review a Local Diff File:
```bash
python scripts/test_pr_review.py --diff-file fixtures/vulnerable_diff.diff --dry-run
```

---

## 🌐 Running the Webhook Server

### Option A: Local Development (Uvicorn)
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Option B: Docker Container
```bash
# Build image
docker build -t reviewbot .

# Run container
docker run -d --name reviewbot -p 8000:8000 --env-file .env reviewbot
```

### Option C: Docker Compose
```bash
docker compose up -d
```

### Available Endpoints:
- **Health Check**: `GET http://localhost:8000/health`
- **Metrics & Stats**: `GET http://localhost:8000/api/stats`
- **Dashboard UI**: `GET http://localhost:8000/dashboard`
- **Webhook Receiver**: `POST http://localhost:8000/webhook`

### Expose with ngrok (for local testing):
```bash
ngrok http 8000
```
Copy the forwarding URL (e.g., `https://xxxx.ngrok-free.app`) and configure your GitHub repo webhook:
- **Payload URL**: `https://xxxx.ngrok-free.app/webhook`
- **Content type**: `application/json`
- **Secret**: Matching `GITHUB_WEBHOOK_SECRET` in your `.env`
- **Events**: Select **Pull requests** and **Issue comments**

---

## 🧪 Running the Test Suite

Run the automated test suite with pytest:

```bash
python -m pytest -p no:langsmith -v tests/
```

Test coverage includes:
- HMAC SHA-256 webhook signature validation & tamper detection
- Unified diff parsing, multi-hunk parsing, and boundary line mapping
- Severity filtering and verdict calculation (Approve, Request Changes, Comment)
- Mocked GitHub REST API review submission
- CLI URL parsing and options handling

---

## 📄 License

MIT License. Crafted for automated developer velocity.