"""
Review history tracking to avoid re-flagging duplicate issues across PR updates,
support /reviewbot ignore dismissals, and provide aggregated dashboard statistics.
Backed by SQLite for thread safety and concurrent write resilience.
"""

import hashlib
import json
import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger("reviewbot.history")

HISTORY_DB_FILE = "review_history.db"
LEGACY_JSON_FILE = "review_history.json"


class ReviewHistoryTracker:
    """
    Tracks reviewed PR commits, dismissed findings, and overall bot review statistics.
    Persists data in SQLite with WAL mode and threading synchronization for concurrent safety.
    """

    def __init__(self, filepath: str = HISTORY_DB_FILE):
        # Support specifying .db or falling back from .json
        if filepath.endswith(".json"):
            self.filepath = filepath.replace(".json", ".db")
            self.legacy_json = filepath
        else:
            self.filepath = filepath
            self.legacy_json = LEGACY_JSON_FILE

        self._lock = threading.RLock()
        self._init_db()
        self._migrate_legacy_json_if_needed()

    @contextmanager
    def _connection(self):
        conn = sqlite3.connect(self.filepath, timeout=30.0, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self):
        """Initializes tables and indexes."""
        with self._lock:
            with self._connection() as conn:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS prs (
                        pr_key TEXT PRIMARY KEY,
                        last_reviewed_commit TEXT,
                        review_count INTEGER DEFAULT 0,
                        title TEXT,
                        last_verdict TEXT,
                        last_review_time TEXT
                    );

                    CREATE TABLE IF NOT EXISTS dismissed_findings (
                        pr_key TEXT,
                        finding_hash TEXT,
                        dismissed_at TEXT,
                        PRIMARY KEY (pr_key, finding_hash)
                    );

                    CREATE TABLE IF NOT EXISTS reviews (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        pr_key TEXT,
                        title TEXT,
                        commit_sha TEXT,
                        verdict TEXT,
                        total_findings INTEGER,
                        findings_by_severity TEXT,
                        timestamp TEXT
                    );

                    CREATE INDEX IF NOT EXISTS idx_reviews_pr_key ON reviews(pr_key);
                    CREATE INDEX IF NOT EXISTS idx_dismissed_pr_key ON dismissed_findings(pr_key);
                    """
                )

    def _migrate_legacy_json_if_needed(self):
        """Migrates historical records from legacy review_history.json if present."""
        if not os.path.exists(self.legacy_json):
            return

        with self._lock:
            try:
                with self._connection() as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT COUNT(*) FROM prs")
                    if cur.fetchone()[0] > 0:
                        # Already populated
                        return

                    with open(self.legacy_json, "r", encoding="utf-8") as f:
                        data = json.load(f)

                    prs = data.get("prs", {})
                    for key, pr_rec in prs.items():
                        conn.execute(
                            """
                            INSERT OR IGNORE INTO prs (pr_key, last_reviewed_commit, review_count, title, last_verdict, last_review_time)
                            VALUES (?, ?, ?, ?, ?, ?)
                            """,
                            (
                                key,
                                pr_rec.get("last_reviewed_commit"),
                                pr_rec.get("review_count", 0),
                                pr_rec.get("title", ""),
                                pr_rec.get("last_verdict", ""),
                                pr_rec.get("last_review_time", ""),
                            ),
                        )
                        for f_hash in pr_rec.get("dismissed_findings", []):
                            conn.execute(
                                """
                                INSERT OR IGNORE INTO dismissed_findings (pr_key, finding_hash, dismissed_at)
                                VALUES (?, ?, ?)
                                """,
                                (key, f_hash, datetime.utcnow().isoformat() + "Z"),
                            )

                    for rev in data.get("recent_reviews", []):
                        conn.execute(
                            """
                            INSERT INTO reviews (pr_key, title, commit_sha, verdict, total_findings, findings_by_severity, timestamp)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                rev.get("pr_key", ""),
                                rev.get("title", ""),
                                rev.get("commit_sha", ""),
                                rev.get("verdict", ""),
                                rev.get("total_findings", 0),
                                json.dumps(rev.get("findings_by_severity", {})),
                                rev.get("timestamp", ""),
                            ),
                        )
                    logger.info(f"Successfully migrated legacy history from {self.legacy_json} into SQLite.")
            except Exception as e:
                logger.warning(f"Could not migrate legacy JSON history from {self.legacy_json}: {e}")

    @staticmethod
    def pr_key(owner: str, repo: str, pull_number: int) -> str:
        return f"{owner}/{repo}#{pull_number}".lower()

    @staticmethod
    def finding_hash(file: str, line: int, title: str) -> str:
        """Generates a stable unique hash for a finding."""
        raw = f"{file}:{line}:{title.strip().lower()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def has_commit_been_reviewed(self, owner: str, repo: str, pull_number: int, commit_sha: str) -> bool:
        """Checks if this specific commit has already been analyzed."""
        key = self.pr_key(owner, repo, pull_number)
        with self._lock:
            with self._connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT last_reviewed_commit FROM prs WHERE pr_key = ?", (key,))
                row = cur.fetchone()
                if not row or not row[0]:
                    return False
                return row[0] == commit_sha

    def is_finding_dismissed(self, owner: str, repo: str, pull_number: int, finding_hash: str) -> bool:
        """Checks if a finding has been dismissed via /reviewbot ignore."""
        key = self.pr_key(owner, repo, pull_number)
        with self._lock:
            with self._connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT 1 FROM dismissed_findings WHERE pr_key = ? AND finding_hash = ?",
                    (key, finding_hash),
                )
                return cur.fetchone() is not None

    def dismiss_finding(self, owner: str, repo: str, pull_number: int, finding_hash: str):
        """Marks a finding as ignored for this PR."""
        key = self.pr_key(owner, repo, pull_number)
        now_iso = datetime.utcnow().isoformat() + "Z"
        with self._lock:
            with self._connection() as conn:
                conn.execute(
                    """
                    INSERT INTO prs (pr_key, last_reviewed_commit, review_count, title, last_verdict, last_review_time)
                    VALUES (?, NULL, 0, '', '', ?)
                    ON CONFLICT(pr_key) DO NOTHING
                    """,
                    (key, now_iso),
                )
                conn.execute(
                    """
                    INSERT INTO dismissed_findings (pr_key, finding_hash, dismissed_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(pr_key, finding_hash) DO NOTHING
                    """,
                    (key, finding_hash, now_iso),
                )

    def record_review(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        commit_sha: str,
        pr_title: str,
        verdict: str,
        total_findings: int,
        findings_by_severity: Dict[str, int],
    ):
        """Records completed review metrics for reporting and deduplication."""
        key = self.pr_key(owner, repo, pull_number)
        now_iso = datetime.utcnow().isoformat() + "Z"
        now_formatted = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        with self._lock:
            with self._connection() as conn:
                conn.execute(
                    """
                    INSERT INTO prs (pr_key, last_reviewed_commit, review_count, title, last_verdict, last_review_time)
                    VALUES (?, ?, 1, ?, ?, ?)
                    ON CONFLICT(pr_key) DO UPDATE SET
                        last_reviewed_commit=excluded.last_reviewed_commit,
                        review_count=prs.review_count + 1,
                        title=excluded.title,
                        last_verdict=excluded.last_verdict,
                        last_review_time=excluded.last_review_time
                    """,
                    (key, commit_sha, pr_title, verdict, now_iso),
                )
                conn.execute(
                    """
                    INSERT INTO reviews (pr_key, title, commit_sha, verdict, total_findings, findings_by_severity, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        key,
                        pr_title,
                        commit_sha,
                        verdict,
                        total_findings,
                        json.dumps(findings_by_severity),
                        now_formatted,
                    ),
                )

    def get_stats(self) -> Dict[str, Any]:
        """Returns aggregated review stats."""
        with self._lock:
            with self._connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM prs")
                total_prs = cur.fetchone()[0]

                cur.execute("SELECT COUNT(*), COALESCE(SUM(total_findings), 0) FROM reviews")
                row = cur.fetchone()
                total_reviews = row[0] if row else 0
                bugs_caught = row[1] if row else 0

                verdicts = {"APPROVE": 0, "REQUEST_CHANGES": 0, "COMMENT": 0}
                cur.execute("SELECT UPPER(verdict), COUNT(*) FROM reviews GROUP BY UPPER(verdict)")
                for v_name, count in cur.fetchall():
                    if v_name in verdicts:
                        verdicts[v_name] = count

                cur.execute(
                    """
                    SELECT pr_key, title, commit_sha, verdict, total_findings, findings_by_severity, timestamp
                    FROM reviews ORDER BY id DESC LIMIT 50
                    """
                )
                recent_reviews = []
                for r in cur.fetchall():
                    try:
                        f_by_sev = json.loads(r[5]) if r[5] else {}
                    except Exception:
                        f_by_sev = {}

                    recent_reviews.append({
                        "pr_key": r[0],
                        "title": r[1],
                        "commit_sha": r[2][:8] if r[2] else "",
                        "verdict": r[3],
                        "total_findings": r[4],
                        "findings_by_severity": f_by_sev,
                        "timestamp": r[6],
                    })

                return {
                    "total_prs": total_prs,
                    "total_reviews": total_reviews,
                    "bugs_caught": bugs_caught,
                    "verdicts": verdicts,
                    "recent_reviews": recent_reviews,
                }


# Global history singleton
history_tracker = ReviewHistoryTracker()
