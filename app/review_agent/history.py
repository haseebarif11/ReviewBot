"""
Review history tracking to avoid re-flagging duplicate issues across PR updates,
support /reviewbot ignore dismissals, and provide aggregated dashboard statistics.
"""

import hashlib
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger("reviewbot.history")

HISTORY_FILE = "review_history.json"


class ReviewHistoryTracker:
    """
    Tracks reviewed PR commits, dismissed findings, and overall bot review statistics.
    Persists data locally in JSON format.
    """

    def __init__(self, filepath: str = HISTORY_FILE):
        self.filepath = filepath
        self.data: Dict[str, Any] = {
            "prs": {},          # repo#pr_num -> PR history record
            "total_prs": 0,
            "total_reviews": 0,
            "bugs_caught": 0,
            "verdicts": {"APPROVE": 0, "REQUEST_CHANGES": 0, "COMMENT": 0},
            "recent_reviews": [],
        }
        self._load()

    def _load(self):
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    self.data.update(loaded)
            except Exception as e:
                logger.warning(f"Could not load review history from {self.filepath}: {e}")

    def _save(self):
        try:
            with open(self.filepath, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save review history to {self.filepath}: {e}")

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
        pr_record = self.data["prs"].get(key)
        if not pr_record:
            return False
        return pr_record.get("last_reviewed_commit") == commit_sha

    def is_finding_dismissed(self, owner: str, repo: str, pull_number: int, finding_hash: str) -> bool:
        """Checks if a finding has been dismissed via /reviewbot ignore."""
        key = self.pr_key(owner, repo, pull_number)
        pr_record = self.data["prs"].get(key, {})
        return finding_hash in pr_record.get("dismissed_findings", [])

    def dismiss_finding(self, owner: str, repo: str, pull_number: int, finding_hash: str):
        """Marks a finding as ignored for this PR."""
        key = self.pr_key(owner, repo, pull_number)
        if key not in self.data["prs"]:
            self.data["prs"][key] = {
                "last_reviewed_commit": None,
                "dismissed_findings": [],
                "review_count": 0,
            }
        dismissed = self.data["prs"][key].setdefault("dismissed_findings", [])
        if finding_hash not in dismissed:
            dismissed.append(finding_hash)
            self._save()

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
        is_new_pr = key not in self.data["prs"]

        pr_record = self.data["prs"].setdefault(key, {
            "dismissed_findings": [],
            "review_count": 0,
        })
        pr_record["last_reviewed_commit"] = commit_sha
        pr_record["review_count"] = pr_record.get("review_count", 0) + 1
        pr_record["title"] = pr_title
        pr_record["last_verdict"] = verdict
        pr_record["last_review_time"] = datetime.utcnow().isoformat() + "Z"

        if is_new_pr:
            self.data["total_prs"] += 1
        self.data["total_reviews"] += 1
        self.data["bugs_caught"] += total_findings

        # Update verdict tally
        norm_verdict = verdict.upper()
        if norm_verdict in self.data["verdicts"]:
            self.data["verdicts"][norm_verdict] += 1

        # Keep recent 50 reviews for dashboard
        recent_entry = {
            "pr_key": key,
            "title": pr_title,
            "commit_sha": commit_sha[:8],
            "verdict": verdict,
            "total_findings": total_findings,
            "findings_by_severity": findings_by_severity,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
        self.data["recent_reviews"].insert(0, recent_entry)
        self.data["recent_reviews"] = self.data["recent_reviews"][:50]

        self._save()

    def get_stats(self) -> Dict[str, Any]:
        """Returns aggregated review stats."""
        return {
            "total_prs": self.data.get("total_prs", 0),
            "total_reviews": self.data.get("total_reviews", 0),
            "bugs_caught": self.data.get("bugs_caught", 0),
            "verdicts": self.data.get("verdicts", {}),
            "recent_reviews": self.data.get("recent_reviews", []),
        }


# Global history singleton
history_tracker = ReviewHistoryTracker()
