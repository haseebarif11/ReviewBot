"""
Tests for SQLite ReviewHistoryTracker storage and concurrent write safety.
"""

import os
import tempfile
import threading
from app.review_agent.history import ReviewHistoryTracker


def test_sqlite_history_tracker_crud():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    try:
        tracker = ReviewHistoryTracker(filepath=db_path)

        # Initial state
        stats = tracker.get_stats()
        assert stats["total_prs"] == 0
        assert stats["total_reviews"] == 0
        assert stats["bugs_caught"] == 0

        # Record review
        tracker.record_review(
            owner="octocat",
            repo="hello-world",
            pull_number=1,
            commit_sha="abcdef123456",
            pr_title="Initial PR",
            verdict="APPROVE",
            total_findings=0,
            findings_by_severity={},
        )

        assert tracker.has_commit_been_reviewed("octocat", "hello-world", 1, "abcdef123456") is True
        assert tracker.has_commit_been_reviewed("octocat", "hello-world", 1, "different_sha") is False

        # Dismiss finding
        f_hash = tracker.finding_hash("main.py", 10, "Test issue")
        assert tracker.is_finding_dismissed("octocat", "hello-world", 1, f_hash) is False
        tracker.dismiss_finding("octocat", "hello-world", 1, f_hash)
        assert tracker.is_finding_dismissed("octocat", "hello-world", 1, f_hash) is True

        # Stats after operations
        stats = tracker.get_stats()
        assert stats["total_prs"] == 1
        assert stats["total_reviews"] == 1
        assert stats["verdicts"]["APPROVE"] == 1
        assert len(stats["recent_reviews"]) == 1
        assert stats["recent_reviews"][0]["commit_sha"] == "abcdef12"

    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_sqlite_history_concurrent_writes():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    try:
        tracker = ReviewHistoryTracker(filepath=db_path)
        num_threads = 10
        writes_per_thread = 10
        errors = []

        def worker(thread_idx: int):
            try:
                for i in range(writes_per_thread):
                    pr_num = (thread_idx * 100) + i
                    tracker.record_review(
                        owner="org",
                        repo="repo",
                        pull_number=pr_num,
                        commit_sha=f"sha_{thread_idx}_{i}",
                        pr_title=f"PR {pr_num}",
                        verdict="COMMENT",
                        total_findings=1,
                        findings_by_severity={"LOW": 1},
                    )
                    f_hash = tracker.finding_hash("file.py", i, f"finding {i}")
                    tracker.dismiss_finding("org", "repo", pr_num, f_hash)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Encountered errors during concurrent writes: {errors}"
        stats = tracker.get_stats()
        assert stats["total_reviews"] == num_threads * writes_per_thread
        assert stats["total_prs"] == num_threads * writes_per_thread
        assert stats["bugs_caught"] == num_threads * writes_per_thread

    finally:
        if os.path.exists(db_path):
            os.remove(db_path)
