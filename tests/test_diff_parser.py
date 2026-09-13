"""
Unit tests for unified diff parser and hunk line mapping.
"""

import pytest
from app.github_client.diff_parser import DiffParser, ParsedFileDiff


SAMPLE_PATCH_1 = """@@ -10,6 +10,8 @@ def process_user(user_id):
     user = get_user(user_id)
     if not user:
         return None
+    # Log access for security audit
+    audit_log(f"User {user_id} accessed")
     return user.to_dict()
"""

SAMPLE_MULTI_HUNK_PATCH = """@@ -1,5 +1,6 @@
 import os
 import sys
+import hashlib
 
 def main():
     pass
@@ -20,6 +21,8 @@ def authenticate(password):
-    return password == "admin123"
+    # Secure comparison
+    return hashlib.sha256(password.encode()).hexdigest() == STORED_HASH
"""


def test_parse_single_hunk():
    parser = DiffParser()
    parsed = parser.parse_patch(
        filename="app/users.py",
        status="modified",
        patch=SAMPLE_PATCH_1,
        additions=2,
        deletions=0
    )

    assert not parsed.is_ignored
    assert len(parsed.hunks) == 1
    hunk = parsed.hunks[0]
    assert hunk.old_start == 10
    assert hunk.old_length == 6
    assert hunk.new_start == 10
    assert hunk.new_length == 8

    # In new file:
    # 10: "    user = get_user(user_id)" (context)
    # 11: "    if not user:" (context)
    # 12: "        return None" (context)
    # 13: "    # Log access for security audit" (addition)
    # 14: "    audit_log(f"User {user_id} accessed")" (addition)
    # 15: "    return user.to_dict()" (context)
    assert 10 in parsed.valid_new_lines
    assert 13 in parsed.valid_new_lines
    assert 14 in parsed.valid_new_lines
    assert 15 in parsed.valid_new_lines
    assert 9 not in parsed.valid_new_lines
    assert 16 not in parsed.valid_new_lines


def test_multi_hunk_and_line_commentable():
    parser = DiffParser()
    parsed = parser.parse_patch(
        filename="app/auth.py",
        status="modified",
        patch=SAMPLE_MULTI_HUNK_PATCH,
        additions=3,
        deletions=1
    )

    assert len(parsed.hunks) == 2

    # In Hunk 1: added line 3
    assert parsed.is_line_commentable(3, side="RIGHT")
    # In Hunk 2: added lines 21, 22
    assert parsed.is_line_commentable(21, side="RIGHT")
    assert parsed.is_line_commentable(22, side="RIGHT")

    # Lines between hunk 1 and hunk 2 (e.g. line 10) are NOT commentable in diff
    assert not parsed.is_line_commentable(10, side="RIGHT")

    # Nearest commentable line
    nearest = parsed.find_nearest_commentable_line(10, side="RIGHT")
    assert nearest in (6, 21)


def test_ignored_files_and_extensions():
    parser = DiffParser(
        ignore_extensions=[".lock", ".min.js", ".png"],
        ignore_files=["package-lock.json", "poetry.lock"]
    )

    # Ignored extensions
    parsed_js = parser.parse_patch("static/bundle.min.js", "modified", SAMPLE_PATCH_1)
    assert parsed_js.is_ignored
    assert "extension" in parsed_js.ignore_reason.lower()

    # Ignored exact files
    parsed_lock = parser.parse_patch("frontend/package-lock.json", "modified", SAMPLE_PATCH_1)
    assert parsed_lock.is_ignored

    # Deleted files
    parsed_deleted = parser.parse_patch("old_script.py", "deleted", SAMPLE_PATCH_1)
    assert parsed_deleted.is_ignored
    assert "deleted" in parsed_deleted.ignore_reason.lower()

    # Empty patch
    parsed_empty = parser.parse_patch("binary.dat", "modified", "")
    assert parsed_empty.is_ignored


def test_parse_github_files_list():
    parser = DiffParser()
    payload = [
        {
            "filename": "src/main.py",
            "status": "modified",
            "patch": SAMPLE_PATCH_1,
            "additions": 2,
            "deletions": 0
        },
        {
            "filename": "yarn.lock",
            "status": "modified",
            "patch": "@@ -1,3 +1,3 @@",
            "additions": 1,
            "deletions": 1
        }
    ]

    results = parser.parse_github_files(payload)
    assert len(results) == 2
    assert not results[0].is_ignored
    assert results[1].is_ignored
