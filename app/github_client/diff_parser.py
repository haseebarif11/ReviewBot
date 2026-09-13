"""
Unified diff parser for GitHub Pull Requests.
Parses diff patches, extracts hunks, tracks valid commentable line numbers,
and enforces filtering rules (ignoring binary/lockfiles).
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class HunkLine:
    """Represents a single line within a diff hunk."""
    line_type: str  # 'addition', 'deletion', 'context'
    content: str
    old_line_number: Optional[int]
    new_line_number: Optional[int]
    diff_position: int  # 1-indexed line offset within the patch (legacy GitHub position)


@dataclass
class DiffHunk:
    """Represents a @@ -old,len +new,len @@ diff block."""
    header: str
    old_start: int
    old_length: int
    new_start: int
    new_length: int
    lines: List[HunkLine] = field(default_factory=list)

    @property
    def new_line_range(self) -> Tuple[int, int]:
        """Returns the (min_new_line, max_new_line) covered by this hunk."""
        valid_lines = [l.new_line_number for l in self.lines if l.new_line_number is not None]
        if not valid_lines:
            return (self.new_start, self.new_start + max(self.new_length - 1, 0))
        return (min(valid_lines), max(valid_lines))


@dataclass
class ParsedFileDiff:
    """Represents the parsed diff and metadata for a single file in a PR."""
    filename: str
    status: str  # 'added', 'modified', 'deleted', 'renamed'
    patch: str
    hunks: List[DiffHunk] = field(default_factory=list)
    valid_new_lines: Set[int] = field(default_factory=set)
    valid_old_lines: Set[int] = field(default_factory=set)
    additions: int = 0
    deletions: int = 0
    is_ignored: bool = False
    ignore_reason: Optional[str] = None

    def is_line_commentable(self, line_number: int, side: str = "RIGHT") -> bool:
        """
        Check if a given line number can be attached as an inline comment on GitHub.
        GitHub API throws a 422 error if an inline review comment is placed on a line
        not contained inside one of the diff hunks.
        """
        if side.upper() == "RIGHT":
            return line_number in self.valid_new_lines
        return line_number in self.valid_old_lines

    def find_nearest_commentable_line(self, target_line: int, side: str = "RIGHT") -> Optional[int]:
        """
        If target_line is valid, return it. Otherwise, find the closest line in the hunks.
        Returns None if there are no commentable lines in the diff.
        """
        valid = self.valid_new_lines if side.upper() == "RIGHT" else self.valid_old_lines
        if not valid:
            return None
        if target_line in valid:
            return target_line
        # Find nearest line by absolute difference
        return min(valid, key=lambda x: abs(x - target_line))


class DiffParser:
    """Parser for PR diffs returned by GitHub REST API."""

    HUNK_HEADER_REGEX = re.compile(
        r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@(?:[ ]?(.*))?$"
    )

    def __init__(self, ignore_extensions: Optional[List[str]] = None, ignore_files: Optional[List[str]] = None):
        if ignore_extensions is None:
            from app.config import settings
            ignore_extensions = settings.IGNORE_EXTENSIONS
        if ignore_files is None:
            from app.config import settings
            ignore_files = settings.IGNORE_FILES

        self.ignore_extensions = [ext.lower() for ext in ignore_extensions]
        self.ignore_files = [f.lower() for f in ignore_files]

    def should_ignore(self, filename: str, status: str = "modified", patch: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Determines whether a file should be skipped from AI review.
        """
        lower_name = filename.lower()
        basename = lower_name.split("/")[-1]

        if status == "deleted":
            return True, "File was deleted in this PR"

        if not patch or not patch.strip():
            return True, "No diff patch available (e.g. binary or unchanged file)"

        for ignored_f in self.ignore_files:
            if basename == ignored_f or lower_name.endswith("/" + ignored_f):
                return True, f"Matched ignored file pattern: {ignored_f}"

        for ext in self.ignore_extensions:
            if lower_name.endswith(ext):
                return True, f"Matched ignored extension: {ext}"

        return False, None

    def parse_patch(self, filename: str, status: str, patch: str, additions: int = 0, deletions: int = 0) -> ParsedFileDiff:
        """
        Parses a git patch string into a ParsedFileDiff object.
        """
        is_ignored, reason = self.should_ignore(filename, status, patch)
        parsed = ParsedFileDiff(
            filename=filename,
            status=status,
            patch=patch or "",
            additions=additions,
            deletions=deletions,
            is_ignored=is_ignored,
            ignore_reason=reason
        )

        if is_ignored or not patch:
            return parsed

        lines = patch.splitlines()
        current_hunk: Optional[DiffHunk] = None
        current_old_line = 0
        current_new_line = 0
        diff_position = 0  # 1-indexed relative to patch

        for raw_line in lines:
            diff_position += 1
            header_match = self.HUNK_HEADER_REGEX.match(raw_line)

            if header_match:
                old_start = int(header_match.group(1))
                old_length = int(header_match.group(2)) if header_match.group(2) else 1
                new_start = int(header_match.group(3))
                new_length = int(header_match.group(4)) if header_match.group(4) else 1

                current_hunk = DiffHunk(
                    header=raw_line,
                    old_start=old_start,
                    old_length=old_length,
                    new_start=new_start,
                    new_length=new_length
                )
                parsed.hunks.append(current_hunk)
                current_old_line = old_start
                current_new_line = new_start
                continue

            if current_hunk is None:
                # Header metadata before first hunk
                continue

            if raw_line.startswith("+"):
                # Addition line: present in new file
                hunk_line = HunkLine(
                    line_type="addition",
                    content=raw_line[1:],
                    old_line_number=None,
                    new_line_number=current_new_line,
                    diff_position=diff_position
                )
                current_hunk.lines.append(hunk_line)
                parsed.valid_new_lines.add(current_new_line)
                current_new_line += 1

            elif raw_line.startswith("-"):
                # Deletion line: present in old file
                hunk_line = HunkLine(
                    line_type="deletion",
                    content=raw_line[1:],
                    old_line_number=current_old_line,
                    new_line_number=None,
                    diff_position=diff_position
                )
                current_hunk.lines.append(hunk_line)
                parsed.valid_old_lines.add(current_old_line)
                current_old_line += 1

            elif raw_line.startswith(" ") or raw_line == "":
                # Context line: present in both old and new files
                content = raw_line[1:] if raw_line.startswith(" ") else ""
                hunk_line = HunkLine(
                    line_type="context",
                    content=content,
                    old_line_number=current_old_line,
                    new_line_number=current_new_line,
                    diff_position=diff_position
                )
                current_hunk.lines.append(hunk_line)
                parsed.valid_old_lines.add(current_old_line)
                parsed.valid_new_lines.add(current_new_line)
                current_old_line += 1
                current_new_line += 1

            elif raw_line.startswith("\\"):
                # "\ No newline at end of file"
                continue

        return parsed

    def parse_github_files(self, files_payload: List[dict]) -> List[ParsedFileDiff]:
        """
        Parses a list of file dicts from GitHub's GET /pulls/{number}/files API.
        """
        results = []
        for file_info in files_payload:
            filename = file_info.get("filename", "")
            status = file_info.get("status", "modified")
            patch = file_info.get("patch", "")
            additions = file_info.get("additions", 0)
            deletions = file_info.get("deletions", 0)

            parsed = self.parse_patch(
                filename=filename,
                status=status,
                patch=patch,
                additions=additions,
                deletions=deletions
            )
            results.append(parsed)
        return results
