"""
Unit tests for CLI test runner arguments and PR URL parsing.
"""

import pytest
from scripts.test_pr_review import parse_pr_url


def test_parse_pr_url_valid():
    owner, repo, pr_num = parse_pr_url("https://github.com/octocat/Hello-World/pull/42")
    assert owner == "octocat"
    assert repo == "Hello-World"
    assert pr_num == 42


def test_parse_pr_url_with_trailing_slash():
    owner, repo, pr_num = parse_pr_url("https://github.com/my-org/my-project/pull/1337/")
    assert owner == "my-org"
    assert repo == "my-project"
    assert pr_num == 1337


def test_parse_pr_url_invalid():
    with pytest.raises(ValueError, match="Invalid GitHub PR URL"):
        parse_pr_url("https://github.com/octocat/Hello-World/issues/42")

    with pytest.raises(ValueError, match="Invalid GitHub PR URL"):
        parse_pr_url("not_a_url")
