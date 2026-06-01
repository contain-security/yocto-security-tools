# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for shared.url_parser module."""
from unittest.mock import Mock, patch

import pytest

from shared.url_parser import extract_commit_hash, fetch_github_pr_commits, parse_fix_url


class TestExtractCommitHash:
    def test_github_commit_url(self):
        url = "https://github.com/openssh/openssh-portable/commit/76685c9b09a66435cd2ad8373246adf1c53976d3"
        assert extract_commit_hash(url) == "76685c9b09a66435cd2ad8373246adf1c53976d3"

    def test_gitlab_commit_url(self):
        url = "https://gitlab.com/project/repo/-/commit/abc1234def5678"
        assert extract_commit_hash(url) == "abc1234def5678"

    def test_short_hash(self):
        url = "https://github.com/owner/repo/commit/abc1234"
        assert extract_commit_hash(url) == "abc1234"

    def test_ignored_bugzilla(self):
        url = "https://bugzilla.redhat.com/show_bug.cgi?id=1234567"
        assert extract_commit_hash(url) is None

    def test_ignored_issues(self):
        url = "https://github.com/owner/repo/issues/1234567"
        assert extract_commit_hash(url) is None

    def test_pure_numeric_ignored(self):
        url = "https://example.com/path/1234567"
        assert extract_commit_hash(url) is None

    def test_no_hash(self):
        url = "https://example.com/no-hash-here"
        assert extract_commit_hash(url) is None


class TestFetchGithubPrCommits:
    @patch('requests.get')
    def test_success(self, mock_get):
        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: [{'sha': 'aaa'}, {'sha': 'bbb'}])
        mock_get.return_value.raise_for_status = Mock()

        result = fetch_github_pr_commits(
            "https://github.com/owner/repo/pull/42", token="fake")
        assert result == ['aaa', 'bbb']

    def test_non_pr_url(self):
        result = fetch_github_pr_commits(
            "https://github.com/owner/repo/commit/abc123", token="fake")
        assert result == []

    @patch.dict('os.environ', {}, clear=True)
    def test_no_token(self):
        result = fetch_github_pr_commits(
            "https://github.com/owner/repo/pull/42")
        assert result == []


class TestParseFixUrl:
    def test_commit_url(self):
        url = "https://github.com/openssh/openssh-portable/commit/76685c9b09a66"
        result = parse_fix_url(url)
        assert result['hashes'] == ['76685c9b09a66']
        assert result['hash_details'] == [
            {'hash': '76685c9b09a66', 'url': url, 'source': 'cli'}]
        assert result['series'] == []

    @patch('shared.url_parser.fetch_github_pr_commits')
    def test_pr_url(self, mock_fetch):
        mock_fetch.return_value = ['aaa', 'bbb', 'ccc']
        url = "https://github.com/owner/repo/pull/99"
        result = parse_fix_url(url)
        assert result['hashes'] == ['aaa', 'bbb', 'ccc']
        assert result['series'] == [
            {'pull_url': url, 'commits': ['aaa', 'bbb', 'ccc']}]
        assert len(result['hash_details']) == 3

    @patch('shared.url_parser.fetch_github_pr_commits')
    def test_pr_url_no_commits_raises(self, mock_fetch):
        mock_fetch.return_value = []
        with pytest.raises(ValueError, match="Could not extract commits"):
            parse_fix_url("https://github.com/owner/repo/pull/99")

    def test_invalid_url_raises(self):
        with pytest.raises(ValueError, match="Could not extract commit hash"):
            parse_fix_url("https://example.com/no-hash-here")
