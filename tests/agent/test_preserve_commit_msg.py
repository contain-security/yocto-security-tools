# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for preserving upstream commit message during backport resolution.

Verifies that amend_commit_with_summary restores the original upstream
commit message when the AI replaced it with backport notes.
"""
from pathlib import Path
from unittest.mock import patch

from cve_agent.review import amend_commit_with_summary

UPSTREAM_SHA = "97acf3dfda80c91c3a8c9f2372546301d4a1a7a8"
UPSTREAM_SUBJECT = (
    "transport.c: Additional boundary checks for packet length (#2052)"
)
UPSTREAM_BODY = (
    "Add upper-bound check on packet_length against\n"
    "LIBSSH2_PACKET_MAXPAYLOAD to prevent OOB write.\n"
    "\n"
    "Closes #2050"
)


class TestPreserveOriginalCommitMessage:
    """Bug: AI replaces original upstream message with backport notes."""

    @patch("subprocess.run")
    @patch("cve_agent.review.run_git_stdout")
    def test_restores_original_when_ai_replaced_message(
        self, mock_git, mock_run
    ):
        """When the AI wrote 'Backport Resolution:' as the message body
        (replacing the original), amend_commit_with_summary should restore
        the original upstream subject+body and append backport notes after."""
        # Simulate AI having replaced the message entirely
        ai_replaced_msg = (
            "transport.c: Additional boundary checks for packet length (#2052)\n"
            "\n"
            "Backport Resolution: Add additional bounds checking on packet\n"
            "length to prevent OOB write.\n"
            "\n"
            "Conflicts Resolved:\n"
            "\n"
            "src/transport.c (1 conflict):\n"
            "- Upstream uses ssh2_ntohu32(); stable uses _libssh2_ntohu32().\n"
            "\n"
            "Assisted-by: kiro:claude-sonnet-4.6\n"
        )

        def git_side_effect(args, cwd):
            if '--format=%B' in args:
                return ai_replaced_msg
            if '--format=%s' in args and UPSTREAM_SHA in args:
                return UPSTREAM_SUBJECT
            if '--format=%b' in args and UPSTREAM_SHA in args:
                return UPSTREAM_BODY
            return ""

        mock_git.side_effect = git_side_effect
        mock_run.return_value = type("R", (), {"returncode": 0})()

        amend_commit_with_summary(
            Path("/ws"), UPSTREAM_SHA, "Changes from upstream commit 97acf3dfda80:\n  - src/transport.c: adapted from upstream"
        )

        mock_run.assert_called_once()
        final_msg = mock_run.call_args[0][0][-1]

        # Original subject must be present
        assert UPSTREAM_SUBJECT in final_msg
        # Original body must be restored
        assert "LIBSSH2_PACKET_MAXPAYLOAD" in final_msg
        assert "Closes #2050" in final_msg
        # Kiro notes must still be present
        assert "Backport Resolution:" in final_msg
        assert "Conflicts Resolved:" in final_msg
        # Summary must be appended
        assert "Changes from upstream commit" in final_msg

    @patch("subprocess.run")
    @patch("cve_agent.review.run_git_stdout")
    def test_no_restore_when_original_preserved(self, mock_git, mock_run):
        """When the AI correctly appended notes after the original message,
        amend_commit_with_summary should just append the summary."""
        # AI properly preserved the original and appended
        preserved_msg = (
            "transport.c: Additional boundary checks for packet length (#2052)\n"
            "\n"
            "Add upper-bound check on packet_length against\n"
            "LIBSSH2_PACKET_MAXPAYLOAD to prevent OOB write.\n"
            "\n"
            "Closes #2050\n"
            "\n"
            "Backport Resolution: Add bounds checking on packet length.\n"
            "\n"
            "Conflicts Resolved:\n"
            "\n"
            "src/transport.c (1 conflict):\n"
            "- Upstream uses ssh2_ntohu32(); stable uses _libssh2_ntohu32().\n"
            "\n"
            "Assisted-by: kiro:claude-sonnet-4.6\n"
        )

        def git_side_effect(args, cwd):
            if '--format=%B' in args:
                return preserved_msg
            if '--format=%s' in args and UPSTREAM_SHA in args:
                return UPSTREAM_SUBJECT
            if '--format=%b' in args and UPSTREAM_SHA in args:
                return UPSTREAM_BODY
            return ""

        mock_git.side_effect = git_side_effect
        mock_run.return_value = type("R", (), {"returncode": 0})()

        amend_commit_with_summary(
            Path("/ws"), UPSTREAM_SHA, "Changes from upstream commit 97acf3dfda80:\n  - src/transport.c: adapted"
        )

        mock_run.assert_called_once()
        final_msg = mock_run.call_args[0][0][-1]

        # Original body preserved
        assert "Closes #2050" in final_msg
        # Kiro notes preserved
        assert "Backport Resolution:" in final_msg
        # Summary appended
        assert "Changes from upstream commit" in final_msg

    @patch("subprocess.run")
    @patch("cve_agent.review.run_git_stdout")
    def test_body_only_replaced_no_subject_match(self, mock_git, mock_run):
        """When the AI wrote a completely different subject line (edge case),
        the original should be restored from upstream SHA."""
        ai_msg = (
            "Backport Resolution: Add bounds checking on packet length.\n"
            "\n"
            "Conflicts Resolved:\n"
            "\n"
            "src/transport.c (1 conflict):\n"
            "- Adapted API call.\n"
        )

        def git_side_effect(args, cwd):
            if '--format=%B' in args:
                return ai_msg
            if '--format=%s' in args and UPSTREAM_SHA in args:
                return UPSTREAM_SUBJECT
            if '--format=%b' in args and UPSTREAM_SHA in args:
                return UPSTREAM_BODY
            return ""

        mock_git.side_effect = git_side_effect
        mock_run.return_value = type("R", (), {"returncode": 0})()

        amend_commit_with_summary(Path("/ws"), UPSTREAM_SHA, "summary")

        mock_run.assert_called_once()
        final_msg = mock_run.call_args[0][0][-1]

        # Original subject restored
        assert UPSTREAM_SUBJECT in final_msg
        # Original body restored
        assert "Closes #2050" in final_msg
        # AI notes kept
        assert "Backport Resolution:" in final_msg
