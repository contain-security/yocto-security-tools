# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_corrector.utils — logging and command execution."""
import subprocess
from unittest.mock import MagicMock, patch

from cve_corrector.utils import logger, run_cmd, run_cmd_capture, setup_logging


class TestSetupLogging:
    def test_creates_log_file(self, tmp_path):
        log_path = setup_logging("CVE-2025-0001", tmp_path, verbose=True)
        assert log_path.parent.exists()
        assert "CVE-2025-0001" in str(log_path)

    def test_verbose_flag(self, tmp_path):
        setup_logging("CVE-1", tmp_path, verbose=False)
        # Console handler should be INFO level when not verbose
        console = [h for h in logger.handlers if not hasattr(h, 'baseFilename')]
        assert console


class TestRunCmd:
    @patch("subprocess.run", return_value=MagicMock(returncode=0))
    def test_verbose_mode(self, mock_call, tmp_path):
        setup_logging("CVE-1", tmp_path, verbose=True)
        assert run_cmd(["echo", "hi"]) == 0
        mock_call.assert_called_once()

    @patch("subprocess.run", return_value=MagicMock(returncode=0))
    def test_non_verbose_logs_to_file(self, mock_call, tmp_path):
        setup_logging("CVE-1", tmp_path, verbose=False)
        assert run_cmd(["echo", "hi"]) == 0

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 5))
    def test_timeout(self, mock_call, tmp_path):
        setup_logging("CVE-1", tmp_path, verbose=True)
        assert run_cmd(["sleep", "100"], timeout=5) == -1

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 5))
    def test_timeout_with_log_file(self, mock_call, tmp_path):
        setup_logging("CVE-1", tmp_path, verbose=False)
        assert run_cmd(["sleep", "100"], timeout=5) == -1


class TestRunCmdCapture:
    @patch("subprocess.run")
    def test_captures_output(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="output")
        result = run_cmd_capture(["echo", "hi"])
        assert result.stdout == "output"
