# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent.session — resolution state checking."""
from unittest.mock import MagicMock
from unittest.mock import patch as mock_patch

from cve_agent.session import check_resolution_state


def test_check_resolution_no_conflicts(tmp_path):
    ws = tmp_path / "repo"
    ws.mkdir()
    result = MagicMock(returncode=0, stdout=" M file.c\n")
    with mock_patch("subprocess.run", return_value=result):
        assert check_resolution_state(ws) is True


def test_check_resolution_with_conflicts(tmp_path):
    ws = tmp_path / "repo"
    ws.mkdir()
    result = MagicMock(returncode=0, stdout="UU file.c\n")
    with mock_patch("subprocess.run", return_value=result):
        assert check_resolution_state(ws) is False


def test_check_resolution_missing_workspace(tmp_path):
    assert check_resolution_state(tmp_path / "nonexistent") is True
