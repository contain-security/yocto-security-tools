# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for _ensure_layer_branch pre-flight check."""
import subprocess

import pytest

from cve_corrector.state import GitError
from cve_corrector.workflow import _ensure_layer_branch


def _init_repo(path):
    """Create a git repo with one commit."""
    subprocess.run(['git', 'init', str(path)], check=True, capture_output=True)
    subprocess.run(['git', 'config', 'user.email', 'test@test.com'],
                   cwd=path, check=True, capture_output=True)
    subprocess.run(['git', 'config', 'user.name', 'Test'],
                   cwd=path, check=True, capture_output=True)
    (path / 'f.txt').write_text('x')
    subprocess.run(['git', 'add', '.'], cwd=path, check=True, capture_output=True)
    subprocess.run(['git', 'commit', '-m', 'init'], cwd=path, check=True,
                   capture_output=True)


def test_ensure_layer_branch_on_branch(tmp_path):
    """No error when meta-layer is on a branch."""
    _init_repo(tmp_path)
    _ensure_layer_branch(tmp_path)  # should not raise


def test_ensure_layer_branch_detached_head(tmp_path):
    """Raises GitError when meta-layer has detached HEAD."""
    _init_repo(tmp_path)
    subprocess.run(['git', 'checkout', '--detach'], cwd=tmp_path, check=True,
                   capture_output=True)
    with pytest.raises(GitError, match="detached HEAD"):
        _ensure_layer_branch(tmp_path)
