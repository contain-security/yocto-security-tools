# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent.setup — agent verification and installation."""
from unittest.mock import patch

import pytest

from cve_agent.setup import (
    REQUIRED_AGENTS,
    check_kiro_cli,
    ensure_agents,
    get_missing_agents,
    install_agents,
    verify_agents_installed,
)


@pytest.fixture
def fake_dirs(tmp_path, monkeypatch):
    """Set up fake source and target agent directories."""
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    target.mkdir()

    # Create source agent JSONs with a file:// prompt URI
    for name in REQUIRED_AGENTS:
        (source / f"{name}.json").write_text(
            f'{{"name": "{name}", "prompt": "file://cve_agent/AGENT_INSTRUCTIONS.md"}}')

    monkeypatch.setattr("cve_agent.setup.AGENT_SOURCE_DIR", source)
    monkeypatch.setattr("cve_agent.setup.KIRO_AGENTS_DIR", target)
    return source, target


def test_get_missing_agents_all_missing(fake_dirs):
    _, _ = fake_dirs
    missing = get_missing_agents()
    assert set(missing) == set(REQUIRED_AGENTS)


def test_get_missing_agents_none_missing(fake_dirs):
    source, target = fake_dirs
    for name in REQUIRED_AGENTS:
        (target / f"{name}.json").symlink_to(source / f"{name}.json")
    assert get_missing_agents() == []


def test_verify_agents_installed_false(fake_dirs):
    assert verify_agents_installed() is False


def test_verify_agents_installed_true(fake_dirs):
    source, target = fake_dirs
    for name in REQUIRED_AGENTS:
        (target / f"{name}.json").symlink_to(source / f"{name}.json")
    assert verify_agents_installed() is True


def test_install_agents_creates_symlinks(fake_dirs):
    source, target = fake_dirs
    result = install_agents(list(REQUIRED_AGENTS))
    assert result is True
    for name in REQUIRED_AGENTS:
        installed = target / f"{name}.json"
        assert installed.exists()
        assert not installed.is_symlink()
        import json
        data = json.loads(installed.read_text())
        assert data['name'] == name
        assert data['prompt'].startswith('file:///')
        assert 'cve_agent/AGENT_INSTRUCTIONS.md' in data['prompt']


def test_install_agents_missing_source(fake_dirs):
    source, _ = fake_dirs
    (source / f"{REQUIRED_AGENTS[0]}.json").unlink()
    result = install_agents([REQUIRED_AGENTS[0]])
    assert result is False


def test_install_agents_creates_target_dir(tmp_path, monkeypatch):
    source = tmp_path / "source"
    target = tmp_path / "nonexistent" / "agents"
    source.mkdir()
    (source / f"{REQUIRED_AGENTS[0]}.json").write_text("{}")

    monkeypatch.setattr("cve_agent.setup.AGENT_SOURCE_DIR", source)
    monkeypatch.setattr("cve_agent.setup.KIRO_AGENTS_DIR", target)

    result = install_agents([REQUIRED_AGENTS[0]])
    assert result is True
    assert target.exists()


def test_check_kiro_cli_found():
    with patch("shutil.which", return_value="/usr/bin/kiro-cli"):
        assert check_kiro_cli() is True


def test_check_kiro_cli_not_found():
    with patch("shutil.which", return_value=None):
        assert check_kiro_cli() is False


def test_ensure_agents_exits_without_kiro_cli(monkeypatch):
    monkeypatch.setattr("cve_agent.setup.check_kiro_cli", lambda: False)
    with pytest.raises(SystemExit):
        ensure_agents()


def test_ensure_agents_noop_when_installed(fake_dirs, monkeypatch):
    source, target = fake_dirs
    for name in REQUIRED_AGENTS:
        (target / f"{name}.json").symlink_to(source / f"{name}.json")
    monkeypatch.setattr("cve_agent.setup.check_kiro_cli", lambda: True)
    ensure_agents()


def test_ensure_agents_auto_installs_non_interactive(fake_dirs, monkeypatch):
    monkeypatch.setattr("cve_agent.setup.check_kiro_cli", lambda: True)
    ensure_agents(interactive=False)
    assert verify_agents_installed() is True


def test_ensure_agents_prompts_and_installs(fake_dirs, monkeypatch):
    monkeypatch.setattr("cve_agent.setup.check_kiro_cli", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "y")
    ensure_agents(interactive=True)
    assert verify_agents_installed() is True


def test_ensure_agents_prompts_and_declines(fake_dirs, monkeypatch):
    monkeypatch.setattr("cve_agent.setup.check_kiro_cli", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "n")
    with pytest.raises(SystemExit):
        ensure_agents(interactive=True)
