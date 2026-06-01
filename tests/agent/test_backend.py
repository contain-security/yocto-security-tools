# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for pluggable AI backend interface."""
from pathlib import Path

from cve_agent.backend import (
    AIBackend,
    SessionResult,
    available_backends,
    get_backend,
    register_backend,
)


class MockBackend(AIBackend):
    name = "mock"

    def is_available(self):
        return True

    def run_session(self, prompt, workspace_path, allowed_files,
                   model, timeout, interactive):
        return SessionResult(resolved=True, duration=0.1)


def test_register_and_get_backend():
    register_backend(MockBackend())
    assert 'mock' in available_backends()
    backend = get_backend('mock')
    assert backend.name == 'mock'


def test_mock_backend_session():
    register_backend(MockBackend())
    backend = get_backend('mock')
    result = backend.run_session(
        'test prompt', Path('/tmp'), set(), 'model', 60, False)
    assert result.resolved is True
    assert result.duration > 0


def test_default_backend_is_kiro():
    assert 'kiro' in available_backends()
    backend = get_backend('kiro')
    assert backend.name == 'kiro'
