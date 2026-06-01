# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_corrector.state — WorkflowState serialization."""
from pathlib import Path

from cve_corrector.state import EXIT_NOT_APPLICABLE, WorkflowState


def _make_state(**overrides):
    defaults = dict(
        workspace_path=Path("/tmp/ws/sources/libarchive"),
        cve_id="CVE-2025-5915",
        recipe="libarchive",
        commit_hash="a612bf62f86a6faa47bd57c52b94849f0a404d8c",
        hash_details=[{"hash": "a612bf62", "url": "https://github.com/libarchive/libarchive/commit/a612bf62"}],
        meta_layer=Path("/home/user/yocto/meta"),
        skip_build=False,
        skip_ptest=False,
    )
    defaults.update(overrides)
    return WorkflowState(**defaults)


def test_to_dict_roundtrip():
    state = _make_state(ptest_before="PASSED: 10, FAILED: 0",
                        series_state={"commits": ["abc", "def"]},
                        current_step="build")
    restored = WorkflowState.from_dict(state.to_dict())
    assert restored.cve_id == state.cve_id
    assert restored.recipe == state.recipe
    assert restored.commit_hash == state.commit_hash
    assert restored.hash_details == state.hash_details
    assert restored.skip_build == state.skip_build
    assert restored.skip_ptest == state.skip_ptest
    assert restored.ptest_before == state.ptest_before
    assert restored.series_state == state.series_state
    assert restored.current_step == state.current_step
    assert restored.workspace_path == state.workspace_path
    assert restored.meta_layer == state.meta_layer


def test_from_dict_missing_optional_fields():
    data = dict(
        workspace_path="/tmp/ws",
        cve_id="CVE-2025-0001",
        recipe="foo",
        commit_hash="abc123",
        hash_details=[],
        meta_layer=None,
        skip_build=True,
    )
    state = WorkflowState.from_dict(data)
    assert state.skip_ptest is False
    assert state.ptest_before is None
    assert state.series_state is None
    assert state.current_step is None
    assert state.skip_confirm is False


def test_to_dict_none_meta_layer():
    state = _make_state(meta_layer=None)
    d = state.to_dict()
    assert d["meta_layer"] is None
    restored = WorkflowState.from_dict(d)
    assert restored.meta_layer is None


def test_from_dict_path_types():
    state = _make_state()
    restored = WorkflowState.from_dict(state.to_dict())
    assert isinstance(restored.workspace_path, Path)
    assert isinstance(restored.meta_layer, Path)


def test_exit_not_applicable_constant():
    assert EXIT_NOT_APPLICABLE == 12
