# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent.knowledge — knowledge base and similarity."""

from cve_agent.knowledge import (
    KnowledgeBase,
    _compute_similarity,
    create_pattern,
)


def test_add_and_list_patterns(tmp_path):
    kb = KnowledgeBase(path=tmp_path / "kb.json")
    pattern = create_pattern("auto", "busybox", "*", "fixed it", "CVE-2025-0001")
    kb.add_pattern(pattern)
    patterns = kb.list_patterns()
    assert len(patterns) == 1
    assert patterns[0].cve_id == "CVE-2025-0001"


def test_find_similar_by_recipe(tmp_path):
    kb = KnowledgeBase(path=tmp_path / "kb.json")
    kb.add_pattern(create_pattern("auto", "busybox", "*", "fix", "CVE-1"))
    kb.add_pattern(create_pattern("auto", "expat", "*", "fix", "CVE-2"))
    results = kb.find_similar("busybox", ["some/file.c"])
    assert len(results) >= 1
    assert results[0].recipe == "busybox"


def test_find_similar_by_files(tmp_path):
    kb = KnowledgeBase(path=tmp_path / "kb.json")
    kb.add_pattern(create_pattern(
        "auto", "busybox", "*", "fix", "CVE-1",
        affected_files=["archival/tar.c", "archival/unzip.c"]))
    results = kb.find_similar("busybox", ["archival/tar.c"])
    assert len(results) == 1


def test_find_similar_no_match(tmp_path):
    kb = KnowledgeBase(path=tmp_path / "kb.json")
    kb.add_pattern(create_pattern("auto", "busybox", "*", "fix", "CVE-1"))
    results = kb.find_similar("unrelated-recipe", ["other/file.c"])
    assert results == []


def test_compute_similarity_recipe_match():
    entry = {"recipe": "busybox", "file_pattern": "", "conflict_type": "auto"}
    assert _compute_similarity(entry, "busybox", []) >= 10


def test_compute_similarity_file_overlap():
    entry = {"recipe": "busybox", "file_pattern": "",
             "affected_files": ["a.c", "b.c"], "conflict_type": ""}
    score = _compute_similarity(entry, "busybox", ["a.c", "b.c"])
    assert score >= 10 + 6  # 10 recipe + 3*2 files


def test_create_pattern_timestamp():
    p = create_pattern("auto", "foo", "*", "desc", "CVE-2025-0001")
    assert p.timestamp  # non-empty
    assert "T" in p.timestamp  # ISO format


def test_knowledge_base_empty(tmp_path):
    kb = KnowledgeBase(path=tmp_path / "kb.json")
    assert kb.list_patterns() == []


def test_knowledge_base_persistence(tmp_path):
    path = tmp_path / "kb.json"
    kb1 = KnowledgeBase(path=path)
    kb1.add_pattern(create_pattern("auto", "foo", "*", "fix", "CVE-1"))
    kb2 = KnowledgeBase(path=path)
    assert len(kb2.list_patterns()) == 1


def test_knowledge_base_corrupt_json(tmp_path):
    path = tmp_path / "kb.json"
    path.write_text("{corrupt")
    kb = KnowledgeBase(path=path)
    assert kb.list_patterns() == []
