# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_corrector.patch_ops — patch metadata injection."""
from unittest.mock import patch as mock_patch

from cve_corrector.patch_ops import modify_patch

MINIMAL_PATCH = """\
From abc123 Mon Sep 17 00:00:00 2001
Subject: Fix something

Some description.
---
 file.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/file.c b/file.c
"""


def test_modify_patch_inserts_metadata(tmp_path):
    p = tmp_path / "test.patch"
    p.write_text(MINIMAL_PATCH)
    with mock_patch("cve_corrector.patch_ops.get_git_user_info",
                    return_value=("Test User", "test@example.com")):
        modify_patch(p, "CVE-2025-0001", "https://example.com/commit/abc")
    content = p.read_text()
    assert "CVE: CVE-2025-0001" in content
    assert "Upstream-Status: Backport [https://example.com/commit/abc]" in content
    assert "Signed-off-by: Test User <test@example.com>" in content
    # Metadata should appear before the --- separator
    assert content.index("CVE: CVE-2025-0001") < content.index("\n---\n")


def test_modify_patch_idempotent(tmp_path):
    p = tmp_path / "test.patch"
    p.write_text(MINIMAL_PATCH)
    with mock_patch("cve_corrector.patch_ops.get_git_user_info",
                    return_value=("Test User", "test@example.com")):
        modify_patch(p, "CVE-2025-0001", "https://example.com/commit/abc")
        first = p.read_text()
        modify_patch(p, "CVE-2025-0001", "https://example.com/commit/abc")
        second = p.read_text()
    assert first == second


def test_modify_patch_no_separator(tmp_path):
    p = tmp_path / "test.patch"
    p.write_text("Subject: no separator\n\nsome content\n")
    import pytest
    with mock_patch("cve_corrector.patch_ops.get_git_user_info",
                    return_value=("Test User", "test@example.com")):
        with pytest.raises(ValueError, match="No line containing '---'"):
            modify_patch(p, "CVE-2025-0001", "https://example.com/commit/abc")


def test_modify_patch_preserves_diff(tmp_path):
    p = tmp_path / "test.patch"
    p.write_text(MINIMAL_PATCH)
    diff_section = MINIMAL_PATCH[MINIMAL_PATCH.index("---"):]
    with mock_patch("cve_corrector.patch_ops.get_git_user_info",
                    return_value=("Test User", "test@example.com")):
        modify_patch(p, "CVE-2025-0001", "https://example.com/commit/abc")
    content = p.read_text()
    assert content.endswith(diff_section)
