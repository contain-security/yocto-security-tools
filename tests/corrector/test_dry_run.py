# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Integration test for cve-corrector --dry-run flag."""
import json
import subprocess
import sys

import pytest


@pytest.fixture
def cve_metadata(tmp_path):
    """Create a minimal cve-metadata.json for testing."""
    data = {
        "CVE-2025-9999": {
            "name": "busybox",
            "hashes": ["abc123"],
            "hash_details": [{"hash": "abc123", "url": "https://github.com/mirror/busybox/commit/abc123"}],
            "series": []
        }
    }
    path = tmp_path / "cve-metadata.json"
    path.write_text(json.dumps(data))
    return path


def test_dry_run_prints_summary(cve_metadata, monkeypatch):
    """--dry-run validates inputs and prints summary without making changes."""
    monkeypatch.setenv("BBPATH", "/fake/build")
    result = subprocess.run(
        [sys.executable, "-m", "cve_corrector",
         "--cve-id", "CVE-2025-9999",
         "--cve-info", str(cve_metadata),
         "--meta-layer", "/tmp",
         "--dry-run"],
        capture_output=True, text=True
    )
    assert result.returncode == 0
    assert "Dry Run: CVE-2025-9999" in result.stdout
    assert "Recipe:     busybox" in result.stdout
    assert "Commits:    1" in result.stdout
    assert "No changes made" in result.stdout


def test_dry_run_missing_cve_fails(cve_metadata, monkeypatch):
    """--dry-run with unknown CVE ID exits with error."""
    monkeypatch.setenv("BBPATH", "/fake/build")
    result = subprocess.run(
        [sys.executable, "-m", "cve_corrector",
         "--cve-id", "CVE-2025-0000",
         "--cve-info", str(cve_metadata),
         "--meta-layer", "/tmp",
         "--dry-run"],
        capture_output=True, text=True
    )
    assert result.returncode != 0
