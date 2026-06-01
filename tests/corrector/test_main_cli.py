# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_corrector/__main__.py CLI parsing and flow."""
import json
from unittest.mock import patch

import pytest

from cve_corrector.__main__ import _check_bitbake_env, _get_version, main


class TestGetVersion:
    def test_returns_string(self):
        v = _get_version()
        assert isinstance(v, str)
        assert v  # not empty


class TestCheckBitbakeEnv:
    def test_no_bbpath(self, monkeypatch):
        monkeypatch.delenv('BBPATH', raising=False)
        with pytest.raises(SystemExit):
            _check_bitbake_env()

    def test_no_bitbake_layers(self, monkeypatch):
        monkeypatch.setenv('BBPATH', '/tmp')
        with patch('shutil.which', return_value=None), pytest.raises(SystemExit):
            _check_bitbake_env()


class TestMainCli:
    def test_no_args_exits(self, monkeypatch):
        monkeypatch.setattr('sys.argv', ['cve-corrector'])
        monkeypatch.setenv('BBPATH', '/tmp')
        with patch('shutil.which', return_value='/usr/bin/bitbake-layers'):
            with pytest.raises(SystemExit):
                main()

    def test_dry_run(self, tmp_path, monkeypatch):
        cve_info = tmp_path / 'cve.json'
        cve_info.write_text(json.dumps({
            'CVE-2025-0001': {'name': 'foo', 'hashes': ['abc123'],
                              'hash_details': [{'hash': 'abc123'}]}
        }))
        monkeypatch.setattr('sys.argv', [
            'cve-corrector', '--cve-id', 'CVE-2025-0001',
            '--cve-info', str(cve_info), '--dry-run',
            '--meta-layer', str(tmp_path)])
        # dry-run skips bitbake env check
        main()  # should not raise

    def test_missing_cve_in_metadata(self, tmp_path, monkeypatch):
        cve_info = tmp_path / 'cve.json'
        cve_info.write_text(json.dumps({'CVE-OTHER': {'name': 'bar'}}))
        monkeypatch.setattr('sys.argv', [
            'cve-corrector', '--cve-id', 'CVE-2025-MISSING',
            '--cve-info', str(cve_info), '--dry-run',
            '--meta-layer', str(tmp_path)])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 6  # EXIT_METADATA_ERROR

    def test_continue_without_state(self, monkeypatch):
        monkeypatch.setattr('sys.argv', ['cve-corrector', '--continue'])
        monkeypatch.setenv('BBPATH', '/tmp')
        with patch('shutil.which', return_value='/usr/bin/bitbake-layers'):
            with pytest.raises(SystemExit):
                main()
