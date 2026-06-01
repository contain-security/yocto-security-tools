# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_corrector.ptest — ptest operations."""
from unittest.mock import MagicMock, patch

import pytest

from cve_corrector.ptest import check_ptest_in_recipe, enable_ptest, run_ptest
from cve_corrector.state import BuildPreexistingError


class TestEnablePtest:
    @patch("cve_corrector.ptest.run_cmd_capture")
    @patch("cve_corrector.ptest.get_build_path")
    def test_appends_when_missing(self, mock_bp, mock_run, tmp_path):
        mock_bp.return_value = tmp_path
        (tmp_path / "conf").mkdir()
        (tmp_path / "conf" / "local.conf").write_text("# config\n")
        mock_run.return_value = MagicMock(stdout="DISTRO_FEATURES=opengl")
        enable_ptest()
        assert "ptest" in (tmp_path / "conf" / "local.conf").read_text()

    @patch("cve_corrector.ptest.run_cmd_capture")
    @patch("cve_corrector.ptest.get_build_path")
    def test_skips_when_present(self, mock_bp, mock_run, tmp_path):
        mock_bp.return_value = tmp_path
        (tmp_path / "conf").mkdir()
        conf = tmp_path / "conf" / "local.conf"
        conf.write_text("# config\n")
        mock_run.return_value = MagicMock(stdout="DISTRO_FEATURES=ptest opengl")
        enable_ptest()
        assert conf.read_text() == "# config\n"


class TestCheckPtestInRecipe:
    @patch("cve_corrector.ptest.run_cmd_capture")
    def test_enabled(self, mock_run):
        mock_run.return_value = MagicMock(stdout='PTEST_ENABLED="1"')
        assert check_ptest_in_recipe("busybox") is True

    @patch("cve_corrector.ptest.run_cmd_capture")
    def test_disabled(self, mock_run):
        mock_run.return_value = MagicMock(stdout='PTEST_ENABLED=""')
        assert check_ptest_in_recipe("busybox") is False


class TestRunPtest:
    @patch("cve_corrector.ptest.check_ptest_in_recipe", return_value=False)
    def test_no_ptest(self, _):
        assert run_ptest("busybox") is None

    @patch("cve_corrector.ptest.run_cmd", return_value=0)
    @patch("cve_corrector.ptest.run_cmd_capture")
    @patch("cve_corrector.ptest.check_ptest_in_recipe", return_value=True)
    @patch("cve_corrector.ptest.get_build_path")
    def test_full_run_with_results(self, mock_bp, mock_check, mock_capture, mock_cmd, tmp_path):
        mock_bp.return_value = tmp_path
        (tmp_path / "conf").mkdir()
        (tmp_path / "conf" / "local.conf").write_text(
            "CORE_IMAGE_EXTRA_INSTALL = \"old\"\n")
        mock_capture.return_value = MagicMock(stdout="testimage enabled")

        # Create ptest log as a file (not directory)
        log_dir = (tmp_path / "tmp-glibc" / "work" / "x86" /
                   "core-image-minimal" / "1.0" / "testimage" /
                   "ptest_log")
        log_dir.mkdir(parents=True)
        log_file = log_dir / "busybox"
        log_file.write_text("PASSED: test1\nPASSED: test2\nFAILED: test3\nSKIPPED: test4")

        result = run_ptest("busybox")
        assert result is not None
        assert "PASSED: 2" in result
        assert "FAILED: 1" in result

    @patch("cve_corrector.ptest.run_cmd")
    @patch("cve_corrector.ptest.run_cmd_capture")
    @patch("cve_corrector.ptest.check_ptest_in_recipe", return_value=True)
    @patch("cve_corrector.ptest.get_build_path")
    def test_build_failure_exits(self, mock_bp, mock_check, mock_capture, mock_cmd, tmp_path):
        mock_bp.return_value = tmp_path
        (tmp_path / "conf").mkdir()
        (tmp_path / "conf" / "local.conf").write_text("# config\n")
        mock_capture.return_value = MagicMock(stdout="testimage enabled")
        mock_cmd.return_value = 1  # build fails
        with pytest.raises(BuildPreexistingError):
            run_ptest("busybox")

    @patch("cve_corrector.ptest.run_cmd")
    @patch("cve_corrector.ptest.run_cmd_capture")
    @patch("cve_corrector.ptest.check_ptest_in_recipe", return_value=True)
    @patch("cve_corrector.ptest.get_build_path")
    def test_testimage_timeout(self, mock_bp, mock_check, mock_capture, mock_cmd, tmp_path):
        mock_bp.return_value = tmp_path
        (tmp_path / "conf").mkdir()
        (tmp_path / "conf" / "local.conf").write_text("# config\n")
        mock_capture.return_value = MagicMock(stdout="testimage enabled")
        mock_cmd.side_effect = [0, -1]  # build ok, testimage timeout
        result = run_ptest("busybox")
        assert result is None

    @patch("cve_corrector.ptest.run_cmd", return_value=0)
    @patch("cve_corrector.ptest.run_cmd_capture")
    @patch("cve_corrector.ptest.check_ptest_in_recipe", return_value=True)
    @patch("cve_corrector.ptest.get_build_path")
    def test_no_ptest_logs(self, mock_bp, mock_check, mock_capture, mock_cmd, tmp_path):
        mock_bp.return_value = tmp_path
        (tmp_path / "conf").mkdir()
        (tmp_path / "conf" / "local.conf").write_text("# config\n")
        mock_capture.return_value = MagicMock(stdout="testimage enabled")
        result = run_ptest("busybox")
        assert result is None

    @patch("cve_corrector.ptest.run_cmd", return_value=0)
    @patch("cve_corrector.ptest.run_cmd_capture")
    @patch("cve_corrector.ptest.check_ptest_in_recipe", return_value=True)
    @patch("cve_corrector.ptest.get_build_path")
    def test_adds_testimage_config(self, mock_bp, mock_check, mock_capture, mock_cmd, tmp_path):
        mock_bp.return_value = tmp_path
        (tmp_path / "conf").mkdir()
        conf = tmp_path / "conf" / "local.conf"
        conf.write_text("# config\n")
        # First call checks IMAGE_CLASSES — return no testimage
        mock_capture.return_value = MagicMock(stdout="IMAGE_CLASSES = ''")
        run_ptest("busybox")
        # After run, local.conf should be restored to original
        content = conf.read_text()
        assert content == "# config\n"
