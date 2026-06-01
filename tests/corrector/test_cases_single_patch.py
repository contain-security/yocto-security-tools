# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Pytest equivalents of test_cve_corrector_cases.sh — single patch scenarios.

Shell test mapping:
  Test 2  -> test_clean_cherry_pick (CVE-2025-5915 / libarchive)
  Test 5  -> test_single_patch_with_ptest (CVE-2023-42363 / busybox)
  Test 12 -> test_skip_build_ptest_baseline (CVE-2024-44331 / gstreamer1.0-rtsp-server)
  Test 16 -> test_ignored_untracked_files (CVE-2025-46802 / screen)
"""

from cve_corrector.workflow import WorkflowConfig
from tests.helpers import (
    assert_no_patches_removed,
    assert_patch_correctness,
    assert_patch_naming,
    get_src_uri_patches,
    run_workflow,
)


def _run_workflow(cve_data, cve_id, config):
    """Run initialize + finish workflow, return exit code."""
    return run_workflow(cve_data, cve_id, config)


def _make_cve_data(recipe, hashes, hash_details=None):
    """Build minimal CVE metadata dict."""
    cve_id = f'CVE-2025-{id(recipe) % 9000 + 1000:04d}'
    if hash_details is None:
        hash_details = [{'hash': h, 'url': f'https://example.com/commit/{h}',
                         'source': 'test'} for h in hashes]
    return cve_id, {cve_id: {'name': recipe, 'hashes': hashes,
                             'hash_details': hash_details}}


class TestCleanCherryPick:
    """Test 2: Single patch, clean cherry-pick with build+ptest."""

    def test_clean_cherry_pick(self, make_upstream_repo, make_workspace,
                               make_meta_layer, mock_bitbake_env):
        bare, hashes = make_upstream_repo(
            files={'src/archive.c': 'void read() { /* vulnerable */ }\n'},
            version_tag='v3.7.2',
            fix_commits=[{'files': {'src/archive.c': 'void read() { /* fixed */ }\n'},
                          'message': 'Fix buffer overflow'}])

        ws = make_workspace(bare, 'libarchive', 'v3.7.2')
        meta = make_meta_layer('libarchive', '3.7.2',
                               existing_patches={'defconfig.patch': 'existing\n'},
                               src_uri_entries=['file://defconfig.patch'])

        before = get_src_uri_patches(meta, 'libarchive')
        build_called = mock_bitbake_env(ws, meta, 'libarchive', '3.7.2')

        cve_id, cve_data = _make_cve_data('libarchive', hashes)
        config = WorkflowConfig(
            mirror_path=None, mirror_dir=None, meta_layer=meta,
            skip_build=False, clean=False, skip_ptest=False,
            edit_mode=False, skip_cve_applicability=True)

        exit_code = _run_workflow(cve_data, cve_id, config)

        assert exit_code == 0
        assert_patch_naming(meta, cve_id, expect_series=False)
        after = get_src_uri_patches(meta, 'libarchive')
        assert_no_patches_removed(before, after)
        assert_patch_correctness(meta, cve_id, expected_files={'src/archive.c'})
        assert len(build_called) > 0  # build was invoked


class TestSinglePatchWithPtest:
    """Test 5: Single patch with ptest verification."""

    def test_single_patch_with_ptest(self, make_upstream_repo, make_workspace,
                                     make_meta_layer, mock_bitbake_env):
        bare, hashes = make_upstream_repo(
            files={'src/shell.c': 'void exec() { /* bug */ }\n'},
            version_tag='v1.36.1',
            fix_commits=[{'files': {'src/shell.c': 'void exec() { /* safe */ }\n'},
                          'message': 'Fix use-after-free'}])

        ws = make_workspace(bare, 'busybox', 'v1.36.1')
        meta = make_meta_layer('busybox', '1.36.1',
                               existing_patches={'init.patch': 'p\n'},
                               src_uri_entries=['file://init.patch'])

        before = get_src_uri_patches(meta, 'busybox')
        mock_bitbake_env(ws, meta, 'busybox', '1.36.1')

        cve_id, cve_data = _make_cve_data('busybox', hashes)
        config = WorkflowConfig(
            mirror_path=None, mirror_dir=None, meta_layer=meta,
            skip_build=False, clean=False, skip_ptest=False,
            edit_mode=False, skip_cve_applicability=True)

        exit_code = _run_workflow(cve_data, cve_id, config)

        assert exit_code == 0
        assert_patch_naming(meta, cve_id, expect_series=False)
        after = get_src_uri_patches(meta, 'busybox')
        assert_no_patches_removed(before, after)
        assert_patch_correctness(meta, cve_id, expected_files={'src/shell.c'})


class TestSkipBuildPtestBaseline:
    """Test 12: Skip-build-ptest baseline — simplest path."""

    def test_skip_build_ptest_baseline(self, make_upstream_repo, make_workspace,
                                       make_meta_layer, mock_bitbake_env):
        bare, hashes = make_upstream_repo(
            files={'src/rtsp.c': 'void serve() { /* vuln */ }\n'},
            version_tag='v1.22.0',
            fix_commits=[{'files': {'src/rtsp.c': 'void serve() { /* ok */ }\n'},
                          'message': 'Fix null deref'}])

        ws = make_workspace(bare, 'gstreamer1.0-rtsp-server', 'v1.22.0')
        meta = make_meta_layer('gstreamer1.0-rtsp-server', '1.22.0')

        before = get_src_uri_patches(meta, 'gstreamer1.0-rtsp-server')
        mock_bitbake_env(ws, meta, 'gstreamer1.0-rtsp-server', '1.22.0')

        cve_id, cve_data = _make_cve_data('gstreamer1.0-rtsp-server', hashes)
        config = WorkflowConfig(
            mirror_path=None, mirror_dir=None, meta_layer=meta,
            skip_build=True, clean=False, skip_ptest=True,
            edit_mode=False, skip_cve_applicability=True)

        exit_code = _run_workflow(cve_data, cve_id, config)

        assert exit_code == 0
        assert_patch_naming(meta, cve_id, expect_series=False)
        after = get_src_uri_patches(meta, 'gstreamer1.0-rtsp-server')
        assert_no_patches_removed(before, after)
        assert_patch_correctness(meta, cve_id, expected_files={'src/rtsp.c'})


class TestIgnoredUntrackedFiles:
    """Test 16: .gitignore blocks checkout unless git clean -fdx is used."""

    def test_ignored_untracked_files(self, make_upstream_repo, make_workspace,
                                     make_meta_layer, mock_bitbake_env):
        # Upstream has src/main.c but NOT configure (simulating git-only repo)
        bare, hashes = make_upstream_repo(
            files={'src/main.c': 'int main() { /* vuln */ }\n',
                   '.gitignore': 'configure\nautom4te.cache\n'},
            version_tag='v4.9.1',
            fix_commits=[{'files': {'src/main.c': 'int main() { /* fixed */ }\n'},
                          'message': 'Fix overflow'}])

        # Workspace: devtool branch has configure (from tarball)
        ws = make_workspace(bare, 'screen', 'v4.9.1',
                            existing_patch_commits=[
                                {'files': {'configure': '#!/bin/sh\necho configured\n'},
                                 'message': 'Add autotools files from tarball'}])

        # Meta-layer already has the autotools patch (it's a pre-existing patch)
        meta = make_meta_layer('screen', '4.9.1',
                               existing_patches={'0001-Add-autotools-files-from-tarball.patch': 'existing\n'},
                               src_uri_entries=['file://0001-Add-autotools-files-from-tarball.patch'])
        before = get_src_uri_patches(meta, 'screen')
        mock_bitbake_env(ws, meta, 'screen', '4.9.1')

        cve_id, cve_data = _make_cve_data('screen', hashes)
        config = WorkflowConfig(
            mirror_path=None, mirror_dir=None, meta_layer=meta,
            skip_build=True, clean=False, skip_ptest=True,
            edit_mode=False, skip_cve_applicability=True)

        exit_code = _run_workflow(cve_data, cve_id, config)

        assert exit_code == 0
        assert_patch_naming(meta, cve_id, expect_series=False)
        after = get_src_uri_patches(meta, 'screen')
        assert_no_patches_removed(before, after)
        assert_patch_correctness(meta, cve_id, expected_files={'src/main.c'})
