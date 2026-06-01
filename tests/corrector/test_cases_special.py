# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Pytest equivalents of test_cve_corrector_cases.sh — special edge cases.

Shell test mapping:
  Test 8  -> test_missing_autotools_files (CVE-2024-0684 / coreutils)
  Test 14 -> test_underscore_tag_matching (CVE-2024-53589 / binutils)
"""
from cve_corrector.workflow import WorkflowConfig
from tests.helpers import assert_patch_correctness, assert_patch_naming, run_workflow


def _run_workflow(cve_data, cve_id, config):
    """Run initialize + finish workflow, return exit code."""
    return run_workflow(cve_data, cve_id, config)


class TestMissingAutotoolsFiles:
    """Test 8: Upstream git lacks autotools files that devtool branch has."""

    def test_missing_autotools_files(self, make_upstream_repo, make_workspace,
                                     make_meta_layer, mock_bitbake_env):
        # Upstream: only has src/main.c (no configure, no Makefile.in)
        bare, hashes = make_upstream_repo(
            files={'src/main.c': 'int main() { /* vuln */ }\n'},
            version_tag='v9.4',
            fix_commits=[{'files': {'src/main.c': 'int main() { /* fixed */ }\n'},
                          'message': 'Fix buffer overflow'}])

        # Devtool branch has configure + Makefile.in (from tarball)
        ws = make_workspace(bare, 'coreutils', 'v9.4',
                            existing_patch_commits=[
                                {'files': {'configure': '#!/bin/sh\necho ok\n',
                                           'Makefile.in': 'all:\n\techo build\n'},
                                 'message': 'Add generated autotools files'}])

        meta = make_meta_layer('coreutils', '9.4',
                               existing_patches={'0001-Add-generated-autotools-files.patch': 'p\n'})
        mock_bitbake_env(ws, meta, 'coreutils', '9.4')

        cve_id = 'CVE-2024-0684'
        cve_data = {cve_id: {
            'name': 'coreutils', 'hashes': hashes,
            'hash_details': [{'hash': hashes[0], 'url': 'https://example.com/x',
                              'source': 'test'}]}}

        config = WorkflowConfig(
            mirror_path=None, mirror_dir=None, meta_layer=meta,
            skip_build=True, clean=False, skip_ptest=True,
            edit_mode=False, skip_cve_applicability=True)

        exit_code = _run_workflow(cve_data, cve_id, config)

        assert exit_code == 0
        assert_patch_naming(meta, cve_id, expect_series=False)
        assert_patch_correctness(meta, cve_id, expected_files={'src/main.c'})


class TestUnderscoreTagMatching:
    """Test 14: Tag binutils-2_42 matches version 2.42 via normalization."""

    def test_underscore_tag_matching(self, make_upstream_repo, make_workspace,
                                     make_meta_layer, mock_bitbake_env):
        # Upstream uses underscore tag format: binutils-2_42
        bare, hashes = make_upstream_repo(
            files={'src/bfd.c': 'void bfd_read() { /* vuln */ }\n'},
            version_tag='binutils-2_42',
            fix_commits=[{'files': {'src/bfd.c': 'void bfd_read() { /* fixed */ }\n'},
                          'message': 'Fix integer overflow'}])

        ws = make_workspace(bare, 'binutils', 'binutils-2_42')
        meta = make_meta_layer('binutils', '2.42')
        mock_bitbake_env(ws, meta, 'binutils', '2.42')

        cve_id = 'CVE-2024-53589'
        cve_data = {cve_id: {
            'name': 'binutils', 'hashes': hashes,
            'hash_details': [{'hash': hashes[0], 'url': 'https://example.com/x',
                              'source': 'test'}]}}

        config = WorkflowConfig(
            mirror_path=None, mirror_dir=None, meta_layer=meta,
            skip_build=True, clean=False, skip_ptest=True,
            edit_mode=False, skip_cve_applicability=True)

        exit_code = _run_workflow(cve_data, cve_id, config)

        assert exit_code == 0
        assert_patch_naming(meta, cve_id, expect_series=False)
        assert_patch_correctness(meta, cve_id, expected_files={'src/bfd.c'})
