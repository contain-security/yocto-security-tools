# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Pytest equivalents of test_cve_corrector_cases.sh — series scenarios.

Shell test mapping:
  Test 1  -> test_multi_patch_removed_subsequent (CVE-2024-12086 / rsync)
  Test 3  -> test_series_multiple_patches (CVE-2026-25210 / expat)
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


class TestMultiPatchRemovedSubsequent:
    """Test 1: Single fix commit, meta-layer has other CVE patches preserved."""

    def test_multi_patch_removed_subsequent(self, make_upstream_repo, make_workspace,
                                            make_meta_layer, mock_bitbake_env):
        bare, hashes = make_upstream_repo(
            files={'src/rsync.c': 'void sync() { /* vuln */ }\n'},
            version_tag='v3.2.7',
            fix_commits=[{'files': {'src/rsync.c': 'void sync() { /* fixed */ }\n'},
                          'message': 'Fix path traversal'}])

        ws = make_workspace(bare, 'rsync', 'v3.2.7')
        # Meta-layer has patches for OTHER CVEs that must be preserved
        meta = make_meta_layer('rsync', '3.2.7',
                               existing_patches={
                                   'CVE-2024-12087.patch': 'other fix 1\n',
                                   'CVE-2024-12088.patch': 'other fix 2\n',
                               },
                               src_uri_entries=['file://CVE-2024-12087.patch',
                                               'file://CVE-2024-12088.patch'])

        before = get_src_uri_patches(meta, 'rsync')
        mock_bitbake_env(ws, meta, 'rsync', '3.2.7')

        cve_id = 'CVE-2024-12086'
        cve_data = {cve_id: {
            'name': 'rsync', 'hashes': hashes,
            'hash_details': [{'hash': hashes[0],
                              'url': f'https://example.com/commit/{hashes[0]}',
                              'source': 'test'}]}}

        config = WorkflowConfig(
            mirror_path=None, mirror_dir=None, meta_layer=meta,
            skip_build=True, clean=False, skip_ptest=True,
            edit_mode=False, skip_cve_applicability=True)

        exit_code = _run_workflow(cve_data, cve_id, config)

        assert exit_code == 0
        assert_patch_naming(meta, cve_id, expect_series=False)
        after = get_src_uri_patches(meta, 'rsync')
        assert_no_patches_removed(before, after)
        assert_patch_correctness(meta, cve_id, expected_files={'src/rsync.c'})


class TestSeriesMultiplePatches:
    """Test 3: PR series with multiple commits → CVE-ID-N.patch naming."""

    def test_series_multiple_patches(self, make_upstream_repo, make_workspace,
                                     make_meta_layer, mock_bitbake_env):
        bare, hashes = make_upstream_repo(
            files={'src/parser.c': 'void parse() { /* v1 */ }\n',
                   'src/alloc.c': 'void alloc() { /* v1 */ }\n'},
            version_tag='v2.5.0',
            fix_commits=[
                {'files': {'src/parser.c': 'void parse() { /* fix1 */ }\n'},
                 'message': 'Fix parser overflow'},
                {'files': {'src/alloc.c': 'void alloc() { /* fix2 */ }\n'},
                 'message': 'Fix allocator'},
                {'files': {'src/parser.c': 'void parse() { /* fix3 */ }\n'},
                 'message': 'Harden parser bounds'},
            ])

        ws = make_workspace(bare, 'expat', 'v2.5.0')
        meta = make_meta_layer('expat', '2.5.0',
                               existing_patches={'base.patch': 'base\n'},
                               src_uri_entries=['file://base.patch'])

        before = get_src_uri_patches(meta, 'expat')
        mock_bitbake_env(ws, meta, 'expat', '2.5.0')

        cve_id = 'CVE-2026-25210'
        cve_data = {cve_id: {
            'name': 'expat', 'hashes': hashes,
            'hash_details': [{'hash': h, 'url': f'https://example.com/commit/{h}',
                              'source': 'test'} for h in hashes],
            'series': [{'pull_url': 'https://github.com/libexpat/libexpat/pull/999',
                        'commits': hashes}]}}

        config = WorkflowConfig(
            mirror_path=None, mirror_dir=None, meta_layer=meta,
            skip_build=True, clean=False, skip_ptest=True,
            edit_mode=False, skip_cve_applicability=True)

        exit_code = _run_workflow(cve_data, cve_id, config)

        assert exit_code == 0
        assert_patch_naming(meta, cve_id, expect_series=True)
        after = get_src_uri_patches(meta, 'expat')
        assert_no_patches_removed(before, after)
        # Verify all files from the series are covered
        assert_patch_correctness(meta, cve_id,
                                 expected_files={'src/parser.c', 'src/alloc.c'})
