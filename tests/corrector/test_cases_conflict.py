# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Pytest equivalents of test_cve_corrector_cases.sh — conflict scenarios.

Shell test mapping:
  Test 4  -> test_conflict_exits_with_state (CVE-2026-2903 / re2c)
  Test 6  -> test_agent_conflict_least_conflicts (CVE-2026-26157 / busybox)
  Test 7  -> test_agent_conflict_state_for_resume (CVE-2024-0684 / coreutils)
  Test 10 -> test_src_uri_plus_equals_conflict (CVE-2024-39689 / python3-certifi)
  Test 11 -> test_devtool_finish_failure_recovery (CVE-2024-39894 / openssh)
  Test 15 -> test_cross_recipe_shared_patch_conflict (CVE-2025-32909 / libsoup-2.4)
"""
import json

from cve_corrector.state import EXIT_CONFLICT, EXIT_GIT_ERROR
from cve_corrector.workflow import WorkflowConfig
from tests.helpers import run_workflow


def _run_workflow(cve_data, cve_id, config):
    """Run initialize + finish workflow, return exit code."""
    return run_workflow(cve_data, cve_id, config)


def _make_conflict_repo(make_upstream_repo, make_workspace, recipe, tag):
    """Create upstream + workspace where fix conflicts with devtool patch."""
    bare, hashes = make_upstream_repo(
        files={'src/file.c': 'line1\nline2\nline3\nvulnerable_code\nline5\n'},
        version_tag=tag,
        fix_commits=[{'files': {'src/file.c': 'line1\nline2\nline3\nfixed_code\nline5\n'},
                      'message': 'Fix vulnerability'}])

    # Devtool branch modifies the SAME line → conflict
    ws = make_workspace(bare, recipe, tag,
                        existing_patch_commits=[
                            {'files': {'src/file.c': 'line1\nline2\nline3\npatched_code\nline5\n'},
                             'message': 'Existing recipe patch'}])
    return ws, hashes


class TestConflictExitsWithState:
    """Test 4: Cherry-pick conflicts → exit 1, state saved."""

    def test_conflict_exits_with_state(self, make_upstream_repo, make_workspace,
                                       make_meta_layer, mock_bitbake_env):
        ws, hashes = _make_conflict_repo(make_upstream_repo, make_workspace, 're2c', 'v3.1')
        meta = make_meta_layer('re2c', '3.1',
                               existing_patches={'0001-Existing-recipe-patch.patch': 'p\n'})
        mock_bitbake_env(ws, meta, 're2c', '3.1')

        cve_id = 'CVE-2026-2903'
        cve_data = {cve_id: {
            'name': 're2c', 'hashes': hashes,
            'hash_details': [{'hash': hashes[0], 'url': 'https://example.com/commit/x',
                              'source': 'test'}]}}

        config = WorkflowConfig(
            mirror_path=None, mirror_dir=None, meta_layer=meta,
            skip_build=True, clean=False, skip_ptest=True,
            edit_mode=False, skip_cve_applicability=True)

        exit_code = _run_workflow(cve_data, cve_id, config)
        assert exit_code == EXIT_CONFLICT

        # Verify state was saved
        state_dir = ws.parent.parent / 'cve_corrector'
        state_files = list(state_dir.glob('*.json'))
        assert state_files, "No state file saved"
        state_data = json.loads(state_files[0].read_text())
        assert state_data['cve_id'] == cve_id


class TestAgentConflictLeastConflicts:
    """Test 6: Two hashes both conflict, best one picked."""

    def test_agent_conflict_least_conflicts(self, make_upstream_repo, make_workspace,
                                            make_meta_layer, mock_bitbake_env):
        # Two fix commits that both conflict
        bare, hashes = make_upstream_repo(
            files={'src/file.c': 'line1\nline2\nline3\nvulnerable\nline5\n'},
            version_tag='v1.36.1',
            fix_commits=[
                {'files': {'src/file.c': 'line1\nline2\nline3\nfix_attempt_1\nline5\n'},
                 'message': 'Fix attempt 1'},
                {'files': {'src/file.c': 'line1\nline2\nline3\nfix_attempt_2\nline5\n'},
                 'message': 'Fix attempt 2'},
            ])

        ws = make_workspace(bare, 'busybox', 'v1.36.1',
                            existing_patch_commits=[
                                {'files': {'src/file.c': 'line1\nline2\nline3\nexisting_patch\nline5\n'},
                                 'message': 'Existing patch'}])
        meta = make_meta_layer('busybox', '1.36.1',
                               existing_patches={'0001-Existing-patch.patch': 'p\n'})
        mock_bitbake_env(ws, meta, 'busybox', '1.36.1')

        cve_id = 'CVE-2026-26157'
        cve_data = {cve_id: {
            'name': 'busybox', 'hashes': hashes,
            'hash_details': [{'hash': h, 'url': f'https://example.com/{h}',
                              'source': 'test'} for h in hashes]}}

        config = WorkflowConfig(
            mirror_path=None, mirror_dir=None, meta_layer=meta,
            skip_build=True, clean=False, skip_ptest=True,
            edit_mode=False, skip_cve_applicability=True)

        exit_code = _run_workflow(cve_data, cve_id, config)
        assert exit_code == EXIT_CONFLICT

        # State saved with a commit hash
        state_dir = ws.parent.parent / 'cve_corrector'
        state_files = list(state_dir.glob('*.json'))
        assert state_files
        state_data = json.loads(state_files[0].read_text())
        assert state_data['commit_hash'] in hashes


class TestAgentConflictStateForResume:
    """Test 7: Single hash conflicts, state saved for agent resume."""

    def test_agent_conflict_state_for_resume(self, make_upstream_repo, make_workspace,
                                             make_meta_layer, mock_bitbake_env):
        ws, hashes = _make_conflict_repo(make_upstream_repo, make_workspace,
                                         'coreutils', 'v9.4')
        meta = make_meta_layer('coreutils', '9.4',
                               existing_patches={'0001-Existing-recipe-patch.patch': 'p\n'})
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
        assert exit_code == EXIT_CONFLICT

        state_dir = ws.parent.parent / 'cve_corrector'
        state_data = json.loads(next(state_dir.glob('*.json')).read_text())
        assert state_data['recipe'] == 'coreutils'
        assert state_data['workspace_path'] == str(ws)


class TestSrcUriPlusEqualsConflict:
    """Test 10: Conflict with SRC_URI += block — recipe not corrupted."""

    def test_src_uri_plus_equals_conflict(self, make_upstream_repo, make_workspace,
                                          make_meta_layer, mock_bitbake_env):
        ws, hashes = _make_conflict_repo(make_upstream_repo, make_workspace,
                                         'python3-certifi', 'v2024.2.2')
        meta = make_meta_layer('python3-certifi', '2024.2.2',
                               existing_patches={'0001-Existing-recipe-patch.patch': 'p\n'})
        mock_bitbake_env(ws, meta, 'python3-certifi', '2024.2.2')

        cve_id = 'CVE-2024-39689'
        cve_data = {cve_id: {
            'name': 'python3-certifi', 'hashes': hashes,
            'hash_details': [{'hash': hashes[0], 'url': 'https://example.com/x',
                              'source': 'test'}]}}

        config = WorkflowConfig(
            mirror_path=None, mirror_dir=None, meta_layer=meta,
            skip_build=True, clean=False, skip_ptest=True,
            edit_mode=False, skip_cve_applicability=True)

        exit_code = _run_workflow(cve_data, cve_id, config)
        assert exit_code == EXIT_CONFLICT

        # Verify recipe file is not corrupted
        bb = next(meta.glob('**/*.bb'))
        content = bb.read_text()
        # No orphaned empty SRC_URI blocks
        assert 'SRC_URI += ""' not in content
        assert 'SRC_URI = ""' not in content or 'file://' in content


class TestDevtoolFinishFailureRecovery:
    """Test 11: Cherry-pick succeeds but devtool finish fails → exit 7."""

    def test_devtool_finish_failure_recovery(self, make_upstream_repo, make_workspace,
                                             make_meta_layer, mock_bitbake_env):
        # Clean cherry-pick (no conflict)
        bare, hashes = make_upstream_repo(
            files={'src/ssh.c': 'void connect() { /* vuln */ }\n'},
            version_tag='v9.6p1',
            fix_commits=[{'files': {'src/ssh.c': 'void connect() { /* fixed */ }\n'},
                          'message': 'Fix version comment'}])

        ws = make_workspace(bare, 'openssh', 'v9.6p1')
        meta = make_meta_layer('openssh', '9.6p1')

        # devtool finish will FAIL
        mock_bitbake_env(ws, meta, 'openssh', '9.6p1', devtool_finish_fails=True)

        cve_id = 'CVE-2024-39894'
        cve_data = {cve_id: {
            'name': 'openssh', 'hashes': hashes,
            'hash_details': [{'hash': hashes[0], 'url': 'https://example.com/x',
                              'source': 'test'}]}}

        config = WorkflowConfig(
            mirror_path=None, mirror_dir=None, meta_layer=meta,
            skip_build=True, clean=False, skip_ptest=True,
            edit_mode=False, skip_cve_applicability=True)

        exit_code = _run_workflow(cve_data, cve_id, config)
        assert exit_code == EXIT_GIT_ERROR


class TestCrossRecipeSharedPatchConflict:
    """Test 15: Two recipes share patches, cherry-pick conflicts."""

    def test_cross_recipe_shared_patch_conflict(self, make_upstream_repo, make_workspace,
                                                make_meta_layer, mock_bitbake_env, tmp_path):
        ws, hashes = _make_conflict_repo(make_upstream_repo, make_workspace,
                                         'libsoup-2.4', 'v2.74.3')

        # Create meta-layer with TWO recipes sharing the same patch
        meta = tmp_path / 'meta-layer'
        meta.mkdir()
        from tests.helpers import git
        git(meta, 'init')
        git(meta, 'commit', '--allow-empty', '-m', 'init')

        for recipe_name in ('libsoup-2.4', 'libsoup'):
            recipe_dir = meta / 'recipes-core' / recipe_name
            recipe_dir.mkdir(parents=True)
            version = '2.74.3' if '2.4' in recipe_name else '3.4.4'
            bb = recipe_dir / f'{recipe_name}_{version}.bb'
            bb.write_text(
                f'SUMMARY = "{recipe_name}"\n'
                'SRC_URI = " \\\n'
                '           file://shared.patch \\\n'
                '           "\n')
            (recipe_dir / 'shared.patch').write_text('shared patch content\n')

        git(meta, 'add', '-A')
        git(meta, 'commit', '-m', 'Add recipes')

        mock_bitbake_env(ws, meta, 'libsoup-2.4', '2.74.3')

        cve_id = 'CVE-2025-32909'
        cve_data = {cve_id: {
            'name': 'libsoup-2.4', 'hashes': hashes,
            'hash_details': [{'hash': hashes[0], 'url': 'https://example.com/x',
                              'source': 'test'}]}}

        config = WorkflowConfig(
            mirror_path=None, mirror_dir=None, meta_layer=meta,
            skip_build=True, clean=False, skip_ptest=True,
            edit_mode=False, skip_cve_applicability=True)

        exit_code = _run_workflow(cve_data, cve_id, config)
        assert exit_code == EXIT_CONFLICT
