# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Pytest equivalents of test_cve_corrector_cases.sh — monorepo scenarios.

Shell test mapping:
  Test 9  -> test_monorepo_strip_level (CVE-2024-47539 / gstreamer1.0-plugins-good)
  Test 13 -> test_monorepo_with_build (CVE-2024-44331 / gstreamer1.0-rtsp-server)
  Test 17 -> test_monorepo_build_verification (CVE-2024-47539 / gstreamer1.0-plugins-good)
"""

from cve_corrector.workflow import WorkflowConfig
from tests.helpers import (
    assert_no_patches_removed,
    assert_patch_correctness,
    assert_patch_naming,
    get_src_uri_patches,
    git,
    run_workflow,
)


def _run_workflow(cve_data, cve_id, config):
    """Run initialize + finish workflow, return exit code."""
    return run_workflow(cve_data, cve_id, config)


def _make_monorepo(make_upstream_repo, make_workspace, tmp_path, recipe, mirror_name,
                   version_tag):
    """Create a monorepo upstream and a workspace with extracted subproject."""
    prefix = f'subprojects/{mirror_name}'

    # Upstream: monorepo with subprojects/<name>/meson.build
    bare, hashes = make_upstream_repo(
        files={'gst/rtpmanager/file.c': 'void process() { /* vuln */ }\n',
               'meson.build': "project('gst-plugins-good')\n"},
        version_tag=version_tag,
        fix_commits=[{'files': {'gst/rtpmanager/file.c': 'void process() { /* fixed */ }\n'},
                      'message': 'Fix buffer overflow in rtpmanager'}],
        monorepo_prefix=prefix)

    # Workspace: extracted subproject (gst/ at root, not subprojects/...)
    ws = tmp_path / 'build' / 'workspace' / 'sources' / recipe
    git(tmp_path, 'clone', str(bare), str(ws))

    # Create main branch with ONLY the subproject content at root
    git(ws, 'checkout', '-b', 'extract', version_tag)
    # Read the file from the subproject path and put it at root
    (ws / prefix / 'gst' / 'rtpmanager' / 'file.c').read_text()
    meson_content = (ws / prefix / 'meson.build').read_text()

    git(ws, 'branch', '-D', 'main')
    git(ws, 'checkout', '--orphan', 'main')
    # Remove everything
    import shutil
    for item in ws.iterdir():
        if item.name == '.git':
            continue
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()

    # Create extracted layout
    (ws / 'gst' / 'rtpmanager').mkdir(parents=True)
    (ws / 'gst' / 'rtpmanager' / 'file.c').write_text('void process() { /* vuln */ }\n')
    (ws / 'meson.build').write_text(meson_content)
    git(ws, 'add', '-A')
    git(ws, 'commit', '-m', 'Extracted subproject')

    git(ws, 'branch', 'devtool-base')
    git(ws, 'checkout', '-b', 'devtool')

    # Add upstream remote
    git(ws, 'remote', 'rename', 'origin', 'upstream')
    git(ws, 'fetch', 'upstream', '--tags')

    return ws, bare, hashes


class TestMonorepoStripLevel:
    """Test 9: Monorepo subprojects/ path stripping with skip-build-ptest."""

    def test_monorepo_strip_level(self, make_upstream_repo, make_workspace,
                                  make_meta_layer, mock_bitbake_env, tmp_path):
        recipe = 'gstreamer1.0-plugins-good'
        mirror_name = 'gst-plugins-good'
        ws, bare, hashes = _make_monorepo(
            make_upstream_repo, make_workspace, tmp_path,
            recipe, mirror_name, '1.24.0')

        meta = make_meta_layer(recipe, '1.24.0')
        before = get_src_uri_patches(meta, recipe)
        mock_bitbake_env(ws, meta, recipe, '1.24.0')

        cve_id = 'CVE-2024-47539'
        cve_data = {cve_id: {
            'name': recipe, 'hashes': hashes,
            'hash_details': [{'hash': hashes[0],
                              'url': f'https://gitlab.freedesktop.org/gstreamer/gstreamer/-/commit/{hashes[0]}',
                              'source': 'test'}]}}

        config = WorkflowConfig(
            mirror_path=bare, mirror_dir=bare.parent, meta_layer=meta,
            skip_build=True, clean=False, skip_ptest=True,
            edit_mode=False, skip_cve_applicability=True)

        exit_code = _run_workflow(cve_data, cve_id, config)

        assert exit_code == 0
        assert_patch_naming(meta, cve_id, expect_series=False)
        after = get_src_uri_patches(meta, recipe)
        assert_no_patches_removed(before, after)
        assert_patch_correctness(meta, cve_id,
                                 expected_files={'gst/rtpmanager/file.c'})


class TestMonorepoWithBuild:
    """Test 13: Monorepo with build step (agent perspective)."""

    def test_monorepo_with_build(self, make_upstream_repo, make_workspace,
                                 make_meta_layer, mock_bitbake_env, tmp_path):
        recipe = 'gstreamer1.0-rtsp-server'
        mirror_name = 'gst-plugins-bad'
        ws, bare, hashes = _make_monorepo(
            make_upstream_repo, make_workspace, tmp_path,
            recipe, mirror_name, '1.22.0')

        meta = make_meta_layer(recipe, '1.22.0')
        build_called = mock_bitbake_env(ws, meta, recipe, '1.22.0')

        cve_id = 'CVE-2024-44331'
        cve_data = {cve_id: {
            'name': recipe, 'hashes': hashes,
            'hash_details': [{'hash': hashes[0],
                              'url': f'https://gitlab.freedesktop.org/gstreamer/gstreamer/-/commit/{hashes[0]}',
                              'source': 'test'}]}}

        config = WorkflowConfig(
            mirror_path=bare, mirror_dir=bare.parent, meta_layer=meta,
            skip_build=False, clean=False, skip_ptest=True,
            edit_mode=False, skip_cve_applicability=True)

        exit_code = _run_workflow(cve_data, cve_id, config)

        assert exit_code == 0
        assert len(build_called) > 0, "devtool build was not called"
        assert_patch_naming(meta, cve_id, expect_series=False)


class TestMonorepoBuildVerification:
    """Test 17: Monorepo build verification (same as 9 but with build)."""

    def test_monorepo_build_verification(self, make_upstream_repo, make_workspace,
                                         make_meta_layer, mock_bitbake_env, tmp_path):
        recipe = 'gstreamer1.0-plugins-good'
        mirror_name = 'gst-plugins-good'
        ws, bare, hashes = _make_monorepo(
            make_upstream_repo, make_workspace, tmp_path,
            recipe, mirror_name, '1.24.0')

        meta = make_meta_layer(recipe, '1.24.0')
        build_called = mock_bitbake_env(ws, meta, recipe, '1.24.0')

        cve_id = 'CVE-2024-47539'
        cve_data = {cve_id: {
            'name': recipe, 'hashes': hashes,
            'hash_details': [{'hash': hashes[0],
                              'url': f'https://gitlab.freedesktop.org/gstreamer/gstreamer/-/commit/{hashes[0]}',
                              'source': 'test'}]}}

        config = WorkflowConfig(
            mirror_path=bare, mirror_dir=bare.parent, meta_layer=meta,
            skip_build=False, clean=False, skip_ptest=True,
            edit_mode=False, skip_cve_applicability=True)

        exit_code = _run_workflow(cve_data, cve_id, config)

        assert exit_code == 0
        assert len(build_called) > 0, "devtool build was not called"
        assert_patch_naming(meta, cve_id, expect_series=False)
        assert_patch_correctness(meta, cve_id,
                                 expected_files={'gst/rtpmanager/file.c'})
