# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Validate conftest fixtures work correctly."""
import subprocess

from tests.helpers import devtool_finish_sim, get_src_uri_patches, git


class TestMakeUpstreamRepo:
    def test_creates_bare_repo_with_tag(self, make_upstream_repo):
        bare, hashes = make_upstream_repo(
            files={'src/file.c': 'int main() { return 0; }\n'},
            version_tag='v1.0',
            fix_commits=[{'files': {'src/file.c': 'int main() { return 1; }\n'},
                          'message': 'Fix bug'}])
        assert bare.exists()
        assert len(hashes) == 1
        # Verify tag exists in bare repo
        result = subprocess.run(['git', 'tag'], cwd=bare, capture_output=True, text=True)
        assert 'v1.0' in result.stdout

    def test_multiple_fix_commits(self, make_upstream_repo):
        bare, hashes = make_upstream_repo(
            files={'a.c': 'a\n'},
            version_tag='v2.0',
            fix_commits=[
                {'files': {'a.c': 'b\n'}, 'message': 'Fix 1'},
                {'files': {'a.c': 'c\n'}, 'message': 'Fix 2'},
            ])
        assert len(hashes) == 2
        assert hashes[0] != hashes[1]

    def test_monorepo_prefix(self, make_upstream_repo):
        bare, hashes = make_upstream_repo(
            files={'gst/file.c': 'code\n', 'meson.build': 'project()\n'},
            version_tag='1.24.0',
            fix_commits=[{'files': {'gst/file.c': 'fixed\n'}, 'message': 'Fix'}],
            monorepo_prefix='subprojects/gst-plugins-good')
        # Verify the file is at the prefixed path
        work = bare.parent / 'upstream_work'
        assert (work / 'subprojects' / 'gst-plugins-good' / 'gst' / 'file.c').exists()


class TestMakeWorkspace:
    def test_branch_structure(self, make_upstream_repo, make_workspace):
        bare, hashes = make_upstream_repo(
            files={'src/file.c': 'original\n'},
            version_tag='v1.0',
            fix_commits=[{'files': {'src/file.c': 'fixed\n'}, 'message': 'Fix'}])
        ws = make_workspace(bare, 'testrecipe', 'v1.0')

        # Verify branches exist
        result = git(ws, 'branch', '--list')
        assert 'main' in result.stdout
        assert 'devtool' in result.stdout
        assert 'devtool-base' in result.stdout

        # Verify upstream remote
        result = git(ws, 'remote')
        assert 'upstream' in result.stdout

        # Verify main is at version tag
        git(ws, 'checkout', 'main')
        assert (ws / 'src' / 'file.c').read_text() == 'original\n'

    def test_existing_patch_commits(self, make_upstream_repo, make_workspace):
        bare, _ = make_upstream_repo(
            files={'src/file.c': 'original\n'},
            version_tag='v1.0',
            fix_commits=[])
        ws = make_workspace(bare, 'testrecipe', 'v1.0',
                            existing_patch_commits=[
                                {'files': {'src/extra.c': 'patch\n'},
                                 'message': 'Existing patch'}])
        git(ws, 'checkout', 'devtool')
        assert (ws / 'src' / 'extra.c').exists()
        git(ws, 'checkout', 'main')
        assert not (ws / 'src' / 'extra.c').exists()


class TestMakeMetaLayer:
    def test_creates_recipe(self, make_meta_layer):
        meta = make_meta_layer('busybox', '1.36.1',
                               existing_patches={'existing.patch': 'patch content\n'},
                               src_uri_entries=['file://defconfig'])
        bb = next(meta.glob('**/*.bb'))
        content = bb.read_text()
        assert 'file://defconfig' in content
        assert 'file://existing.patch' in content
        assert (bb.parent / 'existing.patch').exists()

    def test_is_git_repo(self, make_meta_layer):
        meta = make_meta_layer('foo', '1.0')
        result = git(meta, 'log', '--oneline')
        assert result.returncode == 0


class TestDevtoolFinishSim:
    def test_copies_patches_as_untracked(self, make_upstream_repo, make_workspace,
                                         make_meta_layer):
        bare, _ = make_upstream_repo(
            files={'src/file.c': 'original\n'},
            version_tag='v1.0', fix_commits=[])
        ws = make_workspace(bare, 'myrecipe', 'v1.0',
                            existing_patch_commits=[
                                {'files': {'src/file.c': 'patched\n'},
                                 'message': 'Add patch'}])
        meta = make_meta_layer('myrecipe', '1.0')

        rc = devtool_finish_sim(ws, meta, 'myrecipe')
        assert rc == 0

        # Patches should be untracked in meta-layer
        result = git(meta, 'ls-files', '--others', '--exclude-standard')
        assert '.patch' in result.stdout

        # SRC_URI should reference the patch
        patches = get_src_uri_patches(meta, 'myrecipe')
        assert len(patches) >= 1
