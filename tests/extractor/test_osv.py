# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
'''Tests for OSV source extractor.'''
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from cve_metadata_extractor.osv import (
    OSVSource,
    extract_from_osv_response,
    get_osv_vuln,
    guess_ecosystem,
)


class TestGuessEcosystem(unittest.TestCase):
    '''Test ecosystem heuristic mapping.'''

    def test_python3_prefix(self):
        self.assertEqual(guess_ecosystem('python3-cryptography'), 'PyPI')

    def test_golang_prefix(self):
        self.assertEqual(guess_ecosystem('golang-github.com-foo'), 'Go')

    def test_go_prefix(self):
        self.assertEqual(guess_ecosystem('go-stdlib'), 'Go')

    def test_nodejs_prefix(self):
        self.assertEqual(guess_ecosystem('nodejs-express'), 'npm')

    def test_node_prefix(self):
        self.assertEqual(guess_ecosystem('node-semver'), 'npm')

    def test_ruby_prefix(self):
        self.assertEqual(guess_ecosystem('ruby-rails'), 'RubyGems')

    def test_perl_prefix(self):
        self.assertEqual(guess_ecosystem('perl-module'), 'CPAN')

    def test_no_match(self):
        self.assertIsNone(guess_ecosystem('openssl'))

    def test_empty(self):
        self.assertIsNone(guess_ecosystem(''))

    def test_none(self):
        self.assertIsNone(guess_ecosystem(None))


class TestGetOsvVuln(unittest.TestCase):
    '''Test OSV API client with caching.'''

    def test_caches_response(self):
        '''API response is cached to file.'''
        with tempfile.TemporaryDirectory() as tmpdir:
            osv_data = {'id': 'CVE-2024-1234', 'affected': []}
            with patch('cve_metadata_extractor.osv.requests.get') as mock_get:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = osv_data
                mock_resp.raise_for_status = MagicMock()
                mock_get.return_value = mock_resp

                result = get_osv_vuln(tmpdir, 'CVE-2024-1234')
                self.assertEqual(result, osv_data)
                self.assertTrue(
                    os.path.isfile(
                        os.path.join(tmpdir, 'CVE-2024-1234-osv.json.gz')))

    def test_uses_cache_on_second_call(self):
        '''Second call reads from cache, no API request.'''
        with tempfile.TemporaryDirectory() as tmpdir:
            osv_data = {'id': 'CVE-2024-1234', 'affected': []}
            cache_file = os.path.join(tmpdir, 'CVE-2024-1234-osv.json')
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(osv_data, f)

            with patch('cve_metadata_extractor.osv.requests.get') as mock_get:
                result = get_osv_vuln(tmpdir, 'CVE-2024-1234')
                self.assertEqual(result, osv_data)
                mock_get.assert_not_called()

    def test_refresh_bypasses_cache(self):
        '''refresh=True re-fetches even if cache exists.'''
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = os.path.join(tmpdir, 'CVE-2024-1234-osv.json')
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump({'old': True}, f)

            new_data = {'id': 'CVE-2024-1234', 'refreshed': True}
            with patch('cve_metadata_extractor.osv.requests.get') as mock_get:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = new_data
                mock_resp.raise_for_status = MagicMock()
                mock_get.return_value = mock_resp

                result = get_osv_vuln(tmpdir, 'CVE-2024-1234', refresh=True)
                self.assertEqual(result, new_data)
                mock_get.assert_called_once()

    def test_404_returns_empty_dict(self):
        '''404 response caches and returns empty dict.'''
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('cve_metadata_extractor.osv.requests.get') as mock_get:
                mock_resp = MagicMock()
                mock_resp.status_code = 404
                mock_get.return_value = mock_resp

                result = get_osv_vuln(tmpdir, 'CVE-9999-0000')
                self.assertEqual(result, {})
                # Verify empty dict was cached
                cache_file = os.path.join(tmpdir, 'CVE-9999-0000-osv.json')
                from shared.json_cache import cache_load
                self.assertEqual(cache_load(cache_file), {})


class TestExtractFromOsvResponse(unittest.TestCase):
    '''Test metadata extraction from OSV response.'''

    def test_extract_git_fix_commits(self):
        '''Extract fix hashes from GIT range events.'''
        osv_data = {
            'affected': [{
                'ranges': [{
                    'type': 'GIT',
                    'repo': 'https://github.com/test/repo',
                    'events': [
                        {'introduced': '0'},
                        {'fixed': 'abc123def456789'}
                    ]
                }]
            }]
        }
        patch_links, hashes, _, _ = extract_from_osv_response(osv_data)
        self.assertEqual(len(hashes), 1)
        self.assertEqual(hashes[0]['hash'], 'abc123def456789')
        self.assertIn('https://github.com/test/repo/commit/abc123def456789',
                      hashes[0]['url'])
        self.assertGreater(len(patch_links), 0)

    def test_extract_fix_references(self):
        '''Extract URLs from references with type FIX.'''
        osv_data = {
            'affected': [],
            'references': [
                {'type': 'FIX',
                 'url': 'https://github.com/test/repo/commit/deadbeef123'},
                {'type': 'WEB', 'url': 'https://example.com/advisory'},
            ]
        }
        patch_links, hashes, _, references = extract_from_osv_response(
            osv_data)
        self.assertEqual(len(patch_links), 1)
        self.assertEqual(patch_links[0]['url'],
                         'https://github.com/test/repo/commit/deadbeef123')
        self.assertEqual(len(hashes), 1)
        self.assertEqual(hashes[0]['hash'], 'deadbeef123')
        # Both references should be in the references list
        self.assertEqual(len(references), 2)

    def test_extract_patch_references(self):
        '''Extract URLs from references with type PATCH.'''
        osv_data = {
            'affected': [],
            'references': [
                {'type': 'PATCH',
                 'url': 'https://github.com/test/repo/commit/cafe1234'},
            ]
        }
        patch_links, hashes, _, _ = extract_from_osv_response(osv_data)
        self.assertEqual(len(patch_links), 1)
        self.assertEqual(hashes[0]['hash'], 'cafe1234')

    def test_pr_url_creates_series(self):
        '''PR URLs in FIX references are processed into series.'''
        osv_data = {
            'affected': [],
            'references': [
                {'type': 'FIX',
                 'url': 'https://github.com/test/repo/pull/42'},
            ]
        }
        with patch('cve_metadata_extractor.osv.process_pr_url') as mock_pr:
            extract_from_osv_response(osv_data)
            mock_pr.assert_called_once()

    def test_empty_response(self):
        '''Empty dict returns empty results.'''
        patch_links, hashes, series, refs = extract_from_osv_response({})
        self.assertEqual(patch_links, [])
        self.assertEqual(hashes, [])
        self.assertEqual(series, [])
        self.assertEqual(refs, [])

    def test_no_duplicate_hashes(self):
        '''Hash from GIT range is not duplicated from FIX reference.'''
        osv_data = {
            'affected': [{
                'ranges': [{
                    'type': 'GIT',
                    'repo': 'https://github.com/test/repo',
                    'events': [{'fixed': 'abc123def456'}]
                }]
            }],
            'references': [
                {'type': 'FIX',
                 'url': 'https://github.com/test/repo/commit/abc123def456'},
            ]
        }
        _, hashes, _, _ = extract_from_osv_response(osv_data)
        self.assertEqual(len(hashes), 1)


class TestOSVSource(unittest.TestCase):
    '''Test OSVSource class integration.'''

    def test_is_enabled_default(self):
        '''OSV is enabled by default.'''
        args = MagicMock()
        args.no_osv = False
        source = OSVSource()
        self.assertTrue(source.is_enabled(args))

    def test_is_disabled_with_flag(self):
        '''OSV is disabled with --no-osv.'''
        args = MagicMock()
        args.no_osv = True
        source = OSVSource()
        self.assertFalse(source.is_enabled(args))

    def test_extract_tags_results(self):
        '''Extract returns results tagged with source osv.'''
        with tempfile.TemporaryDirectory() as tmpdir:
            osv_data = {
                'affected': [{
                    'ranges': [{
                        'type': 'GIT',
                        'repo': 'https://github.com/test/repo',
                        'events': [{'fixed': 'abc123def456'}]
                    }]
                }],
                'references': []
            }
            source = OSVSource()
            source._cache = tmpdir
            source._refresh = False

            with patch('cve_metadata_extractor.osv.get_osv_vuln',
                       return_value=osv_data):
                stats = {'osv_hashes': 0, 'osv_patches': 0}
                hashes, patches, _, _ = source.extract('CVE-2024-1234', stats)
                self.assertEqual(len(hashes), 1)
                self.assertEqual(hashes[0]['source'], 'osv')
                self.assertEqual(stats['osv_hashes'], 1)

    def test_deduce_component_from_cache(self):
        '''deduce_component reads package name from cached OSV data.'''
        with tempfile.TemporaryDirectory() as tmpdir:
            osv_data = {
                'affected': [{
                    'package': {'name': 'nghttp2', 'ecosystem': 'Linux'}
                }]
            }
            cache_file = os.path.join(tmpdir, 'CVE-2024-1234-osv.json')
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(osv_data, f)

            source = OSVSource()
            result = source.deduce_component('CVE-2024-1234', tmpdir)
            self.assertEqual(result, 'nghttp2')

    def test_deduce_component_no_cache(self):
        '''deduce_component returns None when no cache file.'''
        with tempfile.TemporaryDirectory() as tmpdir:
            source = OSVSource()
            result = source.deduce_component('CVE-2024-9999', tmpdir)
            self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
