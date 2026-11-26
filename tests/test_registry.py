"""Registry client tests: HTTP outcomes, cache, TTL, offline mode, injection."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from slopsquat_guard.registry import FetchError, RegistryClient
from tests.helpers import FakeFetcher, cache_entry, fixed_now, make_client, write_cache


class HttpOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tmp_path = Path(self.tmp.name)

    def test_200_means_exists(self):
        client = make_client(self.tmp_path, existing={"requests"})
        result = client.check("pypi", "requests")
        self.assertTrue(result.exists)
        self.assertEqual(result.status, 200)
        self.assertEqual(result.source, "network")
        self.assertEqual(result.version, "1.2.3")

    def test_404_means_missing(self):
        client = make_client(self.tmp_path, existing=set())
        result = client.check("pypi", "openai-toolkit-x")
        self.assertIs(result.exists, False)
        self.assertEqual(result.status, 404)

    def test_500_is_unverified_not_missing(self):
        client = RegistryClient(
            fetcher=FakeFetcher(status_map={"requests": 500}),
            cache_path=self.tmp_path / "cache.json",
            now=fixed_now(),
        )
        result = client.check("pypi", "requests")
        self.assertIsNone(result.exists)
        self.assertEqual(result.status, 500)
        self.assertEqual(result.source, "error")
        self.assertIn("unexpected registry status", result.note)

    def test_network_error_is_unverified(self):
        client = RegistryClient(
            fetcher=FakeFetcher(error_names={"requests"}),
            cache_path=self.tmp_path / "cache.json",
            now=fixed_now(),
        )
        result = client.check("pypi", "requests")
        self.assertIsNone(result.exists)
        self.assertEqual(result.source, "error")
        self.assertIn("simulated network failure", result.note)

    def test_npm_scoped_name_is_url_encoded(self):
        fetcher = FakeFetcher(existing={"@types/node"})
        client = RegistryClient(fetcher=fetcher, cache_path=self.tmp_path / "cache.json", now=fixed_now())
        result = client.check("npm", "@types/node")
        self.assertTrue(result.exists)
        self.assertIn("%2F", fetcher.calls[0])

    def test_unknown_ecosystem_raises(self):
        client = make_client(self.tmp_path)
        with self.assertRaises(ValueError):
            client.check("maven", "x")


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tmp_path = Path(self.tmp.name)
        self.cache_path = self.tmp_path / "cache.json"

    def test_second_check_uses_cache_not_network(self):
        fetcher = FakeFetcher(existing={"requests"})
        client = RegistryClient(fetcher=fetcher, cache_path=self.cache_path, now=fixed_now())
        client.check("pypi", "requests")
        client.check("pypi", "requests")
        self.assertEqual(len(fetcher.calls), 1)
        self.assertEqual(client.calls["cache"], 1)

    def test_cache_survives_new_client(self):
        first = RegistryClient(fetcher=FakeFetcher(existing={"requests"}), cache_path=self.cache_path, now=fixed_now())
        first.check("pypi", "requests")
        first.save()
        second_fetcher = FakeFetcher(existing=set())
        second = RegistryClient(fetcher=second_fetcher, cache_path=self.cache_path, now=fixed_now())
        result = second.check("pypi", "requests")
        self.assertTrue(result.exists)
        self.assertEqual(result.source, "cache")
        self.assertEqual(second_fetcher.calls, [])

    def test_expired_cache_triggers_refetch(self):
        first = RegistryClient(fetcher=FakeFetcher(existing={"requests"}), cache_path=self.cache_path, now=fixed_now())
        first.check("pypi", "requests")
        first.save()
        later_fetcher = FakeFetcher(existing={"requests"})
        later = RegistryClient(fetcher=later_fetcher, cache_path=self.cache_path, now=fixed_now(8))
        result = later.check("pypi", "requests")
        self.assertEqual(result.source, "network")
        self.assertEqual(len(later_fetcher.calls), 1)

    def test_refresh_ignores_fresh_cache(self):
        first = RegistryClient(fetcher=FakeFetcher(existing={"requests"}), cache_path=self.cache_path, now=fixed_now())
        first.check("pypi", "requests")
        first.save()
        fetcher = FakeFetcher(existing={"requests"})
        refreshed = RegistryClient(fetcher=fetcher, cache_path=self.cache_path, refresh=True, now=fixed_now())
        result = refreshed.check("pypi", "requests")
        self.assertEqual(result.source, "network")
        self.assertEqual(len(fetcher.calls), 1)

    def test_offline_uses_cache(self):
        write_cache(self.cache_path, {"pypi:nonexistent-x": cache_entry(False, 404)})
        fetcher = FakeFetcher(existing=set())
        client = RegistryClient(fetcher=fetcher, cache_path=self.cache_path, offline=True, now=fixed_now())
        result = client.check("pypi", "nonexistent-x")
        self.assertIs(result.exists, False)
        self.assertEqual(result.source, "cache-offline")
        self.assertEqual(fetcher.calls, [])

    def test_offline_miss_is_unverified(self):
        client = RegistryClient(fetcher=FakeFetcher(), cache_path=self.cache_path, offline=True, now=fixed_now())
        result = client.check("pypi", "unknown")
        self.assertIsNone(result.exists)
        self.assertEqual(result.source, "offline-miss")

    def test_offline_does_not_write_cache(self):
        client = RegistryClient(fetcher=FakeFetcher(), cache_path=self.cache_path, offline=True, now=fixed_now())
        client.check("pypi", "unknown")
        client.save()
        self.assertFalse(self.cache_path.exists())

    def test_malformed_cache_is_tolerated(self):
        self.cache_path.write_text("not json at all", encoding="utf-8")
        client = RegistryClient(fetcher=FakeFetcher(existing={"requests"}), cache_path=self.cache_path, now=fixed_now())
        self.assertTrue(client.check("pypi", "requests").exists)

    def test_cache_snapshot_shape(self):
        client = make_client(self.tmp_path, existing={"requests"})
        client.check("pypi", "requests")
        snapshot = client.cache_snapshot()
        self.assertEqual(snapshot["version"], 1)
        self.assertIn("pypi:requests", snapshot["entries"])
        json.dumps(snapshot)


if __name__ == "__main__":
    unittest.main()
