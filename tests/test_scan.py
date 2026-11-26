"""Scan orchestration tests with an injected (mocked) registry fetcher."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from slopsquat_guard import scan_path, verify_package
from slopsquat_guard.registry import RegistryClient
from tests.helpers import FakeFetcher, fixed_now, make_popular

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "llm_manifest"
EXISTING = {
    "requests",
    "flask",
    "pydantic",
    "fastapi",
    "httpx",
    "pytest",
    "setuptools",
    "react",
    "lodash",
    "typescript",
    "langchain-core",
    "pillow",
    "pyyaml",
}


def scan_with(existing=None, error_names=None, allow=()):
    tmp = tempfile.TemporaryDirectory()
    client = RegistryClient(
        fetcher=FakeFetcher(existing=existing or EXISTING, error_names=error_names or set()),
        cache_path=Path(tmp.name) / "cache.json",
        now=fixed_now(),
    )
    result = scan_path(EXAMPLES, client=client, popular=make_popular(), allow=allow)
    return result, client, tmp


class ScanFindingTests(unittest.TestCase):
    def test_invented_names_are_high_not_found(self):
        result, _, tmp = scan_with()
        with tmp:
            codes = {(finding["name"], finding["code"]) for finding in result["findings"]}
            for name in ("openai-toolkit-x", "pandas-profiling-plus", "llm-utils-magic"):
                self.assertIn((name, "SQ-NOT-FOUND"), codes)
            self.assertEqual(result["summary"]["not_found"], 11)

    def test_real_packages_are_not_flagged(self):
        result, _, tmp = scan_with()
        with tmp:
            flagged = {finding["name"] for finding in result["findings"]}
            for name in ("requests", "flask", "pydantic", "fastapi", "httpx", "react", "lodash", "typescript"):
                self.assertNotIn(name, flagged)

    def test_typo_names_are_high_typosquat(self):
        result, _, tmp = scan_with()
        with tmp:
            typos = {finding["name"]: finding for finding in result["findings"] if finding["code"] == "SQ-TYPOSQUAT"}
            self.assertIn("reqeusts", typos)
            self.assertIn("numpyy", typos)
            self.assertIn("flassk", typos)
            self.assertEqual(typos["reqeusts"]["severity"], "high")
            self.assertEqual(typos["reqeusts"]["data"]["near_miss"]["target"], "requests")

    def test_existing_typosquat_is_medium(self):
        existing = set(EXISTING) | {"reqeusts"}
        result, _, tmp = scan_with(existing=existing)
        with tmp:
            finding = [item for item in result["findings"] if item["name"] == "reqeusts"][0]
            self.assertEqual(finding["code"], "SQ-TYPOSQUAT")
            self.assertEqual(finding["severity"], "medium")

    def test_network_error_is_low_unverified(self):
        result, _, tmp = scan_with(error_names={"openai-toolkit-x"})
        with tmp:
            finding = [item for item in result["findings"] if item["name"] == "openai-toolkit-x"][0]
            self.assertEqual(finding["code"], "SQ-UNVERIFIED")
            self.assertEqual(finding["severity"], "low")
            self.assertEqual(result["summary"]["unverified"], 1)

    def test_allowlist_skips_names(self):
        result, _, tmp = scan_with(allow=["openai-toolkit-x", "reqeusts"])
        with tmp:
            names = {finding["name"] for finding in result["findings"]}
            self.assertNotIn("openai-toolkit-x", names)
            self.assertNotIn("reqeusts", names)
            self.assertEqual(result["summary"]["allowed"], 2)

    def test_import_name_finding_is_marked_import_only(self):
        result, _, tmp = scan_with()
        with tmp:
            finding = [item for item in result["findings"] if item["name"] == "llm_utils_magic"][0]
            self.assertEqual(finding["data"]["origin"], "import")
            self.assertIn("import-only", finding["message"])

    def test_dependencies_are_sorted_deterministically(self):
        first, _, tmp = scan_with()
        with tmp:
            second, _, tmp2 = scan_with()
            with tmp2:
                self.assertEqual(
                    [(item["source_file"], item["line"], item["normalized"]) for item in first["dependencies"]],
                    [(item["source_file"], item["line"], item["normalized"]) for item in second["dependencies"]],
                )
                self.assertEqual(first["findings"], second["findings"])

    def test_summary_counts_are_consistent(self):
        result, _, tmp = scan_with()
        with tmp:
            summary = result["summary"]
            self.assertEqual(summary["dependencies"], len(result["dependencies"]))
            self.assertEqual(
                summary["verified_existing"] + summary["not_found"] + summary["unverified"] + summary["allowed"],
                summary["dependencies"],
            )
            self.assertEqual(summary["total"], len(result["findings"]))

    def test_manifests_only_skips_imports(self):
        tmp = tempfile.TemporaryDirectory()
        with tmp:
            client = RegistryClient(fetcher=FakeFetcher(existing=EXISTING), cache_path=Path(tmp.name) / "c.json", now=fixed_now())
            result = scan_path(EXAMPLES, client=client, popular=make_popular(), include_imports=False)
            origins = {dependency["origin"] for dependency in result["dependencies"]}
            self.assertNotIn("import", origins)


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.client = RegistryClient(
            fetcher=FakeFetcher(existing={"requests"}),
            cache_path=Path(self.tmp.name) / "cache.json",
            now=fixed_now(),
        )

    def test_verify_missing_name(self):
        result = verify_package("reqeusts", "pypi", client=self.client, popular=make_popular())
        self.assertFalse(result["registry"]["exists"])
        self.assertEqual(result["finding"]["code"], "SQ-TYPOSQUAT")
        self.assertEqual(result["finding"]["severity"], "high")

    def test_verify_existing_name(self):
        result = verify_package("requests", "pypi", client=self.client, popular=make_popular())
        self.assertTrue(result["registry"]["exists"])
        self.assertIsNone(result["finding"])
        self.assertTrue(result["in_popular_list"])

    def test_verify_unknown_existing_name(self):
        client = RegistryClient(
            fetcher=FakeFetcher(existing={"requests", "some-unlisted-package"}),
            cache_path=Path(self.tmp.name) / "cache2.json",
            now=fixed_now(),
        )
        result = verify_package("some-unlisted-package", "pypi", client=client, popular=make_popular())
        self.assertTrue(result["registry"]["exists"])
        self.assertIsNone(result["finding"])

    def test_verify_invalid_ecosystem(self):
        with self.assertRaises(ValueError):
            verify_package("x", "maven", client=self.client)

    def test_verify_empty_name(self):
        with self.assertRaises(ValueError):
            verify_package("  ", "pypi", client=self.client)


if __name__ == "__main__":
    unittest.main()
