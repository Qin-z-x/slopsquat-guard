"""Validate emitted JSON against the published JSON Schemas."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from slopsquat_guard import scan_path, verify_package
from slopsquat_guard.registry import RegistryClient
from tests.helpers import FakeFetcher, fixed_now, make_popular
from tests.schema_lite import validate

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
EXAMPLES = ROOT / "examples" / "llm_manifest"


def load_schema(name: str) -> dict:
    return json.loads((DOCS / name).read_text(encoding="utf-8"))


class SchemaTests(unittest.TestCase):
    def test_schemas_are_valid_json(self):
        for name in ("finding.schema.json", "scan-result.schema.json", "verify-result.schema.json"):
            schema = load_schema(name)
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_scan_result_matches_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            client = RegistryClient(
                fetcher=FakeFetcher(existing={"requests", "flask"}),
                cache_path=Path(directory) / "cache.json",
                now=fixed_now(),
            )
            result = scan_path(EXAMPLES, client=client, popular=make_popular())
        schema = load_schema("scan-result.schema.json")
        self.assertEqual(validate(result, schema), [])
        finding_schema = load_schema("finding.schema.json")
        for finding in result["findings"]:
            self.assertEqual(validate(finding, finding_schema), [])

    def test_verify_result_matches_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            client = RegistryClient(
                fetcher=FakeFetcher(existing=set()),
                cache_path=Path(directory) / "cache.json",
                now=fixed_now(),
            )
            result = verify_package("reqeusts", "pypi", client=client, popular=make_popular())
        self.assertEqual(validate(result, load_schema("verify-result.schema.json")), [])

    def test_schema_rejects_bad_finding(self):
        schema = load_schema("finding.schema.json")
        bad = {
            "code": "NOPE",
            "severity": "critical",
            "ecosystem": "maven",
            "name": "",
            "normalized": "",
            "source_file": "x",
            "line": -1,
            "message": "",
            "data": {},
        }
        self.assertNotEqual(validate(bad, schema), [])


if __name__ == "__main__":
    unittest.main()
