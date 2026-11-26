"""CLI tests: offline scan with a cache fixture, exit codes, JSON output, verify."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "slopsquat_guard", *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=180,
    )


def make_project(directory: Path, requirements: str, extra_files: dict[str, str] | None = None) -> Path:
    project = directory / "project"
    project.mkdir(parents=True, exist_ok=True)
    (project / "requirements.txt").write_text(requirements, encoding="utf-8")
    for name, content in (extra_files or {}).items():
        (project / name).write_text(content, encoding="utf-8")
    return project


def make_cache(directory: Path, entries: dict[str, bool]) -> Path:
    cache = directory / "cache.json"
    payload = {
        "version": 1,
        "saved_at": "2026-11-26T12:00:00+00:00",
        "entries": {
            key: {
                "exists": exists,
                "status": 200 if exists else 404,
                "checked_at": "2026-11-26T12:00:00+00:00",
                "version": "1.0.0" if exists else None,
            }
            for key, exists in entries.items()
        },
    }
    cache.write_text(json.dumps(payload), encoding="utf-8")
    return cache


class ScanCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.cache = make_cache(self.dir, {"pypi:requests": True, "pypi:openai-toolkit-x": False})
        self.project = make_project(self.dir, "requests>=2.31\nopenai-toolkit-x==1.0\n")

    def test_scan_json_exits_zero_without_gate(self):
        result = run_cli("scan", "--path", str(self.project), "--offline", "--cache", str(self.cache), "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["tool"], "slopsquat-guard")
        self.assertEqual(payload["summary"]["not_found"], 1)
        self.assertTrue(payload["offline"])

    def test_scan_fail_on_high_exits_one(self):
        result = run_cli(
            "scan", "--path", str(self.project), "--offline", "--cache", str(self.cache), "--fail-on", "high"
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL:", result.stdout)

    def test_clean_project_passes_gate(self):
        clean = make_project(self.dir, "requests>=2.31\n")
        result = run_cli("scan", "--path", str(clean), "--offline", "--cache", str(self.cache), "--fail-on", "high")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_human_output_contains_summary(self):
        result = run_cli("scan", "--path", str(self.project), "--offline", "--cache", str(self.cache))
        self.assertEqual(result.returncode, 0)
        self.assertIn("slopsquat-guard", result.stdout)
        self.assertIn("summary:", result.stdout)
        self.assertIn("SQ-NOT-FOUND", result.stdout)

    def test_offline_missing_cache_is_unverified_not_high(self):
        empty_cache = self.dir / "empty.json"
        result = run_cli(
            "scan", "--path", str(self.project), "--offline", "--cache", str(empty_cache), "--fail-on", "high", "--json"
        )
        self.assertEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["summary"]["high"], 0)
        self.assertEqual(payload["summary"]["unverified"], 2)

    def test_missing_path_exits_two(self):
        result = run_cli("scan", "--path", str(self.dir / "nope"), "--offline", "--cache", str(self.cache))
        self.assertEqual(result.returncode, 2)

    def test_manifests_only_skips_imports(self):
        project = make_project(
            self.dir,
            "requests>=2.31\n",
            extra_files={"app.py": "import openai_toolkit_x\n"},
        )
        cache = make_cache(self.dir / "..", {}) if False else self.cache
        result = run_cli(
            "scan", "--path", str(project), "--offline", "--cache", str(cache), "--manifests-only", "--json"
        )
        self.assertEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        origins = {dependency["origin"] for dependency in payload["dependencies"]}
        self.assertNotIn("import", origins)

    def test_allow_flag_skips_name(self):
        result = run_cli(
            "scan",
            "--path",
            str(self.project),
            "--offline",
            "--cache",
            str(self.cache),
            "--allow",
            "openai-toolkit-x",
            "--json",
        )
        payload = json.loads(result.stdout)
        self.assertEqual(payload["summary"]["allowed"], 1)
        self.assertEqual(payload["summary"]["not_found"], 0)


class VerifyCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.cache = make_cache(self.dir, {"pypi:requests": True, "pypi:reqeusts": False, "npm:react": True})

    def test_verify_missing_json(self):
        result = run_cli("verify", "reqeusts", "--offline", "--cache", str(self.cache), "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["finding"]["code"], "SQ-TYPOSQUAT")
        self.assertEqual(payload["finding"]["severity"], "high")

    def test_verify_existing(self):
        result = run_cli("verify", "requests", "--offline", "--cache", str(self.cache), "--json")
        payload = json.loads(result.stdout)
        self.assertTrue(payload["registry"]["exists"])
        self.assertIsNone(payload["finding"])

    def test_verify_fail_on_high(self):
        result = run_cli("verify", "reqeusts", "--offline", "--cache", str(self.cache), "--fail-on", "high")
        self.assertEqual(result.returncode, 1)

    def test_verify_npm(self):
        result = run_cli("verify", "react", "--ecosystem", "npm", "--offline", "--cache", str(self.cache), "--json")
        payload = json.loads(result.stdout)
        self.assertTrue(payload["registry"]["exists"])

    def test_invalid_ecosystem_exits_two(self):
        result = run_cli("verify", "x", "--ecosystem", "maven")
        self.assertEqual(result.returncode, 2)

    def test_empty_name_exits_two(self):
        result = run_cli("verify", "  ", "--offline", "--cache", str(self.cache))
        self.assertEqual(result.returncode, 2)


class MiscCliTests(unittest.TestCase):
    def test_version(self):
        result = run_cli("--version")
        self.assertEqual(result.returncode, 0)
        self.assertIn("0.1.0", result.stdout)

    def test_unknown_option_exits_two(self):
        self.assertEqual(run_cli("scan", "--bogus").returncode, 2)


if __name__ == "__main__":
    unittest.main()
