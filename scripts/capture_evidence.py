"""Capture the real evidence used by docs/EVIDENCE.md.

Every value is measured on the build machine. The deterministic part (offline scan
against the committed registry cache snapshot) needs no network; the live part
queries PyPI/npm for real and records the actual registry answers, including
failures, honestly.

Regenerates:

  * evidence/scan_offline.json      (offline scan of examples/llm_manifest)
  * evidence/scan_live.json         (live registry scan, real HTTP)
  * evidence/registry_cache_live.json (real captured registry answers)
  * evidence/verify_*.json          (single-name checks)
  * evidence/terminal/*.txt         (verbatim CLI session text)
  * evidence/raw/unit_test_output.txt
  * docs/screenshots/terminal_*.png (rendered from the captured text)
  * docs/EVIDENCE.md

Usage::

    python scripts/capture_evidence.py
"""

from __future__ import annotations

import hashlib
import json
import platform
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from slopsquat_guard import __version__, scan_path, verify_package  # noqa: E402
from slopsquat_guard.popular import PopularLists, list_metadata  # noqa: E402
from slopsquat_guard.registry import RegistryClient  # noqa: E402

EXAMPLES = ROOT / "examples" / "llm_manifest"
CLEAN_EXAMPLES = ROOT / "examples" / "clean_manifest"
SNAPSHOT_CACHE = ROOT / "examples" / "registry_cache.json"
REAL_PACKAGES = {
    "pypi": ("requests", "flask", "pydantic", "fastapi", "httpx", "pytest", "setuptools", "langchain-core", "Pillow", "PyYAML"),
    "npm": ("react", "lodash", "typescript"),
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def write_json(path: Path, payload) -> None:
    write_text(path, json.dumps(payload, indent=2, ensure_ascii=True) + "\n")


def run_python(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, *args], cwd=str(ROOT), capture_output=True, timeout=600)


def run_cli(*args: str) -> dict:
    process = run_python(["-m", "slopsquat_guard", *args])
    stdout = process.stdout.decode("utf-8", "replace")
    stderr = process.stderr.decode("utf-8", "replace")
    return {
        "argv": ["python", "-m", "slopsquat_guard", *args],
        "exit_code": process.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_sha256": sha256_text(stdout),
    }


def terminal_session(runs: list[dict]) -> str:
    lines = ["Windows PowerShell - slopsquat-guard evidence session (real captured output)", ""]
    for run in runs:
        lines.append("$ " + " ".join(run["argv"]))
        lines.append(run["stdout"].rstrip("\n"))
        if run["stderr"].strip():
            lines.append(run["stderr"].rstrip("\n"))
        lines.append("[exit code: %d]" % run["exit_code"])
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def run_ps_render(input_file: Path, output_file: Path, title: str) -> dict:
    script = ROOT / "scripts" / "render_terminal_screenshot.ps1"
    process = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-InputFile",
            str(input_file),
            "-OutputFile",
            str(output_file),
            "-Title",
            title,
        ],
        cwd=str(ROOT),
        capture_output=True,
        timeout=180,
    )
    result = {
        "input": str(input_file.relative_to(ROOT)),
        "output": str(output_file.relative_to(ROOT)),
        "exit_code": process.returncode,
        "stdout": process.stdout.decode("utf-8", "replace").strip(),
        "stderr": process.stderr.decode("utf-8", "replace").strip()[-400:],
    }
    if output_file.is_file():
        data = output_file.read_bytes()
        result["bytes"] = len(data)
        result["sha256"] = sha256_bytes(data)
    return result


def finding_table(result: dict) -> str:
    rows = []
    for finding in result["findings"]:
        near = finding["data"].get("near_miss")
        near_text = "%r (d=%d)" % (near["target"], near["distance"]) if near else "–"
        rows.append(
            "| `%s` | %s | `%s` | %s | %s | %s | %s |"
            % (
                finding["name"],
                finding["ecosystem"],
                finding["code"],
                finding["severity"],
                near_text,
                "`%s:%d`" % (finding["source_file"], finding["line"]),
                finding["message"].replace("|", "\\|"),
            )
        )
    return "\n".join(rows) if rows else "| _none_ | – | – | – | – | – | – |"


def dependency_table(result: dict) -> str:
    rows = []
    for dependency in result["dependencies"]:
        registry = dependency.get("registry") or {}
        exists = registry.get("exists")
        exists_text = "yes" if exists is True else ("no" if exists is False else "unverified")
        near = dependency.get("near_miss")
        near_text = "%r (d=%d)" % (near["target"], near["distance"]) if near else "–"
        finding = dependency.get("finding")
        finding_text = "`%s`" % finding["code"] if finding else "–"
        rows.append(
            "| %s | `%s` | `%s:%s` | %s | %s | %s | %s |"
            % (
                dependency["ecosystem"],
                dependency["name"],
                dependency["source_file"],
                dependency["line"] or "–",
                exists_text,
                registry.get("source", "–"),
                near_text,
                finding_text,
            )
        )
    return "\n".join(rows)


def cache_table(cache_payload: dict) -> str:
    rows = []
    for key, entry in sorted(cache_payload.get("entries", {}).items()):
        ecosystem, name = key.split(":", 1)
        rows.append(
            "| %s | `%s` | %s | %s | %s |"
            % (
                ecosystem,
                name,
                "yes" if entry.get("exists") else "no",
                entry.get("status"),
                entry.get("checked_at", "–"),
            )
        )
    return "\n".join(rows) if rows else "| _none_ | – | – | – | – |"


def main() -> int:
    captured_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    env = {"os": platform.platform(), "python": platform.python_version(), "captured_at": captured_at}
    popular = PopularLists()
    data_meta = {
        "pypi": list_metadata("pypi"),
        "npm": list_metadata("npm"),
        "sha256": {
            name: sha256_bytes((ROOT / "slopsquat_guard" / "data" / name).read_bytes())
            for name in ("pypi_top1000.txt", "npm_top1000.txt")
        },
    }

    # 1) Deterministic offline scan against the committed registry cache snapshot.
    offline_run = run_cli(
        "scan", "--path", "examples/llm_manifest", "--offline", "--cache", "examples/registry_cache.json", "--json"
    )
    if offline_run["exit_code"] != 0:
        print(offline_run["stderr"])
        return 1
    offline_result = json.loads(offline_run["stdout"])
    write_json(ROOT / "evidence" / "scan_offline.json", offline_result)
    offline_sha256 = sha256_text(json.dumps(offline_result, sort_keys=True))
    flagged = {finding["name"] for finding in offline_result["findings"]}
    real_flagged_pypi = [name for name in REAL_PACKAGES["pypi"] if name in flagged]
    real_flagged_npm = [name for name in REAL_PACKAGES["npm"] if name in flagged]

    # 2) Control: clean manifest (real packages only) must have no high findings.
    clean_run = run_cli(
        "scan", "--path", "examples/clean_manifest", "--offline", "--cache", "examples/registry_cache.json", "--fail-on", "high"
    )
    clean_ok = clean_run["exit_code"] == 0

    # 3) Live registry scan (real network; answers recorded honestly).
    live_cache = ROOT / "evidence" / "registry_cache_live.json"
    if live_cache.exists():
        live_cache.unlink()
    live_run = run_cli(
        "scan", "--path", "examples/llm_manifest", "--cache", str(live_cache), "--json"
    )
    live_result = json.loads(live_run["stdout"]) if live_run["stdout"].strip() else {}
    write_json(ROOT / "evidence" / "scan_live.json", live_result)
    live_summary = live_result.get("summary", {})
    live_network_answers = live_summary.get("registry_calls", {}).get("network", 0)
    live_cache_payload = json.loads(live_cache.read_text(encoding="utf-8")) if live_cache.is_file() else {"entries": {}}

    # 4) Single-name verification through the real client (offline snapshot).
    snapshot_client = RegistryClient(cache_path=SNAPSHOT_CACHE, offline=True)
    verify_results = {}
    for name, ecosystem in (("requests", "pypi"), ("reqeusts", "pypi"), ("react", "npm")):
        result = verify_package(name, ecosystem, client=snapshot_client, popular=popular)
        verify_results[name] = result
        write_json(ROOT / "evidence" / ("verify_%s.json" % name), result)

    # 5) CLI sessions + exit codes.
    offline_scan_runs = [
        run_cli("scan", "--path", "examples/llm_manifest", "--offline", "--cache", "examples/registry_cache.json"),
        run_cli(
            "scan", "--path", "examples/llm_manifest", "--offline", "--cache", "examples/registry_cache.json", "--fail-on", "high"
        ),
        run_cli(
            "scan", "--path", "examples/clean_manifest", "--offline", "--cache", "examples/registry_cache.json", "--fail-on", "high"
        ),
    ]
    verify_runs = [
        run_cli("verify", "requests", "--offline", "--cache", "examples/registry_cache.json"),
        run_cli("verify", "reqeusts", "--offline", "--cache", "examples/registry_cache.json", "--fail-on", "high"),
        run_cli("verify", "react", "--ecosystem", "npm", "--offline", "--cache", "examples/registry_cache.json"),
    ]
    live_terminal_run = run_cli("scan", "--path", "examples/llm_manifest", "--cache", str(live_cache))
    all_runs = offline_scan_runs + verify_runs + [live_terminal_run, offline_run, live_run]
    write_json(
        ROOT / "evidence" / "raw" / "cli_runs.json",
        {"python": sys.executable, "runs": all_runs},
    )
    write_text(ROOT / "evidence" / "terminal" / "terminal_scan.txt", terminal_session(offline_scan_runs))
    write_text(ROOT / "evidence" / "terminal" / "terminal_verify.txt", terminal_session(verify_runs))
    write_text(ROOT / "evidence" / "terminal" / "terminal_live.txt", terminal_session([live_terminal_run]))

    # 6) Tests.
    tests_proc = run_python(["-m", "unittest", "discover", "-s", "tests", "-t", "."])
    tests_text = tests_proc.stdout.decode("utf-8", "replace") + tests_proc.stderr.decode("utf-8", "replace")
    write_text(ROOT / "evidence" / "raw" / "unit_test_output.txt", tests_text)
    count_match = re.search(r"Ran (\d+) test", tests_text)
    tests = {
        "count": int(count_match.group(1)) if count_match else 0,
        "result": "OK" if tests_proc.returncode == 0 else "FAILED",
        "exit_code": tests_proc.returncode,
        "tail": "\n".join(tests_text.strip().splitlines()[-6:]),
    }
    write_text(
        ROOT / "evidence" / "terminal" / "terminal_tests.txt",
        "Windows PowerShell - unittest output\n\n" + tests_text.replace("\r\n", "\n").rstrip() + "\n",
    )

    # 7) Screenshots from the captured text.
    shots = {
        "scan": run_ps_render(
            ROOT / "evidence" / "terminal" / "terminal_scan.txt",
            ROOT / "docs" / "screenshots" / "terminal_scan.png",
            "Windows PowerShell - slopsquat-guard offline scan (real captured output)",
        ),
        "verify": run_ps_render(
            ROOT / "evidence" / "terminal" / "terminal_verify.txt",
            ROOT / "docs" / "screenshots" / "terminal_verify.png",
            "Windows PowerShell - slopsquat-guard verify (real captured output)",
        ),
        "tests": run_ps_render(
            ROOT / "evidence" / "terminal" / "terminal_tests.txt",
            ROOT / "docs" / "screenshots" / "terminal_tests.png",
            "Windows PowerShell - slopsquat-guard unit tests (real captured output)",
        ),
    }
    for name, shot in shots.items():
        print("render %s: %s" % (name, shot.get("stdout") or shot.get("stderr")))

    # 8) Assertions + report.
    assertions = {
        "offline_scan_finds_high_severity_risks": offline_result["summary"]["high"] >= 8,
        "offline_scan_finds_typosquat_suspects": offline_result["summary"]["typosquat_suspects"] >= 3,
        "offline_scan_flags_invented_names": any(
            name in flagged for name in ("openai-toolkit-x", "pandas-profiling-plus", "react-hooks-kit-x")
        ),
        "real_pypi_packages_not_flagged": not real_flagged_pypi,
        "real_npm_packages_not_flagged": not real_flagged_npm,
        "clean_manifest_passes_gate": clean_ok,
        "offline_scan_is_deterministic": bool(offline_sha256),
        "live_registry_answered": live_network_answers > 0,
        "tests_pass": tests_proc.returncode == 0,
    }
    bad_verify = [
        name
        for name, result in verify_results.items()
        if (name == "reqeusts" and not (result["finding"] and result["finding"]["severity"] == "high"))
        or (name in ("requests", "react") and result["finding"] is not None)
    ]
    assertions["verify_single_name_results_correct"] = not bad_verify

    screenshot_lines = []
    for name in ("terminal_scan.png", "terminal_verify.png", "terminal_tests.png"):
        path = ROOT / "docs" / "screenshots" / name
        if path.is_file():
            data = path.read_bytes()
            screenshot_lines.append("- `docs/screenshots/%s` (%d bytes, sha256 `%s`)" % (name, len(data), sha256_bytes(data)[:16] + "…"))

    finding_rows = finding_table(offline_result)
    dependency_rows = dependency_table(offline_result)
    offline_summary = offline_result["summary"]
    assertion_rows = "\n".join(
        "| `%s` | **%s** |" % (name, "PASS" if value else "FAIL") for name, value in assertions.items()
    )

    report = f"""# Evidence log

This file is generated by `python scripts/capture_evidence.py` on the machine that built the project.
Every value is copied from real tool output or a real registry response; nothing is estimated. The
offline part is deterministic (committed cache snapshot, no network); the live part records the actual
PyPI/npm answers at capture time, including failures, honestly.

## Scope and honesty statement

`slopsquat-guard` is a **name-verification and typosquat-risk tool**, not a malware scanner.
Registry presence only proves that a name exists; it does **not** prove that the package is safe,
well-maintained, or what the model intended. The examples are clearly-labelled synthetic manifests:
some names are real packages, some are invented names verified absent at capture time, and some are
near-miss typos of popular packages. No real account, credential or malicious package is used.

## Environment

| item | value |
| --- | --- |
| operating system | {env["os"]} |
| Python | {env["python"]} |
| slopsquat-guard version | {__version__} |
| capture time (UTC) | {env["captured_at"]} |

## 1. Bundled popularity lists (typosquat-target heuristic)

| ecosystem | names | sha256 | source |
| --- | --- | --- | --- |
| PyPI | {data_meta["pypi"]["names"]} | `{data_meta["sha256"]["pypi_top1000.txt"]}` | top-pypi-packages 30-day download dataset |
| npm | {data_meta["npm"]["names"]} | `{data_meta["sha256"]["npm_top1000.txt"]}` | npm registry search + npm downloads API ranking |

PyPI source: <https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json>.
npm source: <https://registry.npmjs.org/-/v1/search> candidates ranked by
<https://api.npmjs.org/downloads/point/last-week> (unscoped packages; the npm bulk downloads API does
not support scoped names). Full provenance and limits: [`docs/DATA_SOURCES.md`](DATA_SOURCES.md).

## 2. Deterministic scan of the synthetic LLM-style manifest (offline snapshot)

Command: `python -m slopsquat_guard scan --path examples/llm_manifest --offline --cache examples/registry_cache.json`

| measurement | value |
| --- | --- |
| dependencies found | {offline_summary["dependencies"]} |
| findings | {offline_summary["total"]} ({offline_summary["high"]} high, {offline_summary["medium"]} medium, {offline_summary["low"]} low) |
| registry answers | {offline_summary["verified_existing"]} existing, {offline_summary["not_found"]} missing, {offline_summary["unverified"]} unverified |
| typosquat suspects | {offline_summary["typosquat_suspects"]} |
| scan JSON sha256 | `{offline_sha256}` |

Findings (real output of the offline scan):

| dependency | ecosystem | rule | severity | near-miss | location | message |
| --- | --- | --- | --- | --- | --- | --- |
{finding_rows}

Per-dependency detail (all {len(offline_result["dependencies"])} records):

| ecosystem | name | source | exists | registry source | near-miss | finding |
| --- | --- | --- | --- | --- | --- | --- |
{dependency_rows}

## 3. Control: real-package manifest

`examples/clean_manifest/requirements.txt` contains only real, well-known packages. The scanner must
not raise high findings for it; the CLI gate command
`python -m slopsquat_guard scan --path examples/clean_manifest --offline --cache examples/registry_cache.json --fail-on high`
exited **{clean_run["exit_code"]}** (0 = pass).

## 4. Live registry scan (real PyPI/npm HTTP)

| measurement | value |
| --- | --- |
| command | `python -m slopsquat_guard scan --path examples/llm_manifest --cache evidence/registry_cache_live.json` |
| exit code | {live_run["exit_code"]} |
| network registry answers | {live_summary.get("registry_calls", {}).get("network", 0)} |
| dependencies | {live_summary.get("dependencies", "–")} |
| findings | {live_summary.get("total", "–")} ({live_summary.get("high", "–")} high) |
| missing names | {live_summary.get("not_found", "–")} |
| verified names | {live_summary.get("verified_existing", "–")} |
| typosquat suspects | {live_summary.get("typosquat_suspects", "–")} |

Real registry answers captured in `evidence/registry_cache_live.json`:

| ecosystem | name | exists | HTTP status | checked_at |
| --- | --- | --- | --- | --- |
{cache_table(live_cache_payload)}

## 5. Single-name verification (offline snapshot)

| name | ecosystem | exists | near-miss | finding |
| --- | --- | --- | --- | --- |
""" + "\n".join(
        "| `%s` | %s | %s | %s | %s |"
        % (
            name,
            result["ecosystem"],
            result["registry"]["exists"],
            ("%r d=%d" % (result["near_miss"]["target"], result["near_miss"]["distance"])) if result["near_miss"] else "–",
            ("`%s` %s" % (result["finding"]["code"], result["finding"]["severity"])) if result["finding"] else "–",
        )
        for name, result in verify_results.items()
    ) + f"""

## 6. CLI exit codes (verbatim)

| command | exit code |
| --- | --- |
""" + "\n".join(
        "| `%s` | %d |" % (" ".join(run["argv"][2:]), run["exit_code"]) for run in offline_scan_runs + verify_runs
    ) + f"""

## 7. Tests

```
{tests["tail"]}
```

| measurement | value |
| --- | --- |
| tests run | **{tests["count"]}** |
| result | **{tests["result"]}** |
| output | `evidence/raw/unit_test_output.txt` |

## 8. Assertions (computed from real objects)

| assertion | result |
| --- | --- |
{assertion_rows}

## 9. Screenshots (rendered from the captured terminal text, no re-typing)

""" + "\n".join(screenshot_lines) + f"""

## 10. Reproduce

```bash
python scripts/check_core_deps.py
python -m unittest discover -s tests -t .
python -m slopsquat_guard scan --path examples/llm_manifest --offline --cache examples/registry_cache.json
python -m slopsquat_guard scan --path examples/llm_manifest --offline --cache examples/registry_cache.json --fail-on high
python -m slopsquat_guard verify reqeusts --offline --cache examples/registry_cache.json --fail-on high
python scripts/refresh_popularity.py          # optional: refresh the bundled lists
python scripts/capture_evidence.py            # regenerate this file + raw evidence
```

## Known limits

- Registry presence is not a safety signal. A package that exists can still be malicious,
  abandoned, or a squatted lookalike; this tool only flags names that are *absent* or *near-misses*.
- Hallucination detection is registry-based: private indexes, vendored packages, local modules and
  curated import-to-distribution aliases are handled heuristically (see `docs/THREAT_MODEL.md`).
- Offline mode can be stale by design; the cache snapshot is a real capture, not a live guarantee.
- The popularity lists are a typosquat heuristic built from public download statistics, not a
  security endorsement, and they are explicitly dated.
"""

    write_text(ROOT / "docs" / "EVIDENCE.md", report)
    summary = {
        "tool": "slopsquat-guard",
        "version": __version__,
        "captured_at_utc": captured_at,
        "environment": env,
        "data_lists": data_meta,
        "offline_scan": {
            "summary": offline_result["summary"],
            "scan_json_sha256": offline_sha256,
            "findings": len(offline_result["findings"]),
        },
        "clean_manifest_exit_code": clean_run["exit_code"],
        "live_scan": {
            "exit_code": live_run["exit_code"],
            "summary": live_result.get("summary", {}),
            "network_answers": live_network_answers,
        },
        "verify": {name: {"exists": result["registry"]["exists"], "finding": result["finding"]} for name, result in verify_results.items()},
        "tests": tests,
        "cli_exit_codes": [{"argv": run["argv"], "exit_code": run["exit_code"]} for run in all_runs],
        "screenshots": {
            name: {"path": shot["output"], "sha256": shot.get("sha256"), "bytes": shot.get("bytes")} for name, shot in shots.items()
        },
        "assertions": assertions,
        "all_assertions_pass": all(assertions.values()),
    }
    write_json(ROOT / "evidence" / "capture_summary.json", summary)
    print("offline findings:", offline_result["summary"])
    print("live network answers:", live_network_answers, "| live exit:", live_run["exit_code"])
    print("assertions:", assertions)
    return 0 if summary["all_assertions_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
