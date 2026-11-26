"""Regenerate the bundled popularity lists used for typosquat detection.

Data sources (public, cited in ``docs/DATA_SOURCES.md``):

* PyPI: ``https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json``
  (public dataset of PyPI download counts over the last 30 days).
* npm: candidate names are collected from the public npm registry search API,
  then ranked by real weekly download counts from
  ``https://api.npmjs.org/downloads/point/last-week/<names>``.

The output is a deterministic, checked-in list of the top 1000 names per
ecosystem. Popularity is a *typosquat-target heuristic*, not a security
endorsement. Run from the repository root:

    python scripts/refresh_popularity.py
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "slopsquat_guard" / "data"
USER_AGENT = "slopsquat-guard-refresh/0.1 (+https://github.com/Qin-Z-x/slopsquat-guard)"
PYPI_TOP_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
NPM_SEARCH_URL = "https://registry.npmjs.org/-/v1/search?text={query}&size=250"
NPM_DOWNLOADS_URL = "https://api.npmjs.org/downloads/point/last-week/{names}"
TOP_N = 1000

NPM_QUERIES = [
    "react",
    "webpack",
    "eslint",
    "typescript",
    "express",
    "vue",
    "angular",
    "jest",
    "babel",
    "node",
    "cli",
    "http",
    "json",
    "css",
    "server",
    "api",
    "test",
    "build",
    "utility",
    "date",
    "log",
    "axios",
    "lodash",
    "chalk",
    "dotenv",
    "uuid",
    "zod",
    "vite",
    "next",
    "stream",
    "file",
    "glob",
    "minimist",
    "yargs",
    "debug",
    "cors",
    "cookie",
    "sass",
    "jquery",
    "three",
    "mongoose",
    "redis",
    "graphql",
    "openai",
    "langchain",
    "ai",
    "markdown",
    "csv",
    "yaml",
    "crypto",
    "image",
    "url",
]


def fetch(url: str, timeout: int = 25) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def short_hash(names: list[str]) -> str:
    return hashlib.sha256(("\n".join(names) + "\n").encode("utf-8")).hexdigest()


def write_list(name: str, ecosystem: str, metric: str, source: str, names: list[str], header_extra: str = "") -> Path:
    assert len(names) == TOP_N, "expected %d names, got %d" % (TOP_N, len(names))
    assert len(set(names)) == len(names), "duplicate names in list"
    path = DATA / name
    lines = [
        "# slopsquat-guard bundled popularity list: %s" % ecosystem,
        "# Source: %s" % source,
        "# Metric: %s" % metric,
        "# Ranked at: %s" % time.strftime("%Y-%m-%d", time.gmtime()),
        "# Regenerate: python scripts/refresh_popularity.py",
        "# Popularity is a typosquat-target heuristic, not a security endorsement.",
    ]
    if header_extra:
        lines.append("# " + header_extra)
    lines.extend(names)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print("wrote %s: %d names, sha256=%s" % (path.relative_to(ROOT), len(names), short_hash(names)))
    return path


def fetch_pypi_top() -> list[str]:
    payload = json.loads(fetch(PYPI_TOP_URL))
    rows = payload["rows"]
    names: list[str] = []
    for row in rows:
        name = str(row["project"]).strip()
        if name and name not in names:
            names.append(name)
        if len(names) == TOP_N:
            break
    if len(names) < TOP_N:
        raise SystemExit("PyPI dataset returned only %d names" % len(names))
    print("PyPI top list: %d names from %d rows (downloads window: %s)" % (len(names), len(rows), payload.get("last_update", "?")))
    return names


CANDIDATE_CACHE = Path(os.environ.get("TEMP", ".")) / "slopsquat-guard-npm-candidates.json"


def _collect_npm_candidates() -> list[str]:
    """Collect candidate npm names from the registry search API (rate limited)."""
    if CANDIDATE_CACHE.is_file():
        try:
            cached = json.loads(CANDIDATE_CACHE.read_text(encoding="utf-8"))
            if isinstance(cached, list) and len(cached) >= 2000:
                print("npm candidates: %d (reused local candidate cache %s)" % (len(cached), CANDIDATE_CACHE))
                return [str(name) for name in cached]
        except ValueError:
            pass
    candidates: list[str] = []
    seen: set[str] = set()
    for index, query in enumerate(NPM_QUERIES, start=1):
        payload = None
        for attempt in range(3):
            try:
                payload = json.loads(fetch(NPM_SEARCH_URL.format(query=urllib.parse.quote(query))))
                break
            except urllib.error.HTTPError as exc:
                if exc.code == 429 and attempt < 2:
                    time.sleep(5 * (attempt + 1))
                    continue
                print("  npm search %r failed: %s" % (query, exc), file=sys.stderr)
                break
            except Exception as exc:  # noqa: BLE001 - one bad query should not kill the refresh
                print("  npm search %r failed: %s" % (query, exc), file=sys.stderr)
                break
        if payload:
            for obj in payload.get("objects", []):
                name = (obj.get("package") or {}).get("name")
                if isinstance(name, str) and name and name not in seen:
                    seen.add(name)
                    candidates.append(name)
        print("  npm search: %d/%d queries, %d candidates" % (index, len(NPM_QUERIES), len(candidates)))
        time.sleep(0.5)
        if len(candidates) >= 9000:
            break
    CANDIDATE_CACHE.write_text(json.dumps(candidates), encoding="utf-8")
    print("npm candidates: %d (cached at %s)" % (len(candidates), CANDIDATE_CACHE))
    return candidates


def fetch_npm_top() -> list[str]:
    """Rank unscoped npm names by real weekly download counts.

    The npm downloads API does not support scoped packages in bulk lookups, so
    the bundled list covers unscoped packages only (documented in
    docs/DATA_SOURCES.md).
    """
    candidates = _collect_npm_candidates()
    unscoped = [name for name in candidates if not name.startswith("@")]
    downloads: dict[str, int] = {}
    batch_size = 25
    failures = 0
    for start in range(0, len(unscoped), batch_size):
        batch = unscoped[start : start + batch_size]
        url = NPM_DOWNLOADS_URL.format(names=",".join(urllib.request.quote(name, safe="@") for name in batch))
        payload = None
        for attempt in range(2):
            try:
                payload = json.loads(fetch(url, timeout=25))
                break
            except Exception as exc:  # noqa: BLE001 - retry once, then skip the batch
                if attempt == 0:
                    time.sleep(2)
                    continue
                failures += 1
                print("  npm downloads batch %d failed: %s" % (start, exc), file=sys.stderr)
        if isinstance(payload, dict):
            for name in batch:
                entry = payload.get(name)
                if isinstance(entry, dict) and isinstance(entry.get("downloads"), int):
                    downloads[name] = entry["downloads"]
        if (start // batch_size) % 10 == 0:
            print("  npm downloads: %d/%d candidates queried" % (min(start + batch_size, len(unscoped)), len(unscoped)))

    ranked = sorted(downloads.items(), key=lambda item: (-item[1], item[0]))
    names = [name for name, count in ranked if count > 0][:TOP_N]
    if len(names) < TOP_N:
        raise SystemExit(
            "npm ranking produced only %d names (%d batches failed); rerun the refresh script"
            % (len(names), failures)
        )
    print("npm top list: %d names (best: %s=%d weekly downloads)" % (len(names), ranked[0][0], ranked[0][1]))
    return names


def main() -> int:
    DATA.mkdir(parents=True, exist_ok=True)
    pypi_names = fetch_pypi_top()
    write_list(
        "pypi_top1000.txt",
        "PyPI",
        "download_count over the last 30 days (public dataset)",
        PYPI_TOP_URL,
        pypi_names,
    )
    npm_names = fetch_npm_top()
    write_list(
        "npm_top1000.txt",
        "npm",
        "weekly download count (npm downloads API; unscoped packages)",
        "npm registry search API + https://api.npmjs.org/downloads/point/last-week",
        npm_names,
    )
    print("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
