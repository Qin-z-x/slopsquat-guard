"""Shared test helpers: fake registry fetchers, popularity fixtures, cache builders."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from slopsquat_guard.popular import PopularLists
from slopsquat_guard.registry import FetchError, RegistryClient

FIXED_NOW = datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc)


class FakeFetcher:
    """Deterministic registry fetcher: names in ``existing`` answer 200, others 404."""

    def __init__(
        self,
        existing: set[str] | None = None,
        error_names: set[str] | None = None,
        status_map: dict[str, int] | None = None,
    ):
        self.existing = {name.lower() for name in (existing or set())}
        self.error_names = {name.lower() for name in (error_names or set())}
        self.status_map = {name.lower(): status for name, status in (status_map or {}).items()}
        self.calls: list[str] = []

    @staticmethod
    def _name_from_url(url: str) -> str:
        if url.startswith("https://pypi.org/pypi/"):
            return url.split("/pypi/", 1)[1].split("/", 1)[0]
        if url.startswith("https://registry.npmjs.org/"):
            name = url.split("registry.npmjs.org/", 1)[1]
            return name.replace("%2F", "/").replace("%2f", "/")
        raise AssertionError("unexpected URL: %s" % url)

    def __call__(self, url: str, timeout: float = 15.0):
        self.calls.append(url)
        name = self._name_from_url(url)
        key = name.lower()
        if key in self.error_names or name in self.error_names:
            raise FetchError("simulated network failure for %s" % name)
        status = self.status_map.get(key) or self.status_map.get(name)
        if status is not None:
            return status, b"{}"
        if key in self.existing:
            return 200, json.dumps({"info": {"version": "1.2.3"}, "dist-tags": {"latest": "1.2.3"}}).encode("utf-8")
        return 404, b'{"message": "Not Found"}'


def fixed_now(delta_days: float = 0.0):
    moment = FIXED_NOW + timedelta(days=delta_days)
    return lambda: moment


def make_popular(pypi=("requests", "numpy", "flask", "pandas", "pydantic"), npm=("react", "lodash", "express", "typescript")):
    return PopularLists({"pypi": list(pypi), "npm": list(npm)})


def make_client(tmp_path: Path, existing: set[str] | None = None, **kwargs) -> RegistryClient:
    kwargs.setdefault("now", fixed_now())
    kwargs.setdefault("cache_path", tmp_path / "cache.json")
    return RegistryClient(fetcher=FakeFetcher(existing=existing or set()), **kwargs)


def write_cache(path: Path, entries: dict[str, dict]) -> Path:
    payload = {"version": 1, "saved_at": FIXED_NOW.isoformat(), "entries": entries}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def cache_entry(exists: bool, status: int = 200, checked_at: str | None = None, version: str | None = None) -> dict:
    return {
        "exists": exists,
        "status": status,
        "checked_at": checked_at or FIXED_NOW.isoformat(),
        "version": version if version is not None else ("1.0.0" if exists else None),
    }
