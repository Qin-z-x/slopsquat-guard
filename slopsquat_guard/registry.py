"""Registry existence checks for PyPI and npm, with an injectable fetcher and cache.

The client answers one question per package: *does this name exist in this public
registry?* It deliberately does **not** claim the package is safe — registry
presence only rules out the "hallucinated name" signal.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

USER_AGENT = "slopsquat-guard/0.1 (+https://github.com/Qin-Z-x/slopsquat-guard)"
PYPI_ENDPOINT = "https://pypi.org/pypi/{name}/json"
NPM_ENDPOINT = "https://registry.npmjs.org/{name}"
CACHE_VERSION = 1
DEFAULT_TTL_DAYS = 7


class FetchError(RuntimeError):
    """Raised by a fetcher when the request itself failed (no HTTP status)."""


def default_fetcher(url: str, timeout: float = 15.0) -> tuple[int, bytes]:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise FetchError(str(exc)) from exc


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def default_cache_path() -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return Path(base) / "slopsquat-guard" / "registry-cache.json"
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "slopsquat-guard" / "registry-cache.json"


@dataclass
class RegistryResult:
    ecosystem: str
    name: str
    exists: bool | None
    status: int | None
    source: str  # "network" | "cache" | "cache-offline" | "offline-miss" | "error"
    checked_at: str | None
    version: str | None = None
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "exists": self.exists,
            "status": self.status,
            "source": self.source,
            "checked_at": self.checked_at,
            "version": self.version,
            "note": self.note,
        }


@dataclass
class RegistryClient:
    fetcher: object = default_fetcher
    cache_path: Path | str | None = None
    ttl_days: float = DEFAULT_TTL_DAYS
    offline: bool = False
    refresh: bool = False
    now: object = _utc_now
    timeout: float = 15.0
    entries: dict = field(default_factory=dict, init=False)
    _dirty: bool = field(default=False, init=False)
    calls: dict = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        if self.cache_path is None:
            self.cache_path = default_cache_path()
        self.cache_path = Path(self.cache_path)
        if not self.refresh:
            self._load_cache()
        self.calls = {"network": 0, "cache": 0, "error": 0, "offline": 0}

    # -- cache ------------------------------------------------------------
    def _load_cache(self) -> None:
        try:
            payload = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        entries = payload.get("entries") if isinstance(payload, dict) else None
        if isinstance(entries, dict):
            self.entries = {str(key): value for key, value in entries.items() if isinstance(value, dict)}

    def save(self) -> None:
        if self.offline or not self._dirty:
            return
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": CACHE_VERSION,
            "saved_at": self.now().isoformat() if callable(self.now) else str(self.now),
            "entries": dict(sorted(self.entries.items())),
        }
        self.cache_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")

    def cache_snapshot(self) -> dict:
        return {"version": CACHE_VERSION, "entries": dict(sorted(self.entries.items()))}

    # -- checking ---------------------------------------------------------
    def _cache_entry_fresh(self, entry: dict) -> bool:
        checked_at = entry.get("checked_at")
        if not checked_at:
            return False
        try:
            checked = datetime.fromisoformat(str(checked_at))
        except ValueError:
            return False
        if checked.tzinfo is None:
            checked = checked.replace(tzinfo=timezone.utc)
        return (self.now() - checked) <= timedelta(days=self.ttl_days)

    def _url(self, ecosystem: str, name: str) -> str:
        if ecosystem == "pypi":
            return PYPI_ENDPOINT.format(name=urllib.parse.quote(name, safe=""))
        if ecosystem == "npm":
            return NPM_ENDPOINT.format(name=urllib.parse.quote(name, safe="@"))
        raise ValueError("unknown ecosystem %r" % ecosystem)

    def _parse_version(self, ecosystem: str, body: bytes) -> str | None:
        try:
            payload = json.loads(body.decode("utf-8", "replace"))
        except ValueError:
            return None
        try:
            if ecosystem == "pypi":
                version = payload.get("info", {}).get("version")
            else:
                version = payload.get("dist-tags", {}).get("latest")
        except AttributeError:
            return None
        return str(version) if version else None

    def check(self, ecosystem: str, name: str) -> RegistryResult:
        key = "%s:%s" % (ecosystem, name)
        entry = self.entries.get(key)
        now_iso = self.now().isoformat()

        if self.offline:
            self.calls["offline"] += 1
            if entry:
                return RegistryResult(
                    ecosystem=ecosystem,
                    name=name,
                    exists=bool(entry.get("exists")),
                    status=entry.get("status"),
                    source="cache-offline",
                    checked_at=entry.get("checked_at"),
                    version=entry.get("version"),
                    note="offline mode: cached registry answer reused",
                )
            return RegistryResult(
                ecosystem=ecosystem,
                name=name,
                exists=None,
                status=None,
                source="offline-miss",
                checked_at=None,
                note="offline mode: no cached answer for this name",
            )

        if entry and not self.refresh and self._cache_entry_fresh(entry):
            self.calls["cache"] += 1
            return RegistryResult(
                ecosystem=ecosystem,
                name=name,
                exists=bool(entry.get("exists")),
                status=entry.get("status"),
                source="cache",
                checked_at=entry.get("checked_at"),
                version=entry.get("version"),
                note="cached answer within TTL",
            )

        url = self._url(ecosystem, name)  # raises ValueError for unknown ecosystems
        try:
            status, body = self.fetcher(url, timeout=self.timeout)  # type: ignore[operator]
        except (FetchError, OSError, TimeoutError, ValueError) as exc:
            self.calls["error"] += 1
            return RegistryResult(
                ecosystem=ecosystem,
                name=name,
                exists=None,
                status=None,
                source="error",
                checked_at=None,
                note="registry request failed: %s" % exc,
            )
        self.calls["network"] += 1
        if status == 200:
            exists = True
            version = self._parse_version(ecosystem, body)
        elif status == 404:
            exists = False
            version = None
        else:
            self.calls["error"] += 1
            return RegistryResult(
                ecosystem=ecosystem,
                name=name,
                exists=None,
                status=status,
                source="error",
                checked_at=None,
                note="unexpected registry status %d; not treated as proof" % status,
            )
        self.entries[key] = {"exists": exists, "status": status, "checked_at": now_iso, "version": version}
        self._dirty = True
        return RegistryResult(
            ecosystem=ecosystem,
            name=name,
            exists=exists,
            status=status,
            source="network",
            checked_at=now_iso,
            version=version,
        )
