"""Command line interface for slopsquat-guard.

Exit codes (stable, CI-gate friendly)::

    0  success (for ``scan``: no finding at/above the --fail-on threshold)
    1  ``scan --fail-on`` threshold reached
    2  usage error, unreadable path, invalid ecosystem
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .core import (
    SEVERITY_ORDER,
    format_finding_line,
    scan_path,
    severity_at_least,
    verify_package,
)
from .popular import PopularLists
from .registry import RegistryClient, default_cache_path


def _force_utf8_output() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):  # pragma: no cover
                pass


def _flatten_allow(values) -> list[str]:
    result: list[str] = []
    for group in values or []:
        for item in group:
            for part in item.split(","):
                part = part.strip()
                if part and part not in result:
                    result.append(part)
    return result


def _make_client(args) -> RegistryClient:
    return RegistryClient(
        cache_path=Path(args.cache).resolve() if args.cache else default_cache_path(),
        ttl_days=args.ttl_days,
        offline=args.offline,
        refresh=args.refresh,
    )


def _print_scan(args) -> int:
    client = _make_client(args)
    try:
        result = scan_path(
            args.path,
            client=client,
            popular=PopularLists(),
            allow=args.allow,
            include_imports=not args.manifests_only,
        )
    except FileNotFoundError:
        print("error: path not found: %s" % args.path, file=sys.stderr)
        return 2
    summary = result["summary"]
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        ecosystems: dict[str, int] = {}
        for dependency in result["dependencies"]:
            ecosystems[dependency["ecosystem"]] = ecosystems.get(dependency["ecosystem"], 0) + 1
        ecosystem_text = ", ".join("%d %s" % (count, name) for name, count in sorted(ecosystems.items())) or "none"
        calls = summary["registry_calls"]
        print(
            "slopsquat-guard %s  scan  %s  (%d dependencies: %s; registry: %d network, %d cache, %d error)"
            % (__version__, result["path"], len(result["dependencies"]), ecosystem_text, calls["network"], calls["cache"], calls["error"])
        )
        if result["offline"]:
            print("offline mode: cached registry answers only")
        for error in result["errors"]:
            print("warning: %s: %s" % (error["file"], error["error"]))
        for finding in result["findings"]:
            print(_format_dict_finding(finding))
        print(
            "summary: %d finding(s): %d high, %d medium, %d low | %d dependencies: %d verified, %d missing, %d unverified"
            % (
                summary["total"],
                summary["high"],
                summary["medium"],
                summary["low"],
                summary["dependencies"],
                summary["verified_existing"],
                summary["not_found"],
                summary["unverified"],
            )
        )
    if args.fail_on:
        hits = [finding for finding in result["findings"] if severity_at_least(finding["severity"], args.fail_on)]
        if hits:
            if not args.json:
                print("FAIL: %d finding(s) at or above severity %r (--fail-on %s)" % (len(hits), args.fail_on, args.fail_on))
            return 1
        if not args.json:
            print("OK: no finding at or above severity %r" % args.fail_on)
    return 0


def _format_dict_finding(finding: dict) -> str:
    return "%s %-16s %-4s %-28s %s:%d  %s" % (
        finding["severity"].upper().ljust(6),
        finding["code"],
        finding["ecosystem"],
        finding["name"],
        finding["source_file"],
        finding["line"],
        finding["message"],
    )


def _print_verify(args) -> int:
    client = _make_client(args)
    try:
        result = verify_package(args.name, args.ecosystem, client=client, popular=PopularLists())
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        registry = result["registry"]
        exists = registry["exists"]
        status = "exists" if exists is True else ("missing" if exists is False else "unverified")
        print(
            "slopsquat-guard %s  verify  %s  (%s: %s, source=%s%s)"
            % (
                __version__,
                result["name"],
                result["ecosystem"],
                status,
                registry["source"],
                ", version=%s" % registry["version"] if registry.get("version") else "",
            )
        )
        if result["in_popular_list"]:
            print("in bundled popularity list: yes")
        if result["near_miss"]:
            near = result["near_miss"]
            print("near-miss of popular %r: distance %d (rank %s)" % (near["target"], near["distance"], near["popularity_rank"]))
        if result["finding"]:
            print(_format_dict_finding(result["finding"]))
    if args.fail_on and result["finding"] and severity_at_least(result["finding"]["severity"], args.fail_on):
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="slopsquat-guard",
        description="Find hallucinated/typosquatted dependencies before installing them.",
    )
    parser.add_argument("--version", action="version", version="slopsquat-guard " + __version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="scan a file or directory for risky dependency names")
    scan_parser.add_argument("--path", default=".", help="file or directory to scan (default: .)")
    scan_parser.add_argument("--json", action="store_true", help="machine-readable JSON output")
    scan_parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default=None, help="exit 1 if a finding at/above this severity exists")
    scan_parser.add_argument("--offline", action="store_true", help="use cached registry answers only, never the network")
    scan_parser.add_argument("--cache", help="registry cache file (default: per-user cache directory)")
    scan_parser.add_argument("--ttl-days", type=float, default=7.0, help="cache freshness in days (default: 7)")
    scan_parser.add_argument("--refresh", action="store_true", help="re-query the registry even if the cache is fresh")
    scan_parser.add_argument("--allow", action="append", nargs="+", metavar="NAME", help="skip this name (repeatable; comma-separated allowed)")
    scan_parser.add_argument("--manifests-only", action="store_true", help="do not scan Python imports")
    scan_parser.set_defaults(func=_print_scan)

    verify_parser = subparsers.add_parser("verify", help="check a single package name")
    verify_parser.add_argument("name")
    verify_parser.add_argument("--ecosystem", choices=["pypi", "npm"], default="pypi")
    verify_parser.add_argument("--json", action="store_true", help="machine-readable JSON output")
    verify_parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default=None)
    verify_parser.add_argument("--offline", action="store_true")
    verify_parser.add_argument("--cache")
    verify_parser.add_argument("--ttl-days", type=float, default=7.0)
    verify_parser.add_argument("--refresh", action="store_true")
    verify_parser.set_defaults(func=_print_verify)

    return parser


def main(argv: list[str] | None = None) -> int:
    _force_utf8_output()
    parser = build_parser()
    args = parser.parse_args(argv)
    if hasattr(args, "allow"):
        args.allow = _flatten_allow(args.allow)
    try:
        return args.func(args)
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
