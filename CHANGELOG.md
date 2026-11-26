# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-11-26

Initial release.

### Added

* Dependency extraction from Python AST imports, `requirements.txt` /
  `constraints*.txt` (including local `-r`/`-c` includes), `pyproject.toml`
  (`tomllib` on 3.11+, built-in fallback parser on 3.10) and `package.json`
  (all dependency sections, scoped names).
* Registry verification against PyPI and npm with an injectable fetcher, on-disk
  cache with TTL, `--offline` mode, and honest "unverified" handling of network
  errors / non-404 statuses.
* Typosquat detection via optimal string alignment distance against bundled
  top-1000 popularity lists per ecosystem (adjacent transposition = 1 edit).
* Findings: `SQ-NOT-FOUND` (high), `SQ-TYPOSQUAT` (high/medium), `SQ-UNVERIFIED`
  (low), with deterministic ordering.
* CLI `python -m slopsquat_guard scan|verify` with `--json`,
  `--fail-on {low,medium,high}`, `--offline`, `--cache`, `--ttl-days`, `--refresh`,
  `--allow` and exit codes 0/1/2.
* Bundled popularity lists with cited headers and a reproducible refresh script
  (`scripts/refresh_popularity.py`); provenance in `docs/DATA_SOURCES.md`.
* Synthetic LLM-style example manifests (labelled), a real-package control
  manifest, and a committed real registry cache snapshot for deterministic CI.
* 92 unit tests with a mocked registry fetcher, JSON Schemas for findings / scan
  results / verify results, GitHub Actions CI on Python 3.10–3.13.
* Evidence capture (`scripts/capture_evidence.py`): offline scan, live PyPI/npm
  scan with real HTTP statuses, single-name verification, CLI exit codes,
  terminal screenshots, `docs/EVIDENCE.md`.

### Notes

* Registry presence does not mean a package is safe. This tool flags names that are
  absent or near-misses of popular packages; it is not a malware scanner.
* Popularity lists are dated public download rankings
  (retrieved 2026-11-26), not security endorsements. See `docs/DATA_SOURCES.md`.

## [Unreleased]

- (planned) optional OSV.dev advisory lookup as an extra signal, clearly separated
  from the name-existence verdict.
