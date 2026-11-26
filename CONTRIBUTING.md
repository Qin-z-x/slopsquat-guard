# Contributing to slopsquat-guard

Thanks for helping catch hallucinated and typosquatted dependencies. This is a
small, dependency-free project; contributions are expected to stay that way.

## Ground rules

* The `slopsquat_guard/` package must import **only the Python standard library**
  (`scripts/check_core_deps.py` enforces this; `tomllib` is allowed and imported
  defensively for Python 3.10).
* Tests must not touch the network: inject a fake fetcher into `RegistryClient`
  (see `tests/helpers.py`). All tests must pass on Python 3.10–3.13:
  `python -m unittest discover -s tests -t .` and `python -m pytest`.
* Keep results deterministic: stable codes, sorted output, JSON-serializable data,
  no timestamps in scan results.
* Be honest: "unverified" is not "missing"; registry presence is not safety. Update
  `docs/THREAT_MODEL.md` when severity or semantics change.
* Regenerating bundled popularity lists (`python scripts/refresh_popularity.py`) is
  a deliberate, reviewed change; include the new `docs/DATA_SOURCES.md` hashes.

## Development

```bash
git clone https://github.com/Qin-Z-x/slopsquat-guard.git
cd slopsquat-guard
python -m pip install -e ".[dev]"

python scripts/check_core_deps.py
python -m unittest discover -s tests -t .
python -m pytest
python -m slopsquat_guard scan --path examples/llm_manifest --offline --cache examples/registry_cache.json
```

## Pull requests

1. Describe the extraction case, registry behaviour or false positive with a minimal
   example.
2. Add tests (`tests/test_extract.py`, `tests/test_registry.py`,
   `tests/test_scan.py`, `tests/test_popular.py`, or `tests/test_cli.py`).
3. Update schemas/docs if output changes; regenerate `docs/EVIDENCE.md` if the
   evidence changes.
4. CI must be green (offline scans only, no secrets).

## Reporting security issues

Please use GitHub Security Advisories for this repository. Evasion reports and
false-positive reports are welcome; both are documented as limitations rather than
silently patched over.
