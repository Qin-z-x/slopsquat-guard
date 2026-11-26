# Video assets — slopsquat-guard (5-minute demo)

All commands below were run on the build machine; quoted outputs are copied from
the captured evidence. Raw material: `docs/screenshots/`, `docs/EVIDENCE.md`,
`evidence/`.

## Files ready for the edit

| asset | path | what it shows |
| --- | --- | --- |
| Offline scan terminal | `docs/screenshots/terminal_scan.png` | 25 dependencies, 11 high findings, `--fail-on high` exit 1, clean control exit 0 |
| Verify terminal | `docs/screenshots/terminal_verify.png` | `verify requests` (exists) vs `verify reqeusts` (typosquat high) |
| Test terminal | `docs/screenshots/terminal_tests.png` | 92 tests passing |
| Raw evidence | `docs/EVIDENCE.md` | offline + live scans, real HTTP statuses, list hashes |

## Suggested 5-minute structure

| time | beat | command / asset | expected output (real) |
| --- | --- | --- | --- |
| 0:00–0:30 | Hook: "the model invented a package name — and someone registered it" | `docs/screenshots/terminal_scan.png`; paper arXiv:2406.10279 (19.7% missing) | `HIGH SQ-TYPOSQUAT pypi reqeusts … 1 edit(s) from popular 'requests'` |
| 0:30–1:10 | What slopsquatting is | `docs/THREAT_MODEL.md` §1 | hallucinated names are free to register; CI installs them |
| 1:10–1:50 | Scan a synthetic LLM manifest | `python -m slopsquat_guard scan --path examples/llm_manifest --offline --cache examples/registry_cache.json` | `summary: 11 finding(s): 11 high … 25 dependencies: 14 verified, 11 missing` |
| 1:50–2:20 | CI gate | add `--fail-on high` | `FAIL: 11 finding(s) at or above severity 'high'`, `[exit code: 1]` |
| 2:20–2:55 | Real packages pass | `python -m slopsquat_guard scan --path examples/clean_manifest --offline --cache examples/registry_cache.json --fail-on high` | `summary: 0 finding(s) … OK`, `[exit code: 0]` |
| 2:55–3:30 | Live registry check (not a canned list) | `python -m slopsquat_guard verify reqeusts` (network) | `missing`, near-miss of `requests`, `SQ-TYPOSQUAT` high |
| 3:30–4:05 | Data provenance / honesty | `docs/DATA_SOURCES.md` | top-1000 by public downloads; lists dated 2026-11-26; registry presence ≠ safety |
| 4:05–4:35 | Offline reproducibility in CI | `--offline --cache examples/registry_cache.json` | same 11 findings, no network, deterministic JSON sha256 |
| 4:35–4:50 | Tests | `python -m unittest discover -s tests -t .` | `Ran 92 tests … OK` |
| 4:50–5:00 | Limits + call to action | `docs/THREAT_MODEL.md` §4 | not a malware scanner; aliases curated; use `--allow` for internal names |

## Exact commands for screen recording

```bash
# 1. Deterministic offline scan (no network)
python -m slopsquat_guard scan --path examples/llm_manifest --offline --cache examples/registry_cache.json

# 2. CI gate (expected exit 1)
python -m slopsquat_guard scan --path examples/llm_manifest --offline --cache examples/registry_cache.json --fail-on high

# 3. Control manifest (expected exit 0)
python -m slopsquat_guard scan --path examples/clean_manifest --offline --cache examples/registry_cache.json --fail-on high

# 4. Single-name checks (offline snapshot, then live if desired)
python -m slopsquat_guard verify requests --offline --cache examples/registry_cache.json
python -m slopsquat_guard verify reqeusts --offline --cache examples/registry_cache.json --fail-on high
python -m slopsquat_guard verify react --ecosystem npm --offline --cache examples/registry_cache.json

# 5. JSON for the overlay
python -m slopsquat_guard scan --path examples/llm_manifest --offline --cache examples/registry_cache.json --json

# 6. Tests
python -m unittest discover -s tests -t .
```

## Key on-screen numbers (copy-safe)

* 25 dependencies extracted from 3 manifest types + Python imports.
* 11 high findings: 8 invented/absent names + 3 typosquat near-misses.
* 14 real dependency names verified, **0** false high findings.
* Control manifest: 0 findings, gate exit 0.
* Live run: same 11 findings from 23 real registry answers.
* 92 tests, all passing.

## Caveats to state on camera

* Registry presence ≠ safety; this is a name-check, not a malware scan.
* Import-name→distribution-name aliases are curated; unmapped internal imports can be
  false positives (use `--allow`).
* The popularity lists are public download rankings (dated 2026-11-26), not a
  security ranking. The npm list is unscoped-only due to the bulk API limitation.
* The synthetic manifest's invented names were verified absent at capture time and
  are clearly labelled; do not install them.
