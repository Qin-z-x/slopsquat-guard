## slopsquat-guard v0.1.0

Find hallucinated and typosquatted dependency names before you install them, with a
standard-library-only Python core and a deterministic offline mode.

### What is included

- `python -m slopsquat_guard scan|verify` with `--json`,
  `--fail-on {low,medium,high}` CI gating (exit codes 0/1/2), `--offline`,
  `--cache`, `--ttl-days`, `--refresh` and repeated `--allow NAME`.
- Dependency extraction from: Python AST imports (stdlib, relative and local
  modules ignored; curated import→distribution aliases), `requirements.txt` /
  `constraints*.txt` (local `-r`/`-c` includes, extras/markers stripped),
  `pyproject.toml` (`tomllib` on 3.11+, built-in fallback on 3.10), and
  `package.json` (all dependency sections, scoped names, workspace/file/git specs
  skipped).
- Real registry verification against PyPI and npm through an **injectable fetcher**
  with an on-disk cache; network errors are reported as `SQ-UNVERIFIED` (low), never
  as missing.
- Typosquat detection with optimal string alignment distance (adjacent transposition
  = 1 edit) against **bundled top-1000 popularity lists per ecosystem**, with cited
  data sources, retrieval date and a reproducible refresh script.
- 92 unit tests (unittest + pytest, mocked registry), GitHub Actions CI on Python
  3.10–3.13 with deterministic offline scans (no network), JSON Schemas.
- Evidence: offline scan of a synthetic LLM-style manifest flags **11 of 25**
  dependency names high (8 invented/absent names + 3 near-miss typos such as
  `reqeusts`→`requests`); real-package control manifest has **0 findings**; a live
  PyPI/npm run reproduced the same 11 findings from 23 real registry answers
  (`docs/EVIDENCE.md`, `evidence/registry_cache_live.json`).

### Honest notes

- Registry presence is **not** a safety signal. This tool flags *names* that are
  absent or near-misses of popular packages; it is not a malware scanner and not a
  guarantee that a model's suggested package is the one it meant.
- Import-name ↔ distribution-name aliases are curated and incomplete; unmapped
  internal imports can be false positives (use `--allow`). Private registries and
  vendored packages are out of scope.
- Popularity lists are dated public download rankings (retrieved 2026-11-26), not a
  security ranking. The npm list is unscoped-only because the bulk downloads API
  does not support scoped names.
- The example manifests are synthetic and clearly labelled; invented names were
  verified absent at capture time. Do not install them.
