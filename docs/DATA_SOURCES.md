# Data sources for the bundled popularity lists

`slopsquat-guard` flags a name as a typosquat suspect when it is 1–2 edits away from
a **popular** package name. "Popular" is computed from public download statistics,
not from any opinion about security. This document records exactly where the
bundled lists came from, how to reproduce them, and what they do **not** mean.

## Files

| File | Ecosystem | Names | sha256 | Ranked by |
| --- | --- | --- | --- | --- |
| `slopsquat_guard/data/pypi_top1000.txt` | PyPI | 1000 | `7a2a9c07a12e691c93708e780500c90c5011d58bbe666640088809eefe5e60d1` | download_count over the last 30 days |
| `slopsquat_guard/data/npm_top1000.txt` | npm | 1000 | `30adfb1aec8082d4d8b70d94533b039a3592cf31cca5110d4dc18771ff3b29c5` | weekly download count |

Retrieved/ranked on **2026-11-26 (UTC)** by `scripts/refresh_popularity.py`.
Each file starts with a header comment repeating these fields plus the
"not a security endorsement" note; the loader ignores `#` lines.

## PyPI source

* URL: <https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json>
* What it is: a public dataset of PyPI download counts over a rolling 30-day window.
* How used: take the rows in the order provided by the dataset (already ranked by
  `download_count`) and keep the first 1000 unique project names, one per line.

## npm source

* Candidate discovery: <https://registry.npmjs.org/-/v1/search> — 52 keyword queries
  (`react`, `webpack`, `eslint`, …), up to 250 results each. The registry search API
  is rate limited; the refresh script spaces queries and retries HTTP 429.
* Ranking: <https://api.npmjs.org/downloads/point/last-week/<comma-separated-names>>
  — real weekly download counts, fetched in batches of 25.
* Limitation: the npm bulk downloads endpoint does **not** support scoped packages
  (`HTTP 400: scoped packages are not currently supported in bulk lookups`), so the
  bundled npm list contains **unscoped package names only**. Scoped names are still
  extracted and verified during scans; they are just not part of the popular-name
  typosquat baseline.

## Regenerating

```bash
python scripts/refresh_popularity.py
```

The script:

1. downloads the PyPI dataset and writes the top 1000 names;
2. collects npm candidates from the registry search API (cached locally during a
   run to avoid refetching);
3. ranks unscoped npm candidates by weekly downloads and writes the top 1000;
4. refuses to write a list with fewer than 1000 or with duplicates.

Review the resulting diff (names and header dates change) before committing.

## Real registry snapshot (offline mode)

`examples/registry_cache.json` is a **real captured snapshot** of registry answers
produced during evidence capture on 2026-11-26 (25 entries, each with HTTP status
and `checked_at`). It is used so CI can run deterministic offline scans with
`--offline --cache examples/registry_cache.json`, with no network access.

It is a snapshot, not a live guarantee: registry answers can change. Refresh it
deliberately by re-running `python scripts/capture_evidence.py` (network) and
committing the result.

## What these lists are not

* **Not a security ranking.** A high download count does not mean a package is safe
  or well-maintained; popular packages are also the most attractive typosquat
  targets, which is exactly why they are used here.
* **Not exhaustive.** The typosquat baseline is 1000 names per ecosystem. A
  near-miss of a package outside the list will not be flagged (it will still be
  flagged as `SQ-NOT-FOUND` if it does not exist).
* **Not current forever.** Lists are dated; refresh them on a schedule you choose.
* **Not a claim about any individual package.** No list membership is a statement of
  trust or intent.
