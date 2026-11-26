# Threat model: hallucinated and typosquatted dependencies

This document explains what `slopsquat-guard` defends against, what it does not
claim, and where its heuristics can go wrong.

> **Honesty statement.** This is a name-verification and typosquat-risk tool, not a
> malware scanner. It does not disclose a new vulnerability and does not claim a new
> CVE. Package hallucination and slopsquatting are public, documented phenomena; the
> citations are at the end. The example manifests are synthetic and clearly labelled.

## 1. The attack

LLMs write code. They also write installation instructions and dependency
manifests. Because model output is generated from statistical patterns, models
sometimes name **packages that do not exist** — plausible-sounding combinations of
known names, or near-misses of popular ones. The paper *We Have a Package for You!*
(Spracklen et al., 2024) found that 19.7% of recommended packages across tested
models did not exist, with open-source models hallucinating more than commercial
ones.

Package registries accept registrations from anyone. So an attacker can:

1. collect or predict hallucinated names,
2. register them on PyPI/npm (often with a plausible-looking README),
3. wait for developers or CI pipelines to `pip install` / `npm install` the
   model-suggested name.

This is **slopsquatting** — a supply-chain attack that turns a model error into
code execution. Typosquatting is the older cousin: register `reqeusts`, `numpyy`,
`flassk` and wait for hand-typed or generated typos.

The practical danger is not only malicious code: a hallucinated name that exists
because of an unrelated project can also break builds, or install something the
model did not intend. The cheapest mitigation is to **check names before
installing** and to gate generated manifests in CI.

## 2. What the tool checks

For each dependency found in a scanned file or directory:

* **Existence** — real HTTP GET against the public registry:
  * PyPI: `https://pypi.org/pypi/<normalized-name>/json`
  * npm: `https://registry.npmjs.org/<normalized-name>`
  * HTTP 200 → exists; HTTP 404 → missing; any other status or network failure →
    **unverified** (low), never "missing".
* **Near-miss (typosquat) risk** — optimal string alignment distance against a
  bundled top-1000 popularity list per ecosystem. Adjacent transpositions cost 1
  (the most common typo). A name ≤2 edits from a popular package is a suspect.
* **Endpoint of interest** — every dependency record is reported with its source
  file, line, origin (`import`, `requirements`, `pyproject`, `package.json`, …) and
  specifier, so a reviewer can see what would be installed.

Severity:

| Rule | Severity | Condition |
| --- | --- | --- |
| `SQ-NOT-FOUND` | high | name absent from the registry (free to register / hallucinated) |
| `SQ-TYPOSQUAT` | high | name absent **and** near-miss of a popular package |
| `SQ-TYPOSQUAT` | medium | name exists **and** is a near-miss of a popular package (verify intent) |
| `SQ-UNVERIFIED` | low | registry unreachable / unexpected status; not proof of absence |

## 3. Detection strategy and why false positives matter

* **Curated import aliases** — Python imports are module names, registries are
  distribution names (`PIL`→Pillow, `yaml`→PyYAML, `sklearn`→scikit-learn, …). The
  alias map is curated, not exhaustive; an unmapped import that is not on PyPI is
  still reported, but flagged as an "import-only" check.
* **Local modules are ignored** — modules that exist as `.py` files or packages in
  the scanned tree are not treated as external dependencies.
* **Relative imports are ignored** — they are local by definition.
* **`--allow` / `allow`** — internal, private-registry or vendored names can be
  excluded explicitly (recorded in the JSON as `allowed: true`).
* **Network errors do not produce high findings** — a rate limit or offline run is
  "unverified", not "missing". This is deliberate: false "hallucination" alarms on
  a flaky network would make the tool untrustworthy.
* **URL/VCS/editable/workspace specs are skipped** — they are not registry names.
* **Specifier/extras/markers are stripped** — only the name is checked.

The trade-off is explicit: an existing package can be a malicious typosquat that
already exists (reported medium), and a hallucinated name that happens to be
another legitimate package cannot be detected by existence checking at all. The
tool is a **targeted signal**, not a safety verdict.

## 4. Non-goals / out of scope

* Not a malware scanner and not a package-safety review: existing packages are not
  inspected for malicious content, install hooks, or maintainer reputation.
* Not a complete import-name ↔ distribution-name resolver; the alias map is
  curated.
* Private registries, vendored wheels, local paths and monorepo workspace packages
  are not resolved; use `--allow`.
* Not a model evaluation. It does not claim a particular model's hallucination rate
  beyond the published research cited below.
* The popularity lists are a typosquat heuristic based on public download
  statistics, dated and regenerable; they are not a security ranking.
* No new vulnerability/CVE claim; no weaponized tooling.

## 5. Recommended deployment

1. Run `slopsquat-guard scan --fail-on high` in CI for any manifest or source tree
   that an LLM touches (especially generated dependency files).
2. Review `SQ-TYPOSQUAT` medium findings manually; they may be intentional names.
3. Use offline mode with a reviewed cache snapshot in locked-down runners
   (`--offline --cache <snapshot>`), and refresh the snapshot deliberately.
4. Keep human review for dependency additions; pair with lockfiles, private
   indexes, and install-time allow-listing. Name verification is one layer.
5. Refreshing the popularity lists is a build-time operation
   (`python scripts/refresh_popularity.py`); review the diff and provenance.

## 6. Data sources (summary)

| Ecosystem | Source | Metric | Notes |
| --- | --- | --- | --- |
| PyPI | [top-pypi-packages](https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json) | 30-day download counts | public dataset |
| npm | [npm registry search](https://registry.npmjs.org/-/v1/search) + [npm downloads API](https://api.npmjs.org/downloads/point/last-week) | weekly downloads | unscoped packages only (bulk API limitation) |

Full detail, retrieval dates and regeneration steps:
[`DATA_SOURCES.md`](DATA_SOURCES.md).

## 7. References

1. J. Spracklen, R. Wijewickrama, A. H. M. N. Sakib, M. Jadliwala, B. Viswanath,
   *We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by
   Code Generating LLMs*, arXiv:2406.10279, <https://arxiv.org/abs/2406.10279>.
2. "Slopsquatting" — term coined by Seth Larson (Python Software Foundation);
   overview and examples: <https://socket.dev/glossary/slopsquatting>.
3. OWASP Top 10 for LLM Applications, **LLM03:2025 Supply Chain**:
   <https://genai.owasp.org/llmrisk/llm032025-supply-chain/>.
4. PyPI/npm public registry APIs used for existence checks:
   <https://pypi.org/pypi/>, <https://registry.npmjs.org/>.

These citations describe prior art and data sources. `slopsquat-guard` is
independent and not affiliated with the authors, foundations or registries above.
