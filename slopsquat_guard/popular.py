"""Bundled popularity lists + edit distance for typosquat (near-miss) detection.

The lists under ``data/`` are the top 1000 packages per ecosystem by public
download statistics; see ``docs/DATA_SOURCES.md`` for the exact sources and
``scripts/refresh_popularity.py`` to regenerate them. Popularity is used only as
a *typosquat-target heuristic*: being popular does not mean a package is safe,
and being absent from the list does not mean a package is malicious.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
DATA_DIR = PACKAGE_DIR / "data"
LIST_FILES = {"pypi": "pypi_top1000.txt", "npm": "npm_top1000.txt"}


def normalize_pypi(name: str) -> str:
    """PEP 503 normalization: ``Foo_Bar.baz`` -> ``foo-bar-baz``."""
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def normalize_npm(name: str) -> str:
    return name.strip().lower()


def normalize(ecosystem: str, name: str) -> str:
    return normalize_pypi(name) if ecosystem == "pypi" else normalize_npm(name)


def load_list(ecosystem: str, directory: Path | None = None) -> list[str]:
    path = (directory or DATA_DIR) / LIST_FILES[ecosystem]
    names: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        names.append(line)
    return names


def load_lists(directory: Path | None = None) -> dict[str, list[str]]:
    return {ecosystem: load_list(ecosystem, directory) for ecosystem in LIST_FILES}


def list_metadata(ecosystem: str, directory: Path | None = None) -> dict:
    path = (directory or DATA_DIR) / LIST_FILES[ecosystem]
    header = []
    names = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            header.append(line[2:])
        elif line.strip():
            names.append(line.strip())
    return {"path": "slopsquat_guard/data/" + LIST_FILES[ecosystem], "names": len(names), "header": header}


def osa_distance(left: str, right: str, max_distance: int | None = None) -> int:
    """Optimal string alignment distance (Levenshtein + adjacent transposition = 1).

    Adjacent transpositions are the most common hand-typed typos
    ("reqeusts" -> "requests"), so they must cost 1, not 2.
    """
    if left == right:
        return 0
    left_len, right_len = len(left), len(right)
    if max_distance is not None and abs(left_len - right_len) > max_distance:
        return max_distance + 1
    previous_previous: list[int] = []
    previous = list(range(right_len + 1))
    for i in range(1, left_len + 1):
        current = [i] + [0] * right_len
        for j in range(1, right_len + 1):
            cost = 0 if left[i - 1] == right[j - 1] else 1
            current[j] = min(
                previous[j] + 1,  # deletion
                current[j - 1] + 1,  # insertion
                previous[j - 1] + cost,  # substitution
            )
            if (
                i > 1
                and j > 1
                and left[i - 1] == right[j - 2]
                and left[i - 2] == right[j - 1]
            ):
                current[j] = min(current[j], previous_previous[j - 2] + 1)  # transposition
        previous_previous, previous = previous, current
    return previous[right_len]


def typo_threshold(name: str) -> int:
    """How many edits away from a popular name still counts as a typo suspect."""
    length = len(name)
    if length <= 4:
        return 1
    if length <= 7:
        return 1
    return 2


def find_near_miss(ecosystem: str, name: str, popular: "PopularLists") -> dict | None:
    normalized = normalize(ecosystem, name)
    if not normalized or normalized in popular.normalized[ecosystem]:
        return None
    threshold = typo_threshold(normalized)
    best: dict | None = None
    for candidate in popular.names[ecosystem]:
        candidate_normalized = popular.normalized[ecosystem + "_map"][candidate]
        if abs(len(candidate_normalized) - len(normalized)) > threshold:
            continue
        distance = osa_distance(normalized, candidate_normalized, max_distance=threshold)
        if distance == 0 or distance > threshold:
            continue
        rank = popular.rank[ecosystem].get(candidate_normalized, 10**9)
        record = {
            "target": candidate,
            "target_normalized": candidate_normalized,
            "distance": distance,
            "popularity_rank": rank if rank != 10**9 else None,
            "ecosystem": ecosystem,
        }
        if best is None or (distance, rank) < (best["distance"], best["popularity_rank"] or 10**9):
            best = record
    return best


class PopularLists:
    """Loaded popularity lists with normalized indexes."""

    def __init__(self, names: dict[str, list[str]] | None = None, directory: Path | None = None):
        raw = names if names is not None else load_lists(directory)
        self.names: dict[str, list[str]] = {}
        self.normalized: dict[str, set[str]] = {}
        self.rank: dict[str, dict[str, int]] = {}
        for ecosystem in LIST_FILES:
            values = list(raw.get(ecosystem, []))
            self.names[ecosystem] = values
            mapping: dict[str, str] = {}
            normalized_set: set[str] = set()
            ranks: dict[str, int] = {}
            for index, value in enumerate(values, start=1):
                key = normalize(ecosystem, value)
                mapping[value] = key
                normalized_set.add(key)
                ranks.setdefault(key, index)
            self.normalized[ecosystem] = normalized_set
            self.normalized[ecosystem + "_map"] = mapping
            self.rank[ecosystem] = ranks

    def near_miss(self, ecosystem: str, name: str) -> dict | None:
        return find_near_miss(ecosystem, name, self)

    def metadata(self) -> dict:
        return {
            "pypi": {"count": len(self.names["pypi"]), "source": list_metadata("pypi")},
            "npm": {"count": len(self.names["npm"]), "source": list_metadata("npm")},
        }


def default_popular() -> PopularLists:
    return PopularLists()


def warn_if_missing() -> None:
    for ecosystem in LIST_FILES:
        if not (DATA_DIR / LIST_FILES[ecosystem]).is_file():
            print("warning: popularity list missing for %s" % ecosystem, file=sys.stderr)
