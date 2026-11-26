"""Popularity lists and edit-distance tests."""

from __future__ import annotations

import unittest

from slopsquat_guard.popular import (
    PopularLists,
    list_metadata,
    normalize,
    normalize_npm,
    normalize_pypi,
    osa_distance,
    typo_threshold,
)
from tests.helpers import make_popular


class NormalizationTests(unittest.TestCase):
    def test_pep503_normalization(self):
        self.assertEqual(normalize_pypi("Foo_Bar.baz"), "foo-bar-baz")
        self.assertEqual(normalize_pypi("  Requests "), "requests")
        self.assertEqual(normalize_pypi("typing_extensions"), "typing-extensions")

    def test_npm_normalization(self):
        self.assertEqual(normalize_npm("@Scope/Package"), "@scope/package")
        self.assertEqual(normalize("npm", "Lodash"), "lodash")
        self.assertEqual(normalize("pypi", "A_B"), "a-b")


class DistanceTests(unittest.TestCase):
    def test_identical(self):
        self.assertEqual(osa_distance("requests", "requests"), 0)

    def test_substitution(self):
        self.assertEqual(osa_distance("flask", "flassk"), 1)

    def test_adjacent_transposition_costs_one(self):
        self.assertEqual(osa_distance("requests", "reqeusts"), 1)
        self.assertEqual(osa_distance("numpy", "numpyy"), 1)

    def test_insertion_and_deletion(self):
        self.assertEqual(osa_distance("axios", "axio"), 1)
        self.assertEqual(osa_distance("react", "raect"), 1)

    def test_max_distance_short_circuit(self):
        self.assertGreater(osa_distance("a", "abcdefgh", max_distance=1), 1)

    def test_thresholds(self):
        self.assertEqual(typo_threshold("react"), 1)
        self.assertEqual(typo_threshold("express"), 1)
        self.assertEqual(typo_threshold("typescript"), 2)


class NearMissTests(unittest.TestCase):
    def setUp(self):
        self.popular = make_popular()

    def test_transposition_is_near_miss(self):
        near = self.popular.near_miss("pypi", "reqeusts")
        self.assertEqual(near["target"], "requests")
        self.assertEqual(near["distance"], 1)

    def test_added_character_is_near_miss(self):
        near = self.popular.near_miss("pypi", "numpyy")
        self.assertEqual(near["target"], "numpy")

    def test_popular_exact_name_is_not_near_miss(self):
        self.assertIsNone(self.popular.near_miss("pypi", "requests"))

    def test_unrelated_name_is_not_near_miss(self):
        self.assertIsNone(self.popular.near_miss("pypi", "some-completely-different-package"))

    def test_short_name_two_edits_is_not_flagged(self):
        self.assertIsNone(self.popular.near_miss("pypi", "raex"))

    def test_long_name_two_edits_is_flagged(self):
        near = self.popular.near_miss("npm", "typescriptt")
        self.assertEqual(near["target"], "typescript")

    def test_npm_scoped_near_miss(self):
        popular = make_popular(npm=("@scope/core", "react"))
        near = popular.near_miss("npm", "@scope/corex")
        self.assertEqual(near["target"], "@scope/core")


class BundledListTests(unittest.TestCase):
    def test_lists_have_1000_unique_names(self):
        popular = PopularLists()
        for ecosystem in ("pypi", "npm"):
            names = popular.names[ecosystem]
            self.assertEqual(len(names), 1000, ecosystem)
            self.assertEqual(len(set(names)), 1000, ecosystem)

    def test_pypi_list_starts_with_very_popular_packages(self):
        names = set(PopularLists().names["pypi"])
        for expected in ("requests", "urllib3", "packaging"):
            self.assertIn(expected, names)

    def test_npm_list_contains_common_packages(self):
        names = set(PopularLists().names["npm"])
        for expected in ("react", "lodash", "express", "typescript"):
            self.assertIn(expected, names)

    def test_list_headers_cite_sources(self):
        pypi = list_metadata("pypi")
        npm = list_metadata("npm")
        self.assertTrue(any("top-pypi-packages" in line for line in pypi["header"]))
        self.assertTrue(any("npm" in line.lower() for line in npm["header"]))
        self.assertTrue(any("Regenerate" in line for line in pypi["header"]))
        self.assertTrue(any("not a security endorsement" in line for line in npm["header"]))


if __name__ == "__main__":
    unittest.main()
