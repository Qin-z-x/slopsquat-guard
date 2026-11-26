"""Dependency extraction tests: requirements, pyproject, package.json, imports."""

from __future__ import annotations

import textwrap
import unittest

from slopsquat_guard.core import (
    ParseError,
    extract_dependencies,
    parse_package_json,
    parse_pyproject,
    parse_python_imports,
    parse_requirements,
    split_requirement,
)


def names(dependencies):
    return [(dependency.ecosystem, dependency.name, dependency.normalized) for dependency in dependencies]


class RequirementsTests(unittest.TestCase):
    def test_basic_names_and_specifiers(self):
        dependencies = parse_requirements("requests>=2.31\nflask==3.0.3\n", "requirements.txt")
        self.assertEqual(names(dependencies), [("pypi", "requests", "requests"), ("pypi", "flask", "flask")])
        self.assertEqual(dependencies[0].specifier, ">=2.31")
        self.assertEqual(dependencies[1].line, 2)

    def test_extras_and_markers_are_stripped(self):
        dependencies = parse_requirements('uvicorn[standard]>=0.30; python_version >= "3.10"\n', "requirements.txt")
        self.assertEqual(dependencies[0].name, "uvicorn")
        self.assertEqual(dependencies[0].specifier, "[standard]>=0.30")

    def test_comments_and_blank_lines_ignored(self):
        text = "# comment\n\nrequests  # inline comment\n"
        self.assertEqual([dependency.name for dependency in parse_requirements(text, "requirements.txt")], ["requests"])

    def test_include_file_is_followed(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "base.txt").write_text("requests>=2.31\n", encoding="utf-8")
            (root / "requirements.txt").write_text("-r base.txt\nflask\n", encoding="utf-8")
            dependencies = parse_requirements((root / "requirements.txt").read_text(encoding="utf-8"), "requirements.txt", root)
            self.assertEqual([dependency.name for dependency in dependencies], ["requests", "flask"])

    def test_urls_and_vcs_are_skipped(self):
        text = textwrap.dedent(
            """\
            git+https://github.com/example/pkg.git#egg=pkg
            https://example.com/pkg.whl
            -e ./local-package
            --index-url https://pypi.org/simple
            file:../local
            """
        )
        self.assertEqual(parse_requirements(text, "requirements.txt"), [])

    def test_editable_with_hash_is_skipped(self):
        self.assertEqual(parse_requirements("-e git+https://github.com/x/y#egg=z", "requirements.txt"), [])

    def test_split_requirement_returns_none_for_options(self):
        self.assertIsNone(split_requirement("--index-url https://pypi.org/simple"))
        self.assertIsNone(split_requirement(""))


class PyprojectTests(unittest.TestCase):
    SAMPLE = textwrap.dedent(
        """\
        [build-system]
        requires = ["setuptools>=68", "wheel"]

        [project]
        name = "demo"
        dependencies = [
            "fastapi>=0.111",
            "httpx>=0.27",
        ]

        [project.optional-dependencies]
        dev = ["pytest>=8", "ruff"]

        [tool.poetry.dependencies]
        python = ">=3.10"
        requests = "^2.31"
        """
    )

    def test_tomllib_parsing(self):
        dependencies = parse_pyproject(self.SAMPLE, "pyproject.toml")
        found = {dependency.name: dependency for dependency in dependencies}
        self.assertIn("fastapi", found)
        self.assertIn("httpx", found)
        self.assertIn("pytest", found)
        self.assertIn("setuptools", found)
        self.assertIn("requests", found)
        self.assertNotIn("python", found)
        self.assertEqual(found["requests"].specifier, "^2.31")

    def test_fallback_parser_matches_tomllib_results(self):
        via_tomllib = names(parse_pyproject(self.SAMPLE, "pyproject.toml", use_tomllib=True))
        via_fallback = names(parse_pyproject(self.SAMPLE, "pyproject.toml", use_tomllib=False))
        self.assertEqual(sorted(via_tomllib), sorted(via_fallback))

    def test_fallback_handles_single_line_arrays(self):
        text = '[project]\nname = "x"\ndependencies = ["requests>=2", "flask"]\n'
        dependencies = parse_pyproject(text, "pyproject.toml", use_tomllib=False)
        self.assertEqual([dependency.name for dependency in dependencies], ["requests", "flask"])

    def test_empty_pyproject(self):
        self.assertEqual(parse_pyproject("", "pyproject.toml"), [])


class PackageJsonTests(unittest.TestCase):
    SAMPLE = """{
      "name": "demo",
      "dependencies": {"react": "^18.3.1", "lodash": "^4.17.21"},
      "devDependencies": {"typescript": "^5.5.0", "@types/node": "^22.0.0"},
      "peerDependencies": {"react-dom": "^18.0.0"},
      "optionalDependencies": {"fsevents": "^2.3.0"}
    }"""

    def test_all_dependency_sections(self):
        dependencies = parse_package_json(self.SAMPLE, "package.json")
        found = {dependency.name for dependency in dependencies}
        self.assertEqual(found, {"react", "lodash", "typescript", "@types/node", "react-dom", "fsevents"})

    def test_scoped_names_are_preserved(self):
        dependencies = parse_package_json(self.SAMPLE, "package.json")
        scoped = [dependency for dependency in dependencies if dependency.name.startswith("@")]
        self.assertEqual(scoped[0].name, "@types/node")
        self.assertEqual(scoped[0].normalized, "@types/node")

    def test_workspace_and_url_specs_are_skipped(self):
        text = """{
          "dependencies": {
            "local-a": "workspace:*",
            "local-b": "file:../b",
            "git-dep": "git+https://github.com/x/y.git",
            "alias": "npm:lodash@^4",
            "normal": "^1.0.0"
          }
        }"""
        dependencies = parse_package_json(text, "package.json")
        self.assertEqual([dependency.name for dependency in dependencies], ["normal"])

    def test_invalid_json_raises_parse_error(self):
        with self.assertRaises(ParseError):
            parse_package_json("{not json", "package.json")


class PythonImportTests(unittest.TestCase):
    def test_side_effect_imports(self):
        dependencies = parse_python_imports("import requests\nimport os\n", "app.py")
        top = [dependency.name for dependency in dependencies]
        self.assertIn("requests", top)
        self.assertNotIn("os", top)

    def test_from_imports(self):
        dependencies = parse_python_imports("from flask import Flask\nfrom . import local\n", "app.py")
        self.assertEqual([dependency.name for dependency in dependencies], ["flask"])

    def test_stdlib_and_local_modules_skipped(self):
        dependencies = parse_python_imports("import json\nimport local_helpers\n", "app.py", local_modules={"local_helpers"})
        self.assertEqual(dependencies, [])

    def test_curated_aliases_map_import_to_distribution(self):
        dependencies = parse_python_imports("from PIL import Image\nimport yaml\n", "app.py")
        by_import = {dependency.import_name: dependency.name for dependency in dependencies}
        self.assertEqual(by_import["PIL"], "Pillow")
        self.assertEqual(by_import["yaml"], "PyYAML")

    def test_duplicate_imports_are_deduplicated(self):
        dependencies = parse_python_imports("import requests\nimport requests\nfrom requests import Session\n", "app.py")
        self.assertEqual([dependency.name for dependency in dependencies], ["requests"])

    def test_syntax_error_raises(self):
        with self.assertRaises(ParseError):
            parse_python_imports("def broken(:\n", "app.py")


class ExtractionIntegrationTests(unittest.TestCase):
    def test_extract_dependencies_from_examples(self):
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent / "examples" / "llm_manifest"
        dependencies, errors, stats = extract_dependencies(root)
        names_seen = {dependency.name for dependency in dependencies}
        self.assertEqual(errors, [])
        self.assertIn("requests", names_seen)
        self.assertIn("react", names_seen)
        self.assertIn("llm-utils-magic", names_seen)
        self.assertIn("llm_utils_magic", names_seen)
        self.assertNotIn("json", names_seen)
        self.assertNotIn("local_helpers", names_seen)
        self.assertGreaterEqual(stats["manifest_files"], 3)
        self.assertGreaterEqual(stats["python_files"], 2)

    def test_missing_files_are_reported_not_fatal(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text("{bad", encoding="utf-8")
            dependencies, errors, stats = extract_dependencies(root)
            self.assertEqual(dependencies, [])
            self.assertEqual(len(errors), 1)
            self.assertIn("package.json", errors[0]["file"])


if __name__ == "__main__":
    unittest.main()
