"""slopsquat-guard core: extract dependencies, verify names, flag hallusquat risk.

Threat: LLMs invent package names ("slopsquatting"). Because PyPI/npm allow
anyone to register a name, an attacker can register a hallucinated name and get
code execution when a model-generated manifest is installed. This module finds
those risky names; it does **not** claim that a package which exists is safe.
"""

from __future__ import annotations

import ast
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:  # tomllib is new in Python 3.11; the fallback parser below covers 3.10
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10 CI
    tomllib = None  # type: ignore[assignment]

from .popular import PopularLists, normalize, normalize_npm, normalize_pypi
from .registry import RegistryClient, RegistryResult

VERSION = "0.1.0"
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}

SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "build",
        "dist",
        "site-packages",
        "target",
        ".idea",
        ".vscode",
    }
)
SKIP_FILE_SUFFIXES = frozenset({".pyc", ".pyo", ".so", ".dll", ".dylib"})
REQUIREMENTS_NAMES = frozenset({"requirements.txt", "constraints.txt", "requirements-dev.txt", "requirements-test.txt"})
REQUIREMENTS_PREFIXES = ("requirements", "constraints")

# Curated import-name -> PyPI distribution-name aliases. This is not exhaustive;
# unmapped imports are checked against PyPI under the import name and reported
# honestly as "import-only" findings (see docs/THREAT_MODEL.md).
PYTHON_IMPORT_ALIASES = {
    "pil": "Pillow",
    "cv2": "opencv-python",
    "sklearn": "scikit-learn",
    "skimage": "scikit-image",
    "yaml": "PyYAML",
    "bs4": "beautifulsoup4",
    "dateutil": "python-dateutil",
    "dotenv": "python-dotenv",
    "jwt": "PyJWT",
    "crypto": "pycryptodome",
    "openssl": "pyOpenSSL",
    "mysqlclient": "mysqlclient",
    "mysqldb": "mysqlclient",
    "psycopg2": "psycopg2-binary",
    "grpc": "grpcio",
    "attr": "attrs",
    "attrs": "attrs",
    "serial": "pyserial",
    "usb": "pyusb",
    "magic": "python-magic",
    "mpl_toolkits": "matplotlib",
    "tensorflow": "tensorflow",
    "torch": "torch",
    "torchvision": "torchvision",
    "transformers": "transformers",
    "sentence_transformers": "sentence-transformers",
    "langchain_core": "langchain-core",
    "langchain_openai": "langchain-openai",
    "langchain_community": "langchain-community",
    "pydantic_settings": "pydantic-settings",
    "rest_framework": "djangorestframework",
    "sqlalchemy": "SQLAlchemy",
    "jinja2": "Jinja2",
    "markupsafe": "MarkupSafe",
    "importlib_metadata": "importlib-metadata",
    "typing_extensions": "typing-extensions",
    "pkg_resources": "setuptools",
    "six": "six",
    "pyyaml": "PyYAML",
    "tqdm": "tqdm",
    "wsgi": None,
    "pymysql": "PyMySQL",
}

REQUIREMENT_START_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
URL_SCHEMES = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*://|git\+|file:|hg\+|svn\+)")
INCLUDE_RE = re.compile(r"^(?:-r|--requirement|-c|--constraint)(?:\s+|=)(.+)$")


class ParseError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str
    normalized: str
    source_file: str
    line: int
    specifier: str = ""
    origin: str = "manifest"  # requirements | pyproject | package.json | import
    import_name: str | None = None

    def to_dict(self) -> dict:
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "normalized": self.normalized,
            "source_file": self.source_file,
            "line": self.line,
            "specifier": self.specifier,
            "origin": self.origin,
            "import_name": self.import_name,
        }


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    ecosystem: str
    name: str
    normalized: str
    source_file: str
    line: int
    message: str
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity,
            "ecosystem": self.ecosystem,
            "name": self.name,
            "normalized": self.normalized,
            "source_file": self.source_file,
            "line": self.line,
            "message": self.message,
            "data": self.data,
        }


def severity_at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold]


def summarize(findings: list[Finding]) -> dict:
    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        counts[finding.severity] += 1
    return {"total": len(findings), **counts}


def format_finding_line(finding: Finding) -> str:
    return "%s %-16s %-4s %-28s %s:%d  %s" % (
        finding.severity.upper().ljust(6),
        finding.code,
        finding.ecosystem,
        finding.name,
        finding.source_file,
        finding.line,
        finding.message,
    )


# ---------------------------------------------------------------------------
# Requirement spec parsing
# ---------------------------------------------------------------------------


def split_requirement(spec: str) -> tuple[str, str] | None:
    """Split ``pkg[extra]>=1.0; marker`` into (name, specifier). Returns None if not a name spec."""
    text = spec.strip()
    if not text or text.startswith("-"):
        return None
    if URL_SCHEMES.match(text):
        return None
    text = text.split(";", 1)[0].strip()
    if not text:
        return None
    match = REQUIREMENT_START_RE.match(text)
    if not match:
        return None
    name = match.group(1)
    rest = text[match.end() :].strip()
    return name, rest


def _dependency_for(ecosystem: str, name: str, specifier: str, source: str, line: int, origin: str, import_name=None) -> Dependency:
    normalized = normalize(ecosystem, name)
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        normalized=normalized,
        source_file=source,
        line=line,
        specifier=specifier,
        origin=origin,
        import_name=import_name,
    )


def parse_requirements(text: str, source: str, root: Path | None = None, seen: set[str] | None = None) -> list[Dependency]:
    """Parse requirements/constraints text, following local ``-r``/``-c`` includes."""
    seen = seen if seen is not None else set()
    source_key = str(source)
    if source_key in seen:
        return []
    seen.add(source_key)
    dependencies: list[Dependency] = []
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        include = INCLUDE_RE.match(line)
        if include:
            include_target = include.group(1).strip().strip('"').strip("'")
            if root is not None and include_target and not URL_SCHEMES.match(include_target):
                source_path = Path(source)
                base = root / source_path.parent if not source_path.is_absolute() else source_path.parent
                include_path = (base / include_target).resolve()
                try:
                    include_text = include_path.read_text(encoding="utf-8")
                except OSError:
                    continue
                try:
                    include_label = include_path.relative_to(Path(root).resolve()).as_posix()
                except ValueError:
                    include_label = str(include_path)
                dependencies.extend(parse_requirements(include_text, include_label, root, seen))
            continue
        if line.startswith("-"):
            continue
        parsed = split_requirement(line)
        if not parsed:
            continue
        name, specifier = parsed
        dependencies.append(_dependency_for("pypi", name, specifier, source, lineno, "requirements"))
    return dependencies


# ---------------------------------------------------------------------------
# pyproject.toml parsing (tomllib, with a small fallback parser for Python 3.10)
# ---------------------------------------------------------------------------


def _mini_toml(text: str) -> dict:
    """Parse the small subset of TOML needed for dependency extraction.

    Used only when ``tomllib`` is unavailable (Python 3.10). It understands table
    headers, key = "value", key = { ... } (ignored unless it has a version) and
    multi-line arrays of strings.
    """
    result: dict = {}
    current = result
    current_path: list[str] = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        raw = lines[index]
        line = raw.split("#", 1)[0].strip() if not raw.lstrip().startswith("#") else ""
        index += 1
        if not line:
            continue
        if line.startswith("[") and line.endswith("]") and not line.startswith("[["):
            current_path = [part.strip() for part in line[1:-1].split(".") if part.strip()]
            current = result
            for part in current_path:
                current = current.setdefault(part, {})
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().strip('"').strip("'")
        value = value.strip()
        if value.startswith("["):
            buffer = value
            while "]" not in buffer and index < len(lines):
                buffer += "\n" + lines[index]
                index += 1
            strings = re.findall(r"\"([^\"]*)\"|'([^']*)'", buffer)
            current[key] = [first if first else second for first, second in strings]
        elif value.startswith("{"):
            buffer = value
            while "}" not in buffer and index < len(lines):
                buffer += "\n" + lines[index]
                index += 1
            version = re.search(r"version\s*=\s*[\"']([^\"']+)[\"']", buffer)
            current[key] = {"version": version.group(1)} if version else {}
        else:
            strings = re.findall(r"\"([^\"]*)\"|'([^']*)'", value)
            current[key] = (strings[0][0] if strings and strings[0][0] else (strings[0][1] if strings else value))
    return result


def _toml_strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def parse_pyproject(text: str, source: str, use_tomllib: bool | None = None) -> list[Dependency]:
    data: dict | None = None
    if use_tomllib is None:
        use_tomllib = tomllib is not None
    if use_tomllib and tomllib is not None:
        try:
            data = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError):
            data = None
    if data is None:
        data = _mini_toml(text)
    dependencies: list[Dependency] = []

    def add(specs, origin):
        for spec in specs:
            parsed = split_requirement(spec)
            if parsed:
                name, specifier = parsed
                dependencies.append(_dependency_for("pypi", name, specifier, source, 0, origin))

    project = data.get("project") or {}
    add(_toml_strings(project.get("dependencies")), "pyproject")
    for group, specs in (project.get("optional-dependencies") or {}).items():
        add(_toml_strings(specs), "pyproject optional-dependency [%s]" % group)
    build_system = data.get("build-system") or {}
    add(_toml_strings(build_system.get("requires")), "pyproject build-system")

    poetry = ((data.get("tool") or {}).get("poetry") or {})
    for name, value in (poetry.get("dependencies") or {}).items():
        if str(name).lower() == "python":
            continue
        if isinstance(value, dict):
            specifier = str(value.get("version", "")).strip()
        else:
            specifier = str(value).strip()
        dependencies.append(_dependency_for("pypi", str(name), specifier, source, 0, "pyproject poetry"))

    for group, specs in (data.get("dependency-groups") or {}).items():
        add(_toml_strings(specs), "pyproject dependency-group [%s]" % group)
    return dependencies


# ---------------------------------------------------------------------------
# package.json parsing
# ---------------------------------------------------------------------------


def parse_package_json(text: str, source: str) -> list[Dependency]:
    try:
        payload = json.loads(text)
    except ValueError as exc:
        raise ParseError("invalid JSON: %s" % exc) from exc
    if not isinstance(payload, dict):
        raise ParseError("package.json root is not an object")
    dependencies: list[Dependency] = []
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        values = payload.get(section)
        if not isinstance(values, dict):
            continue
        for name, specifier in values.items():
            name = str(name).strip()
            if not name:
                continue
            specifier = str(specifier).strip()
            if specifier.startswith(("workspace:", "file:", "link:", "portal:")):
                continue
            if URL_SCHEMES.match(specifier) or specifier.startswith("npm:"):
                continue
            dependencies.append(_dependency_for("npm", name, specifier, source, 0, "package.json %s" % section))
    return dependencies


# ---------------------------------------------------------------------------
# Python import extraction
# ---------------------------------------------------------------------------


def _local_module_names(root: Path) -> set[str]:
    if not root.is_dir():
        return set()
    names: set[str] = set()
    for path in root.rglob("*.py"):
        relative = path.relative_to(root)
        if any(part in SKIP_DIRS for part in relative.parts):
            continue
        if path.name == "__init__.py":
            for part in relative.parts[:-1]:
                names.add(part)
        else:
            names.add(path.stem)
    return names


def parse_python_imports(text: str, source: str, local_modules: set[str] | None = None) -> list[Dependency]:
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        raise ParseError("invalid Python: %s" % exc.msg) from exc
    local_modules = local_modules or set()
    stdlib = set(sys.stdlib_module_names)
    dependencies: list[Dependency] = []
    seen: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in seen:
                    continue
                seen.add(top)
                dependency = _import_dependency(top, source, node.lineno, stdlib, local_modules)
                if dependency is not None:
                    dependencies.append(dependency)
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                continue  # relative import: local by definition
            module = (node.module or "").split(".")[0]
            if not module or module in seen:
                continue
            seen.add(module)
            dependency = _import_dependency(module, source, node.lineno, stdlib, local_modules)
            if dependency is not None:
                dependencies.append(dependency)
    return [dependency for dependency in dependencies if dependency is not None]


def _import_dependency(module: str, source: str, line: int, stdlib: set[str], local_modules: set[str]) -> Dependency | None:
    if not module or module in stdlib or module in local_modules or module == "__future__":
        return None
    alias = PYTHON_IMPORT_ALIASES.get(module.lower())
    if alias is None and module.lower() in PYTHON_IMPORT_ALIASES:
        return None  # explicit "not a PyPI distribution" entry
    distribution = alias or module
    return _dependency_for("pypi", distribution, "", source, line, "import", import_name=module)


# ---------------------------------------------------------------------------
# File discovery and extraction
# ---------------------------------------------------------------------------


def classify_file(path: Path) -> str | None:
    name = path.name
    if path.suffix == ".py":
        return "python"
    if name == "pyproject.toml":
        return "pyproject"
    if name == "package.json":
        return "package-json"
    if path.suffix == ".txt" and (name in REQUIREMENTS_NAMES or name.startswith(REQUIREMENTS_PREFIXES)):
        return "requirements"
    return None


def discover_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root] if classify_file(root) else []
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in SKIP_DIRS for part in relative.parts):
            continue
        if path.suffix in SKIP_FILE_SUFFIXES:
            continue
        if classify_file(path):
            files.append(path)
    return files


def extract_dependencies(root: Path, include_imports: bool = True) -> tuple[list[Dependency], list[dict], dict]:
    """Return (dependencies, parse_errors, stats) for a file or directory."""
    dependencies: list[Dependency] = []
    errors: list[dict] = []
    files = discover_files(root)
    local_modules = _local_module_names(root) if root.is_dir() else _local_module_names(root.parent)
    stats = {"files_scanned": 0, "python_files": 0, "manifest_files": 0}
    for path in files:
        kind = classify_file(path)
        if kind is None:
            continue
        source = path.name if root.is_file() else path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            errors.append({"file": source, "error": "cannot read UTF-8: %s" % exc})
            continue
        stats["files_scanned"] += 1
        try:
            if kind == "python":
                stats["python_files"] += 1
                if include_imports:
                    dependencies.extend(parse_python_imports(text, source, local_modules))
            elif kind == "requirements":
                stats["manifest_files"] += 1
                dependencies.extend(parse_requirements(text, source, root if root.is_dir() else root.parent))
            elif kind == "pyproject":
                stats["manifest_files"] += 1
                dependencies.extend(parse_pyproject(text, source))
            elif kind == "package-json":
                stats["manifest_files"] += 1
                dependencies.extend(parse_package_json(text, source))
        except ParseError as exc:
            errors.append({"file": source, "error": str(exc)})
    dependencies.sort(key=lambda dep: (dep.source_file, dep.line, dep.ecosystem, dep.normalized))
    return dependencies, errors, stats


# ---------------------------------------------------------------------------
# Scan orchestration
# ---------------------------------------------------------------------------


def _nearest(popular: PopularLists, dependency: Dependency) -> dict | None:
    return popular.near_miss(dependency.ecosystem, dependency.normalized)


def _finding_for(dependency: Dependency, result: RegistryResult, near: dict | None) -> Finding | None:
    common = {
        "ecosystem": dependency.ecosystem,
        "name": dependency.name,
        "normalized": dependency.normalized,
        "source_file": dependency.source_file,
        "line": dependency.line,
        "origin": dependency.origin,
        "import_name": dependency.import_name,
        "specifier": dependency.specifier,
        "exists": result.exists,
        "registry_source": result.source,
        "registry_status": result.status,
        "near_miss": near,
    }
    if result.exists is False:
        if near:
            return Finding(
                code="SQ-TYPOSQUAT",
                severity="high",
                ecosystem=dependency.ecosystem,
                name=dependency.name,
                normalized=dependency.normalized,
                source_file=dependency.source_file,
                line=dependency.line,
                message="name does not exist in %s and is %d edit(s) from popular %r (typosquat/hallucination risk)"
                % (dependency.ecosystem, near["distance"], near["target"]),
                data=common,
            )
        suffix = " (import-only check; the distribution name may differ)" if dependency.origin == "import" else ""
        return Finding(
            code="SQ-NOT-FOUND",
            severity="high",
            ecosystem=dependency.ecosystem,
            name=dependency.name,
            normalized=dependency.normalized,
            source_file=dependency.source_file,
            line=dependency.line,
            message="name does not exist in %s: likely a hallucinated/free-to-register name%s"
            % (dependency.ecosystem, suffix),
            data=common,
        )
    if result.exists is True:
        if near:
            return Finding(
                code="SQ-TYPOSQUAT",
                severity="medium",
                ecosystem=dependency.ecosystem,
                name=dependency.name,
                normalized=dependency.normalized,
                source_file=dependency.source_file,
                line=dependency.line,
                message="name exists in %s but is %d edit(s) from popular %r: verify this is intentional"
                % (dependency.ecosystem, near["distance"], near["target"]),
                data=common,
            )
        return None
    return Finding(
        code="SQ-UNVERIFIED",
        severity="low",
        ecosystem=dependency.ecosystem,
        name=dependency.name,
        normalized=dependency.normalized,
        source_file=dependency.source_file,
        line=dependency.line,
        message="could not verify %r in %s (%s); not treated as missing" % (dependency.name, dependency.ecosystem, result.note or result.source),
        data=common,
    )


def scan_path(
    path: str | Path,
    client: RegistryClient | None = None,
    popular: PopularLists | None = None,
    allow: set[str] | list[str] | tuple[str, ...] = (),
    include_imports: bool = True,
) -> dict:
    """Scan a file or directory for hallucinated/typosquatted dependencies."""
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(str(path))
    client = client or RegistryClient()
    popular = popular or PopularLists()
    allow_set = {str(item).strip().lower() for item in allow if str(item).strip()}

    dependencies, errors, stats = extract_dependencies(root, include_imports=include_imports)
    findings: list[Finding] = []
    records: list[dict] = []
    for dependency in dependencies:
        if dependency.normalized in allow_set or dependency.name.lower() in allow_set:
            records.append({**dependency.to_dict(), "registry": None, "near_miss": None, "allowed": True, "finding": None})
            continue
        result = client.check(dependency.ecosystem, dependency.normalized)
        near = _nearest(popular, dependency)
        finding = _finding_for(dependency, result, near)
        if finding:
            findings.append(finding)
        records.append(
            {
                **dependency.to_dict(),
                "registry": result.to_dict(),
                "near_miss": near,
                "allowed": False,
                "finding": finding.to_dict() if finding else None,
            }
        )
    findings.sort(key=lambda finding: (finding.source_file, finding.line, finding.code, finding.ecosystem, finding.normalized))
    client.save()
    registry_calls = dict(client.calls)
    summary = summarize(findings)
    summary.update(
        {
            "dependencies": len(records),
            "checked": sum(1 for record in records if record["registry"] and record["registry"]["exists"] is not None),
            "not_found": sum(1 for record in records if record["registry"] and record["registry"]["exists"] is False),
            "verified_existing": sum(1 for record in records if record["registry"] and record["registry"]["exists"] is True),
            "unverified": sum(1 for record in records if record["registry"] and record["registry"]["exists"] is None),
            "typosquat_suspects": sum(1 for finding in findings if finding.code == "SQ-TYPOSQUAT"),
            "allowed": sum(1 for record in records if record["allowed"]),
            "registry_calls": registry_calls,
        }
    )
    return {
        "tool": "slopsquat-guard",
        "version": VERSION,
        "path": str(path),
        "offline": bool(client.offline),
        "include_imports": include_imports,
        "allow": sorted(allow_set),
        "summary": summary,
        "dependencies": records,
        "findings": [finding.to_dict() for finding in findings],
        "errors": errors,
        "stats": stats,
        "popular_lists": popular.metadata(),
    }


def verify_package(
    name: str,
    ecosystem: str = "pypi",
    client: RegistryClient | None = None,
    popular: PopularLists | None = None,
) -> dict:
    """Check one package name (used by the ``verify`` CLI command)."""
    if ecosystem not in ("pypi", "npm"):
        raise ValueError("ecosystem must be pypi or npm")
    if not name or not name.strip():
        raise ValueError("empty package name")
    client = client or RegistryClient()
    popular = popular or PopularLists()
    normalized = normalize(ecosystem, name)
    result = client.check(ecosystem, normalized)
    near = popular.near_miss(ecosystem, normalized)
    dependency = _dependency_for(ecosystem, name.strip(), "", "<verify>", 0, "verify")
    finding = _finding_for(dependency, result, near)
    client.save()
    return {
        "tool": "slopsquat-guard",
        "version": VERSION,
        "ecosystem": ecosystem,
        "name": name.strip(),
        "normalized": normalized,
        "registry": result.to_dict(),
        "near_miss": near,
        "finding": finding.to_dict() if finding else None,
        "in_popular_list": normalized in popular.normalized[ecosystem],
        "offline": bool(client.offline),
    }
