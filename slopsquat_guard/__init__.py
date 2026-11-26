"""slopsquat-guard: find hallucinated/typosquatted dependencies before you install them.

Public API::

    from slopsquat_guard import scan_path, verify_package, RegistryClient

    result = scan_path(".")                       # dict with dependencies/findings/summary
    one    = verify_package("reqeusts", "pypi")   # dict for a single name
"""

from __future__ import annotations

from .core import (
    Dependency,
    Finding,
    SEVERITY_ORDER,
    format_finding_line,
    parse_package_json,
    parse_pyproject,
    parse_python_imports,
    parse_requirements,
    scan_path,
    severity_at_least,
    summarize,
    verify_package,
)
from .popular import PopularLists, normalize, normalize_npm, normalize_pypi, osa_distance
from .registry import FetchError, RegistryClient, RegistryResult

__version__ = "0.1.0"

__all__ = [
    "Dependency",
    "FetchError",
    "Finding",
    "PopularLists",
    "RegistryClient",
    "RegistryResult",
    "SEVERITY_ORDER",
    "format_finding_line",
    "normalize",
    "normalize_npm",
    "normalize_pypi",
    "osa_distance",
    "parse_package_json",
    "parse_pyproject",
    "parse_python_imports",
    "parse_requirements",
    "scan_path",
    "severity_at_least",
    "summarize",
    "verify_package",
    "__version__",
]
