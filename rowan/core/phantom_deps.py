"""Phantom (undeclared) dependency detection.

A *phantom dependency* is a third-party package that the code imports and
uses but that is not declared in any manifest or lockfile. They are a real
supply-chain risk: their version is uncontrolled (whatever the environment
happens to resolve), they are invisible to a manifest-only vulnerability
scan, and an undeclared import is a dependency-confusion foothold. Endor
Labs reports that for some Python codebases phantom dependencies are 0-60%
of all dependencies and carry up to 85% of the vulnerabilities -- precisely
because manifest-only SCA never looks at them.

This detector is deliberately precision-first, matching the rest of this
codebase's bias: it only flags an import when it is confident the module is
(a) third-party (not stdlib, not a module defined inside the scanned repo)
and (b) not already declared under any known name. When in doubt it stays
silent rather than emitting a false positive.

Python only for now -- it shares the import model of ``core.reachability``.
"""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from pathlib import Path

from rowan.core.paths import iter_within_root

# Import name -> PyPI distribution name, for the common cases where the two
# differ. Without this, a declared `pillow` would be falsely reported phantom
# because the code imports `PIL`. Only well-established, unambiguous mappings
# belong here; anything genuinely ambiguous goes in _AMBIGUOUS_NAMESPACES
# instead (skipped entirely rather than guessed).
_IMPORT_TO_DISTRIBUTION: dict[str, str] = {
    "PIL": "pillow",
    "cv2": "opencv-python",
    "sklearn": "scikit-learn",
    "yaml": "pyyaml",
    "bs4": "beautifulsoup4",
    "dateutil": "python-dateutil",
    "dotenv": "python-dotenv",
    "jwt": "pyjwt",
    "OpenSSL": "pyopenssl",
    "Crypto": "pycryptodome",
    "Cryptodome": "pycryptodomex",
    "serial": "pyserial",
    "git": "gitpython",
    "MySQLdb": "mysqlclient",
    "docx": "python-docx",
    "pptx": "python-pptx",
    "fitz": "pymupdf",
    "magic": "python-magic",
    "slugify": "python-slugify",
    "attr": "attrs",
    "attrs": "attrs",
    "jose": "python-jose",
    "nacl": "pynacl",
    "usb": "pyusb",
    "wx": "wxpython",
    "gi": "pygobject",
    "cairo": "pycairo",
    "ldap": "python-ldap",
    "grpc": "grpcio",
    "typing_extensions": "typing-extensions",
    "importlib_metadata": "importlib-metadata",
    "pkg_resources": "setuptools",
    "psycopg2": "psycopg2-binary",
}

# Import roots that map to several unrelated distributions (or to a mix of
# first- and third-party code) and therefore can't be resolved to a single
# distribution name with confidence. Skipped entirely -- flagging them would
# be a guess, and this detector never guesses.
_AMBIGUOUS_NAMESPACES: frozenset[str] = frozenset(
    {
        "google",  # google-cloud-*, protobuf (google.protobuf), google-auth, ...
        "ruamel",  # ruamel.yaml, ruamel.std.*, ...
        "backports",  # backports.* -- many independent distributions
        "tests",  # near-universally a first-party test package
        "test",
        "conftest",
    }
)


def _normalize(name: str) -> str:
    """PEP 503-style normalization collapsed to a comparable key.

    Lowercase and strip the separators PyPI treats as equivalent
    (``-``/``_``/``.``) so ``scikit-learn``, ``scikit_learn`` and
    ``Scikit.Learn`` all compare equal. Mirrors
    ``core.vuln_functions._normalize`` but also folds ``.``.
    """
    return name.lower().replace("-", "").replace("_", "").replace(".", "")


def import_roots_for_distribution(distribution: str) -> set[str]:
    """Normalized import roots a PyPI distribution is imported under.

    Defaults to the distribution's own normalized name and adds any known
    import-name alias (``pillow`` -> also ``pil``; ``pyyaml`` -> also
    ``yaml``) by inverting the curated alias map. Used to decide whether a
    dotted symbol named in an advisory belongs to the flagged package.
    """
    norm = _normalize(distribution)
    roots = {norm}
    for import_name, dist in _IMPORT_TO_DISTRIBUTION.items():
        if _normalize(dist) == norm:
            roots.add(_normalize(import_name))
    return roots


def _stdlib_module_names() -> frozenset[str]:
    """Top-level stdlib module names for the running interpreter.

    ``sys.stdlib_module_names`` (3.10+) is authoritative. Fall back to a
    small hardcoded set of the modules most likely to appear in scanned
    code if it's somehow unavailable, so detection degrades to
    conservative (over-excluding) rather than false-positiving on stdlib.
    """
    names = getattr(sys, "stdlib_module_names", None)
    if names:
        return frozenset(names)
    return frozenset(
        {
            "os", "sys", "re", "json", "math", "time", "typing", "pathlib",
            "collections", "itertools", "functools", "logging", "datetime",
            "subprocess", "threading", "asyncio", "io", "abc", "dataclasses",
            "enum", "hashlib", "base64", "socket", "struct", "warnings",
            "unittest", "sqlite3", "urllib", "http", "email", "xml", "csv",
        }
    )


def collect_imported_modules(py_files: list[Path]) -> set[str]:
    """Top-level module roots imported across a set of Python files.

    ``import a.b.c`` and ``from a.b import c`` both contribute the root
    ``a``. Relative imports (``from . import x``, ``from ..pkg import y``)
    are skipped -- they always name first-party modules, never a
    distribution.
    """
    modules: set[str] = set()
    for py_file in py_files:
        try:
            source = py_file.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(py_file))
        except (SyntaxError, UnicodeDecodeError, OSError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root:
                        modules.add(root)
            elif isinstance(node, ast.ImportFrom):
                # level > 0 is a relative import (first-party); module None
                # only happens for a bare relative import.
                if node.level and node.level > 0:
                    continue
                if node.module:
                    root = node.module.split(".")[0]
                    if root:
                        modules.add(root)
    return modules


def collect_local_module_names(
    target: Path, py_files: list[Path], *, authoritative: bool = False
) -> set[str]:
    """Module roots that are defined *inside* the scanned repo.

    Any top-level package directory (one containing ``__init__.py``) and any
    Python file's stem is treated as a potential first-party module name. We
    deliberately over-collect here: excluding a name that is really a
    phantom dependency only costs a missed finding, whereas failing to
    exclude a genuine first-party module would produce a false positive --
    and precision is the priority.
    """
    local: set[str] = set()
    for py_file in py_files:
        local.add(py_file.stem)
        if py_file.name == "__init__.py":
            local.add(py_file.parent.name)
    # Standalone callers may supply a partial list, so retain the historical
    # safety-biased package walk there. Pipeline inventory candidates are the
    # complete resolved scope and must not be widened or walked again.
    if not authoritative:
        for init in iter_within_root(target, "__init__.py"):
            local.add(init.parent.name)
    return local


@dataclass(frozen=True)
class PhantomDependency:
    """An imported-but-undeclared third-party module."""

    import_name: str
    distribution: str  # best-effort PyPI distribution name


def find_phantom_dependencies(
    imported_modules: set[str],
    declared_pypi: set[str],
    local_modules: set[str],
) -> list[PhantomDependency]:
    """Imports that are third-party and not declared under any known name.

    ``declared_pypi`` is the set of package names declared in the project's
    Python manifests/lockfiles (raw, un-normalized -- this function
    normalizes internally). ``local_modules`` names modules defined inside
    the repo. Returns a stable, sorted list.
    """
    declared_norm = {_normalize(name) for name in declared_pypi}
    local_norm = {_normalize(name) for name in local_modules}
    stdlib = _stdlib_module_names()

    phantoms: list[PhantomDependency] = []
    seen: set[str] = set()
    for module in imported_modules:
        if module in stdlib or module in _AMBIGUOUS_NAMESPACES:
            continue
        if module.startswith("_"):
            # Private/internal roots (`_pytest`, `_distutils_hack`) are
            # implementation details of other packages, not declarable deps.
            continue
        norm_import = _normalize(module)
        if not norm_import or norm_import in local_norm:
            continue

        distribution = _IMPORT_TO_DISTRIBUTION.get(module, module)
        # A match under *either* the raw import name or its mapped
        # distribution name clears the import -- the alias map only needs to
        # cover mismatches, and never causes a false "declared" match.
        candidates = {norm_import, _normalize(distribution)}
        if candidates & declared_norm:
            continue

        if norm_import in seen:
            continue
        seen.add(norm_import)
        phantoms.append(PhantomDependency(import_name=module, distribution=distribution))

    return sorted(phantoms, key=lambda p: p.import_name.lower())
