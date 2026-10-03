"""Shared classification constants for non-source scan artifacts."""

from __future__ import annotations

import re
from pathlib import Path

DEPENDENCY_MANIFEST_PATTERNS: tuple[str, ...] = (
    r"requirements.*\.txt$",
    r"pyproject\.toml$",
    r"Pipfile$",
    r"Pipfile\.lock$",
    r"poetry\.lock$",
    r"uv\.lock$",
    r"package\.json$",
    r"package-lock\.json$",
    r"npm-shrinkwrap\.json$",
    r"yarn\.lock$",
    r"pnpm-lock\.yaml$",
    r"pom\.xml$",
    r"packages\.config$",
    r"packages\.lock\.json$",
    r"[^/]+\.csproj$",
    r"build\.gradle$",
    r"build\.gradle\.kts$",
    r"libs\.versions\.toml$",
    r"go\.mod$",
    r"go\.work$",
    r"Cargo\.toml$",
    r"Cargo\.lock$",
    r"Gemfile$",
    r"Gemfile\.lock$",
    r"composer\.json$",
    r"composer\.lock$",
)

DEPENDENCY_SKIP_DIRS = frozenset({
    ".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
})

_DEPENDENCY_MANIFEST_REGEXES = tuple(
    re.compile(pattern, re.I) for pattern in DEPENDENCY_MANIFEST_PATTERNS
)


# Every extension Hayward's own directory discovery reads, so a model file
# Hayward can analyse is never left out of Rowan's inventory.
# tests/test_artifact_inventory.py fails if the two sets drift apart.
MODEL_ARTIFACT_EXTENSIONS: tuple[str, ...] = (
    ".pkl", ".pickle", ".pth", ".pt", ".ptl", ".ckpt", ".th", ".mar", ".nemo",
    ".safetensors", ".gguf", ".h5", ".hdf5", ".keras", ".onnx", ".pb",
    ".npy", ".npz", ".joblib", ".7z", ".tar", ".tflite", ".skops", ".pmml",
    ".bin", ".zip", ".json",
)


def is_dependency_manifest(path: Path) -> bool:
    """Return whether a path name is one of the supported SCA formats."""

    return any(regex.match(path.name) for regex in _DEPENDENCY_MANIFEST_REGEXES)


def is_model_artifact(path: Path) -> bool:
    """Return whether a path suffix is accepted by model-file discovery."""

    # Preserve Path.rglob("*.ext") discovery semantics: direct scan_file()
    # accepts upper-case suffixes, but repository discovery historically did
    # not widen to them on case-sensitive filesystems.
    return path.suffix in MODEL_ARTIFACT_EXTENSIONS
