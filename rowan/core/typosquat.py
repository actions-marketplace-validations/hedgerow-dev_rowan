"""Typosquatting detection for declared dependencies.

Flags a declared package whose name is one edit away from a well-known,
frequently-squatted package -- the classic supply-chain trap where a
developer types (or an LLM hallucinates) ``reqeusts`` / ``python-dateutil``
and pulls a malicious look-alike. Offline: matches against a curated corpus
of high-value squat targets rather than a live registry.

Precision-first: the name must be *exactly* one edit from a corpus entry,
be at least a few characters long (short names have too many near-neighbors),
and must not itself be a known-good package (many legitimate packages sit one
edit from a popular one -- ``request`` is real, not a squat of ``requests``).
"""

from __future__ import annotations

# Curated corpus of the most valuable / most-squatted packages per ecosystem.
# Names are normalized (lowercase). Not exhaustive -- intentionally the
# high-signal targets, to keep false positives low.
_POPULAR: dict[str, frozenset[str]] = {
    "PyPI": frozenset({
        "requests", "urllib3", "numpy", "pandas", "scipy", "matplotlib",
        "flask", "django", "fastapi", "starlette", "pydantic", "httpx",
        "aiohttp", "werkzeug", "jinja2", "click", "rich", "typer",
        "sqlalchemy", "celery", "redis", "pymongo", "psycopg2", "psycopg", "boto3",
        "botocore", "setuptools", "wheel", "pip", "cryptography", "certifi",
        "idna", "charset-normalizer", "pyyaml", "python-dateutil", "six",
        "packaging", "attrs", "pytest", "tox", "coverage", "black", "ruff",
        "mypy", "pillow", "opencv-python", "scikit-learn", "tensorflow",
        "keras", "torch", "torchvision", "transformers", "huggingface-hub",
        "openai", "anthropic", "langchain", "tqdm", "beautifulsoup4",
        "lxml", "selenium", "scrapy", "paramiko", "cryptg", "colorama",
        "python-dotenv", "pyjwt", "bcrypt", "passlib", "gunicorn", "uvicorn",
        "google-auth", "protobuf", "grpcio", "tenacity", "websockets",
    }),
    "npm": frozenset({
        "react", "react-dom", "lodash", "express", "axios", "chalk",
        "commander", "debug", "moment", "webpack", "babel-core", "eslint",
        "typescript", "vue", "angular", "jquery", "next", "dotenv",
        "mongoose", "socket.io", "redux", "rxjs", "uuid", "bluebird",
        "request", "node-fetch", "cross-env", "nodemon", "prettier", "jest",
        "enquirer",
        "yargs", "inquirer", "glob", "fs-extra", "semver", "ws", "cors",
        "body-parser", "passport", "bcrypt", "jsonwebtoken", "dayjs",
        "classnames", "styled-components", "tailwindcss", "vite", "esbuild",
    }),
}

# Below this length, one-edit neighborhoods are dense with legitimate names,
# so the false-positive rate isn't worth it.
_MIN_NAME_LEN = 4


def _edit_distance_is_one(a: str, b: str) -> bool:
    """True iff ``a`` and ``b`` are exactly one edit apart under
    Damerau-Levenshtein: a single insertion, deletion, substitution, or
    *adjacent transposition* (never zero -- an exact match isn't a squat).

    Transpositions matter: ``reqeusts`` -> ``requests`` is a swap of two
    adjacent characters, one of the most common real typosquat classes, yet
    plain Levenshtein distance 2.
    """
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False

    if la == lb:
        mismatches = [i for i in range(la) if a[i] != b[i]]
        if len(mismatches) == 1:
            return True  # substitution
        if len(mismatches) == 2:
            i, j = mismatches
            return j == i + 1 and a[i] == b[j] and a[j] == b[i]  # adjacent swap
        return False

    # Lengths differ by one: the shorter must equal the longer with a single
    # character removed. Walk both with a two-pointer, allowing one skip.
    if la > lb:
        a, b = b, a  # a is now the shorter
    i = j = 0
    skipped = False
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            i += 1
            j += 1
        else:
            if skipped:
                return False
            skipped = True
            j += 1  # skip one char in the longer string
    return True


def nearest_popular(name: str, ecosystem: str) -> str | None:
    """A popular package exactly one edit from ``name``, or None.

    Returns None when ``name`` is itself popular, is too short, or has no
    one-edit popular neighbor.
    """
    corpus = _POPULAR.get(ecosystem)
    if not corpus:
        return None
    norm = name.lower()
    if norm in corpus or len(norm) < _MIN_NAME_LEN:
        return None
    for popular in sorted(corpus):
        if _edit_distance_is_one(norm, popular):
            return popular
    return None
