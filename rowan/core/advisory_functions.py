"""Derive a CVE's vulnerable functions from its OSV/GHSA advisory text.

``core.vuln_functions`` hand-maps ~25 packages to their vulnerable functions,
so call-graph reachability (which downgrades a CVE whose vulnerable function
is never invoked) only ever fires for those packages. This module scales that
signal to the long tail by extracting the vulnerable API *per CVE* from the
advisory ``details`` OSV already returns with every finding -- more accurate
than a package-level map, since different CVEs in the same package have
different vulnerable functions.

Precision-first, to protect the reachability downgrade from ever hiding a real
CVE:

* Only *qualified* symbols (``requests.get``, ``yaml.load``) are extracted --
  never bare names, which are where ambiguity and false matches live.
* A symbol is kept only when its head segment is a known import root of the
  flagged package, so an advisory that merely *mentions* ``os.system`` when
  describing impact never gets mistaken for the package's own API.
* Only text inside code spans (inline ``code`` and fenced blocks) is scanned,
  never prose.

When extraction yields nothing, the caller keeps the finding's full severity
(the pre-existing behavior for unmapped packages) rather than guessing.

Deliberately conservative on the downgrade: an advisory that names both a
constructor (``pkg.Client()``) and the vulnerable method (``pkg.Client.fetch``)
yields both symbols, so merely instantiating the class keeps the CVE
"reachable" (full severity) even if the specific method is never called. That
errs toward *keeping* a finding, never toward silently hiding one -- the
right bias for a security tool. The dominant real-world win (suppressing CVEs
in packages pulled in transitively but never imported or called at all) is
unaffected by this and works regardless of how many symbols an advisory names.
"""

from __future__ import annotations

import re

from rowan.core.phantom_deps import _normalize, import_roots_for_distribution

# Inline `code` spans and ```fenced``` / ~~~fenced~~~ blocks in the advisory
# markdown. Everything outside these is prose and is ignored.
_CODE_SPAN_RE = re.compile(r"`{1,3}([^`]+)`{1,3}", re.DOTALL)
_FENCED_RE = re.compile(r"(?:```|~~~)(.*?)(?:```|~~~)", re.DOTALL)

# A dotted call/attribute path: `a.b`, `a.b.c`, optionally trailed by `(`.
# Requires at least one dot (qualified only).
_DOTTED_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)")

# Cap per advisory -- a pathological advisory listing dozens of code snippets
# shouldn't explode the vuln-function list.
_MAX_SYMBOLS = 20


def extract_vulnerable_symbols(details: str, package: str) -> list[str]:
    """Qualified vulnerable symbols for ``package`` named in ``details``.

    Returns a de-duplicated, order-stable list of dotted symbols (trailing
    ``()`` stripped) whose head is a known import root of ``package`` --
    directly consumable by ``core.reachability.is_package_reachable`` as
    qualified entries. Empty when the advisory names no in-namespace symbol.
    """
    if not details or not package:
        return []

    valid_heads = import_roots_for_distribution(package)

    code_text_parts: list[str] = []
    code_text_parts.extend(_FENCED_RE.findall(details))
    code_text_parts.extend(_CODE_SPAN_RE.findall(details))
    if not code_text_parts:
        return []
    code_text = "\n".join(code_text_parts)

    symbols: list[str] = []
    seen: set[str] = set()
    for match in _DOTTED_RE.finditer(code_text):
        dotted = match.group(1)
        head = dotted.split(".", 1)[0]
        if _normalize(head) not in valid_heads:
            continue
        if dotted in seen:
            continue
        seen.add(dotted)
        symbols.append(dotted)
        if len(symbols) >= _MAX_SYMBOLS:
            break
    return symbols
