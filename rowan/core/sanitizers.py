"""Per-category sanitizer registry and the one window-correlation rule.

The patterns live in :data:`rowan.rules_registry.SANITIZER_REGEX`; this
module types them and owns the single implementation of "does a sanitizer
in this window clear this finding" (BACKLOG CN-04). Both the legacy regex
engine (`core/rules.py`) and the enrichment post-filter call
`sanitizer_matches`, so the two cannot drift again (TE-23).

Two kinds of entry:

* a **call** sanitizer, whose pattern ends in an open paren
  (`shlex.quote(`, `os.path.basename(`): it neutralises what is passed to
  it, so it only counts on a line that shares an identifier with the
  finding's line;
* a **shape** sanitizer, a keyword or class that marks a call safe
  (`shell=False`, `weights_only=True`, `PreparedStatement`): it describes
  one call, so it counts on the finding's own line or a line sharing an
  identifier with it. Anywhere else in the window it describes some other
  call (TE-11).
"""

from __future__ import annotations

import keyword
import re
from dataclasses import dataclass
from functools import cache

from rowan.core.findings import Category
from rowan.rules_registry import SANITIZER_REGEX

#: Derived from the registry: do not edit inline; edit
#: ``rowan/rules_registry.py::SANITIZER_REGEX``.
CATEGORY_SANITIZERS: dict[Category, list[str]] = {
    category: list(patterns) for category, patterns in SANITIZER_REGEX.items()
}

_CALL_SUFFIX = "\\("


@dataclass(frozen=True)
class Sanitizer:
    pattern: str
    kind: str  # "call" | "shape"
    regex: re.Pattern

    def search(self, text: str) -> bool:
        return self.regex.search(text) is not None


def _typed(pattern: str) -> Sanitizer | None:
    try:
        regex = re.compile(pattern)
    except re.error:
        return None
    kind = "call" if pattern.rstrip().endswith(_CALL_SUFFIX) else "shape"
    return Sanitizer(pattern, kind, regex)


@cache
def sanitizers_for(category: Category) -> tuple[Sanitizer, ...]:
    typed = (_typed(p) for p in CATEGORY_SANITIZERS.get(category, []))
    return tuple(s for s in typed if s is not None)


def call_sanitizers(category: Category) -> tuple[Sanitizer, ...]:
    return tuple(s for s in sanitizers_for(category) if s.kind == "call")


def shape_sanitizers(category: Category) -> tuple[Sanitizer, ...]:
    return tuple(s for s in sanitizers_for(category) if s.kind == "shape")


@cache
def get_sanitizers_for_category(category: Category) -> list[re.Pattern]:
    """Compiled regexes only; kept for callers that build mixed lists."""
    return [s.regex for s in sanitizers_for(category)]


_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
#: Names that would make every line look related to every other.
_IDENT_STOPWORDS = frozenset({"self", "cls", "shell", "args", "kwargs"})


def line_identifiers(line: str) -> set[str]:
    """Identifiers on a line, minus keywords and a few universal names."""
    return {
        tok
        for tok in _IDENT_RE.findall(line)
        if not keyword.iskeyword(tok) and tok not in _IDENT_STOPWORDS
    }


def sanitizer_matches(
    sanitizers: tuple[Sanitizer, ...] | list,
    window_lines: list[str],
    matched_line: str,
    *,
    whole_window: bool = False,
) -> bool:
    """Does any sanitizer in the window clear the finding on `matched_line`?

    Accepts typed `Sanitizer`s or bare compiled patterns, which are typed by
    their pattern text. Registry entries are correlated to the finding (its
    line, its statement, or a line sharing an identifier). A rule's own
    `sanitizers:` list is written against its window by its author (a loop
    cap inside the loop body, an agent limit a few lines above the crew),
    so those callers pass `whole_window=True` and a shape entry anywhere in
    the window counts; call entries still need a shared identifier.
    """
    sink_vars = line_identifiers(matched_line)
    statement = _statement_span(window_lines, matched_line)
    for entry in sanitizers:
        s = entry if isinstance(entry, Sanitizer) else _typed(entry.pattern)
        if s is None:
            continue
        if s.search(matched_line):
            return True
        # A rule's own sanitizer list is authored against that rule's whole
        # window.  In that mode both call and shape entries are intentional
        # window-level guards (for example ns-aiml-129's
        # ImmutableSandboxedEnvironment() next to get_jinja_env()).
        if whole_window and any(s.search(line) for line in window_lines):
            return True
        # A shape sanitizer describes the call it sits in: a kwarg on a
        # later line of the same multi-line call still applies.
        if s.kind == "shape" and any(s.search(line) for line in statement):
            return True
        for wline in window_lines:
            if wline == matched_line or not s.search(wline):
                continue
            if line_identifiers(wline) & sink_vars:
                return True
    return False


def _net_depth(line: str) -> int:
    return (line.count("(") + line.count("[") + line.count("{")) - (
        line.count(")") + line.count("]") + line.count("}")
    )


def _statement_span(window_lines: list[str], matched_line: str) -> list[str]:
    """The lines of the bracketed statement containing `matched_line`.

    Lines are grouped by running bracket depth from the window start: a new
    statement begins after every line on which the depth returns to zero.
    A window that starts mid-statement truncates that first statement,
    which only makes the span smaller.
    """
    try:
        target = window_lines.index(matched_line)
    except ValueError:
        return [matched_line]
    depth = 0
    stmt = 0
    ids: list[int] = []
    for line in window_lines:
        ids.append(stmt)
        depth = max(0, depth + _net_depth(line))
        if depth == 0:
            stmt += 1
    return [line for line, sid in zip(window_lines, ids, strict=True) if sid == ids[target]]
