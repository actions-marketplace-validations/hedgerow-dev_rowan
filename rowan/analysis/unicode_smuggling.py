"""Decode Unicode-smuggled ASCII in attacker-authored instruction text.

ns-aiml-107 flags the *presence* of Tags-block characters, but a capable LLM
reads them as their decoded ASCII, so a hidden instruction override never
reaches the override matcher (ns-aiml-053). This module produces the decoded
shadow and reports an override phrase that appears only after decoding
(LangFail V32, CWE-150).

Decoding is deliberately targeted at documented smuggling encodings -- the
Unicode Tags block (U+E0000..U+E007F) plus zero-width / bidi-control
characters -- never blanket NFKC normalization. Legitimate CJK / RTL / emoji
prose decodes to itself and cannot match an override phrase, so the i18n
false positives that ns-aiml-108 guards against are impossible here by
construction.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from pathlib import Path

from rowan.core.findings import Category, Finding, Severity
from rowan.core.paths import is_within_root, iter_within_root
from rowan.passes.file_scan import BASE_SKIP_DIRS, _parts_under, is_ai_instruction_file

# Unicode Tags block. Each tag character decodes to the ASCII whose codepoint
# is (tag - 0xE0000). U+E0000 (language tag) and U+E007F (cancel tag) are
# controls with no ASCII glyph and are dropped rather than decoded.
_TAG_BASE = 0xE0000
_TAG_LAST = 0xE007F

# Zero-width and bidirectional-control characters used to hide or reorder text
# between visible glyphs. Stripped (not decoded) so text split by them rejoins
# into the phrase a model reads.
_INVISIBLE = frozenset(
    "​‌‍⁠﻿"  # ZWSP ZWNJ ZWJ WJ BOM
    "‎‏"  # LRM RLM
    "‪‫‬‭‮"  # bidi embeddings / overrides
    "⁦⁧⁨⁩"  # bidi isolates
)

# Instruction-override phrases, mirroring ns-aiml-053. Matched against the
# decoded shadow; a hit that is absent from the raw text is a smuggled
# override. Kept to unambiguous injection phrases so a hidden match is
# unambiguously malicious.
_OVERRIDE_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"ignore (?:all )?(?:previous|prior) instructions",
        r"disregard (?:all )?(?:previous|prior) instructions",
        r"do anything now",
        r"developer mode",
        r"stay in character",
    )
]

# Prose file suffixes scanned in addition to recognized instruction files,
# matching ns-aiml-107's ai_instructions + markdown + text reach.
_PROSE_SUFFIXES = frozenset({".md", ".txt"})


def has_smuggled_chars(text: str) -> bool:
    """True if `text` contains any Tags-block or invisible control character."""
    return any(_TAG_BASE <= ord(ch) <= _TAG_LAST or ch in _INVISIBLE for ch in text)


def decode_smuggled(text: str) -> str:
    """Return `text` with Tags-block characters decoded to ASCII and
    zero-width / bidi-control characters removed."""
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if _TAG_BASE <= cp <= _TAG_LAST:
            ascii_cp = cp - _TAG_BASE
            if 0x20 <= ascii_cp <= 0x7E:
                out.append(chr(ascii_cp))
            # else: language-tag / cancel-tag control, drop
            continue
        if ch in _INVISIBLE:
            continue
        out.append(ch)
    return "".join(out)


def _smuggled_overrides(text: str) -> list[str]:
    """Override phrases present in the decoded text but not the raw text."""
    if not has_smuggled_chars(text):
        return []
    decoded = decode_smuggled(text)
    hits: list[str] = []
    for pattern in _OVERRIDE_PATTERNS:
        match = pattern.search(decoded)
        if match and not pattern.search(text):
            hits.append(match.group(0))
    return hits


def _first_smuggle_line(text: str) -> int:
    """1-indexed line of the first smuggle character, or 1."""
    for i, line in enumerate(text.splitlines(), 1):
        if has_smuggled_chars(line):
            return i
    return 1


def _is_scan_target(path: Path) -> bool:
    return is_ai_instruction_file(path) or path.suffix.lower() in _PROSE_SUFFIXES


def scan_directory(
    target: Path,
    candidates: Iterable[Path] | None = None,
    read_text: Callable[[Path], str | None] | None = None,
) -> list[Finding]:
    """Report smuggled instruction overrides in instruction / prose files
    under `target`."""
    findings: list[Finding] = []
    target = Path(target)
    paths = (
        candidates
        if candidates is not None
        else (
            [target]
            if target.is_file() and is_within_root(target, target.parent)
            else iter_within_root(target, "*")
        )
    )
    for path in paths:
        if not path.is_file():
            continue
        if any(part in BASE_SKIP_DIRS for part in _parts_under(path, target)):
            continue
        if not _is_scan_target(path):
            continue
        if read_text is not None:
            text = read_text(path)
            if text is None:
                continue
        else:
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
        overrides = _smuggled_overrides(text)
        if not overrides:
            continue
        phrase = overrides[0]
        findings.append(
            Finding(
                rule_id="PROMPT-SMUGGLE-001",
                message=(
                    f"An instruction-override phrase ('{phrase}') is hidden in "
                    f"this file using invisible Unicode (Tags block or zero-width "
                    f"/ bidi characters). It renders as nothing to a human "
                    f"reviewer but decodes to an instruction a capable LLM obeys, "
                    f"smuggling a prompt-injection past review into an agent "
                    f"instruction file."
                ),
                severity=Severity.HIGH,
                category=Category.PROMPT_INJECTION,
                file_path=str(path),
                start_line=_first_smuggle_line(text),
                confidence=0.9,
                engine="smuggle",
                cwe_ids=[150],
                metadata={"decoded_phrase": phrase},
            )
        )
    return findings
