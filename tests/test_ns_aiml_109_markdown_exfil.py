"""Tests for ns-aiml-109 (rules/ai_security.yaml): markdown exfiltration
channel presence signal, the companion rule to TNT-LLMOUT-006 (issue #133).
"""

from pathlib import Path

from rowan.core.rules import load_neuroscan_rules

RULES_DIR = Path(__file__).parent.parent / "rules"


def _rule():
    rules = load_neuroscan_rules(RULES_DIR / "ai_security.yaml")
    return next(r for r in rules if r.metadata.id == "ns-aiml-109")


def test_markdown_render_without_allowlist_flagged(tmp_path):
    fp = tmp_path / "chat_ui.py"
    fp.write_text(
        "import markdown\n\n"
        "def render(completion_text):\n"
        "    return markdown.markdown(completion_text)\n",
        encoding="utf-8",
    )
    assert _rule().check(fp), (
        "markdown.markdown() with no allow-list/CSP/sanitize reference nearby must be flagged"
    )


def test_mistune_render_without_allowlist_flagged(tmp_path):
    fp = tmp_path / "chat_ui_mistune.py"
    fp.write_text(
        "import mistune\n\n"
        "def render(completion_text):\n"
        "    return mistune.html(completion_text)\n",
        encoding="utf-8",
    )
    assert _rule().check(fp), "mistune.html() with no allow-list nearby must be flagged"


def test_marked_js_without_allowlist_flagged(tmp_path):
    fp = tmp_path / "ChatMessage.tsx"
    fp.write_text(
        "import { marked } from 'marked';\n\n"
        "function render(completionText) {\n"
        "  return marked(completionText);\n"
        "}\n",
        encoding="utf-8",
    )
    assert _rule().check(fp), "marked() with no allow-list/CSP reference nearby must be flagged"


def test_markdown_render_with_allowlist_comment_not_flagged(tmp_path):
    fp = tmp_path / "chat_ui_safe.py"
    fp.write_text(
        "import markdown\n\n"
        "# image sources are restricted to an allowlist of known-safe hosts\n"
        "def render(completion_text):\n"
        "    return markdown.markdown(completion_text)\n",
        encoding="utf-8",
    )
    assert _rule().check(fp) == [], "an allow-list reference nearby must suppress the signal"


def test_markdown_render_with_dompurify_not_flagged(tmp_path):
    fp = tmp_path / "ChatMessageSanitized.tsx"
    fp.write_text(
        "import { marked } from 'marked';\n"
        "import DOMPurify from 'dompurify';\n\n"
        "function render(completionText) {\n"
        "  return DOMPurify.sanitize(marked(completionText));\n"
        "}\n",
        encoding="utf-8",
    )
    assert _rule().check(fp) == [], "a DOMPurify sanitize reference nearby must suppress the signal"


def test_markdown_render_with_csp_reference_not_flagged(tmp_path):
    fp = tmp_path / "chat_ui_csp.py"
    fp.write_text(
        "import markdown\n\n"
        "# served behind a strict Content-Security-Policy that blocks remote images\n"
        "def render(completion_text):\n"
        "    return markdown.markdown(completion_text)\n",
        encoding="utf-8",
    )
    assert _rule().check(fp) == [], "a CSP reference nearby must suppress the signal"


def test_comment_only_mention_not_flagged(tmp_path):
    fp = tmp_path / "notes.py"
    fp.write_text(
        "# TODO: consider using markdown.markdown( for rendering release notes\n",
        encoding="utf-8",
    )
    assert _rule().check(fp) == [], "a commented-out mention must not be flagged"
