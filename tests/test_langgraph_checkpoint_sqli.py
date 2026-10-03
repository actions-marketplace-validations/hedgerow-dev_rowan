"""Positive/negative fixtures for TNT-LG-001 (rules/ml_taint.yaml, issue #290):
LangGraph checkpoint metadata-KEY SQL injection (CVE-2025-67644).

The novelty this rule owns is a tainted filter/metadata KEY interpolated into a
checkpoint-store query (`for k in filter: query += k`), as opposed to a tainted
VALUE reaching `.execute` -- which TNT-SQLI-001/002 already own. The disjointness
control (test_value_only_execute_*) proves the two do not double-report the
value-only shape.

Requires the Opengrep binary (skipped entirely if not installed, matching the
project's convention -- CI does not install it, see .github/workflows/ci.yml).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _scan(tmp_path, filename, source, rule_id, rule_file="ml_taint.yaml"):
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(
        tmp_path, [RULES_DIR / rule_file], languages=["python"]
    )
    return [f for f in findings if f.rule_id == rule_id]


class TestMetadataKeyInjectionTNTLG001:
    """TNT-LG-001: request source -> filter KEY -> checkpoint-store query."""

    def test_key_loop_execute_flagged(self, tmp_path):
        """A request filter's KEYS iterated into an execute is the CVE shape."""
        src = (
            "def list_checkpoints(cur):\n"
            "    filter = request.json.get('filter')\n"
            "    for key in filter:\n"
            "        cur.execute(\"SELECT * FROM checkpoints WHERE metadata->>'\" + key + \"' = 1\")\n"
        )
        findings = _scan(tmp_path, "key_loop.py", src, "TNT-LG-001")
        assert findings, "filter KEY interpolated into an execute must be flagged"

    def test_saver_list_filter_flagged(self, tmp_path):
        """Acceptance (a): request value -> filter -> checkpointer query call."""
        src = (
            "def search(checkpoint_saver):\n"
            "    flt = request.json.get('filter')\n"
            "    return checkpoint_saver.list(config, filter=flt)\n"
        )
        findings = _scan(tmp_path, "saver_api.py", src, "TNT-LG-001")
        assert findings, "an untrusted filter reaching a checkpointer .list(filter=) must be flagged"

    def test_generic_store_key_loop_flagged(self, tmp_path):
        """Generality: the same shape on a plain DB (not LangGraph, different
        variable names, no saver-shaped receiver) must still fire."""
        src = (
            "def query_documents(db):\n"
            "    conditions = request.args.get('where')\n"
            "    sql = 'SELECT * FROM memory_store WHERE 1=1'\n"
            "    for column_name in conditions:\n"
            "        sql = sql + ' AND ' + column_name + ' IS NOT NULL'\n"
            "        db.execute(sql)\n"
        )
        findings = _scan(tmp_path, "generic_store.py", src, "TNT-LG-001")
        assert findings, "the key-loop shape must generalize beyond LangGraph's own code"

    def test_allowlisted_key_not_flagged(self, tmp_path):
        """Acceptance (b): a key validated against a column allow-list is safe."""
        src = (
            "ALLOWED = {'thread_id': 'thread_id', 'step': 'step'}\n"
            "\n"
            "def list_checkpoints(cur):\n"
            "    filter = request.json.get('filter')\n"
            "    for key in filter:\n"
            "        key = ALLOWED[key]\n"
            "        cur.execute(\"SELECT * FROM checkpoints WHERE metadata->>'\" + key + \"' = 1\")\n"
        )
        findings = _scan(tmp_path, "allowlist.py", src, "TNT-LG-001")
        assert findings == [], "an allow-listed (reassigned) key must not be flagged"

    def test_parameterized_query_not_flagged(self, tmp_path):
        """Acceptance (b): a parameterized query (bound key) is safe."""
        src = (
            "def list_checkpoints(cur):\n"
            "    filter = request.json.get('filter')\n"
            "    for key in filter:\n"
            "        cur.execute('SELECT * FROM checkpoints WHERE k = ?', (key,))\n"
        )
        findings = _scan(tmp_path, "parameterized.py", src, "TNT-LG-001")
        assert findings == [], "a parameterized query must not be flagged"

    def test_value_only_execute_not_flagged_here(self, tmp_path):
        """Acceptance (c): a plain value-only execute is NOT this rule's shape --
        TNT-LG-001 must stay silent so it does not double-report what
        TNT-SQLI-* owns."""
        src = (
            "def get_one(cur):\n"
            "    thread_id = request.json.get('thread_id')\n"
            "    cur.execute(\"SELECT * FROM checkpoints WHERE thread='\" + thread_id + \"'\")\n"
        )
        findings = _scan(tmp_path, "value_only.py", src, "TNT-LG-001")
        assert findings == [], (
            "a value-only execute (no filter-key loop) belongs to TNT-SQLI-*, "
            "not TNT-LG-001"
        )

    def test_value_only_execute_owned_by_sqli(self, tmp_path):
        """Acceptance (c) control: the value-only execute IS caught by the
        general SQLi taint rules, confirming the disjointness split is real."""
        src = (
            "def get_one(cur):\n"
            "    thread_id = request.json.get('thread_id')\n"
            "    cur.execute(\"SELECT * FROM checkpoints WHERE thread='\" + thread_id + \"'\")\n"
        )
        sqli = _scan(
            tmp_path, "value_only_web.py", src, "TNT-SQLI-001", rule_file="web_taint.yaml"
        )
        sqli2 = _scan(
            tmp_path,
            "value_only_ext.py",
            src,
            "TNT-SQLI-002",
            rule_file="python_taint_extended.yaml",
        )
        assert sqli or sqli2, (
            "the value-only shape must be owned by TNT-SQLI-001/002 (it is not a "
            "false negative -- just not TNT-LG-001's finding)"
        )
