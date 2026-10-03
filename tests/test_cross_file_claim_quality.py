"""Cross-file claim quality (#264): a SINK/RETURN pair describing one flow
collapses into one finding, and a finding that says it "reaches a sink" names
the sink.

From the letta clean_code audit: 18 cross-file high findings described about
6 distinct claims, and several ended at "...via get_or_create_agent() from
proxy_helpers.py" without ever saying what the sink was.
"""

from __future__ import annotations

from rowan.core.findings import Category, Finding, Severity, TaintFlow, TaintNode
from rowan.passes.cross_file import _merge_direction_pairs, _sink_description


def _cf_finding(rule_id: str, line: int = 60, caller: str = "handler",
                callee: str = "helper", confidence: float = 0.75,
                taint_flow: TaintFlow | None = None) -> Finding:
    return Finding(
        rule_id=rule_id,
        message=f"Cross-file taint [{rule_id}]",
        severity=Severity.HIGH,
        category=Category.GENERAL,
        file_path="app/routes.py",
        start_line=line,
        confidence=confidence,
        engine="crossfile",
        taint_flow=taint_flow,
        metadata={"cross_file": True, "caller": caller, "callee_name": callee},
    )


class TestDirectionPairMerge:
    def test_same_line_pair_collapses_to_one(self) -> None:
        merged = _merge_direction_pairs([
            _cf_finding("CF-SINK-001"),
            _cf_finding("CF-RETURN-001"),
        ])
        assert len(merged) == 1
        survivor = merged[0]
        # The sink direction survives: it names where the taint ends up.
        assert survivor.rule_id == "CF-SINK-001"
        assert survivor.metadata["directions"] == ["sink", "return"]
        # Both ids stay matchable so an existing baseline entry still hits.
        assert survivor.metadata["merged_rule_ids"] == ["CF-RETURN-001", "CF-SINK-001"]

    def test_merge_keeps_the_available_taint_flow(self) -> None:
        flow = TaintFlow(
            source=TaintNode(file_path="app/routes.py", line=55, snippet="request.args.get('q')"),
            sink=TaintNode(file_path="app/db.py", line=12, snippet="cursor.execute(sql)"),
        )
        merged = _merge_direction_pairs([
            _cf_finding("CF-SINK-001", taint_flow=None, confidence=0.65),
            _cf_finding("CF-RETURN-001", taint_flow=flow, confidence=0.75),
        ])
        assert len(merged) == 1
        assert merged[0].taint_flow is flow, "evidence must not be lost in the merge"
        assert merged[0].confidence == 0.75

    def test_different_lines_are_not_merged(self) -> None:
        """Two directions on different call sites are two real claims."""
        merged = _merge_direction_pairs([
            _cf_finding("CF-SINK-001", line=60),
            _cf_finding("CF-RETURN-001", line=178),
        ])
        assert len(merged) == 2

    def test_different_callees_are_not_merged(self) -> None:
        merged = _merge_direction_pairs([
            _cf_finding("CF-SINK-001", callee="extract_user_messages"),
            _cf_finding("CF-RETURN-001", callee="persist_messages"),
        ])
        assert len(merged) == 2

    def test_two_sinks_on_one_line_are_not_merged(self) -> None:
        """The merge is specifically for a direction PAIR; two findings of
        the same direction are not two views of one flow."""
        merged = _merge_direction_pairs([
            _cf_finding("CF-SINK-001", callee="a"),
            _cf_finding("CF-SINK-001", callee="a"),
        ])
        assert len(merged) == 2

    def test_order_is_preserved(self) -> None:
        first = _cf_finding("CF-SINK-001", line=10, callee="a")
        second = _cf_finding("CF-SINK-001", line=20, callee="b")
        third = _cf_finding("CF-RETURN-001", line=20, callee="b")
        merged = _merge_direction_pairs([first, second, third])
        assert [f.start_line for f in merged] == [10, 20]


class TestSinkNaming:
    def test_rule_detail_preferred(self) -> None:
        class _Sig:
            sink_detail = "User input flows to a log statement without newline sanitization."

        assert _sink_description(_Sig(), None).startswith("User input flows")

    def test_falls_back_to_the_taint_flow_sink(self) -> None:
        """A structurally-detected sink has no rule message, which is how
        findings ended up asserting 'reaches a sink' and never saying which."""
        class _Sig:
            sink_detail = ""

        flow = TaintFlow(
            sink=TaintNode(file_path="app/db.py", line=12, snippet="cursor.execute(sql)"),
        )
        detail = _sink_description(_Sig(), flow)
        assert "db.py:12" in detail
        assert "cursor.execute(sql)" in detail

    def test_no_sink_information_yields_empty_string(self) -> None:
        class _Sig:
            sink_detail = ""

        assert _sink_description(_Sig(), None) == ""
        assert _sink_description(None, None) == ""


def test_taint_flow_source_is_the_source_read_line(tmp_path):
    """XF-16: the flow starts at the source read (a.py:6), not the call (a.py:7)."""
    from rowan.config import ScanConfig
    from rowan.pipeline import ScanPipeline

    (tmp_path / "a.py").write_text(
        "from flask import request\nfrom b import run_it\n\n\ndef handler():\n"
        "    q = request.args.get('q')\n    run_it(q)\n",
        encoding="utf-8",
    )
    (tmp_path / "b.py").write_text(
        "import subprocess\n\ndef run_it(cmd):\n    subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True)).run()
    cf = [f for f in result.findings if f.rule_id == "CF-SINK-001"]
    assert [(f.start_line, f.taint_flow.source.line) for f in cf] == [(7, 6)]
