"""Milestone C: raw flows remain intact while review output groups root causes."""

from __future__ import annotations

import json

from rowan.config import ScanConfig
from rowan.core.finding_clusters import cluster_findings
from rowan.core.findings import (
    Category,
    Finding,
    ScanResult,
    Severity,
    TaintFlow,
    TaintNode,
)
from rowan.passes.base import ScanContext
from rowan.passes.cross_file import CrossFilePass
from rowan.reporters import to_json, to_sarif, to_text


def _flow_finding(
    root,
    caller: str,
    caller_line: int,
    sink_symbol: str,
) -> Finding:
    caller_file = root / f"{caller}.py"
    sink_file = root / "sink.py"
    return Finding(
        rule_id="CF-SINK-001",
        message=f"{caller} reaches {sink_symbol}",
        severity=Severity.HIGH,
        category=Category.COMMAND_INJECTION,
        file_path=str(caller_file),
        start_line=caller_line,
        confidence=0.8,
        engine="crossfile",
        taint_flow=TaintFlow(
            source=TaintNode(file_path=str(caller_file), line=caller_line),
            sink=TaintNode(
                file_path=str(sink_file),
                line=20,
                snippet=f"{sink_symbol}(payload)",
            ),
        ),
        metadata={
            "cross_file": True,
            "caller": caller,
            "hop_depth": 1,
            "sink_rule_id": "TNT-CMDI-001",
            "sink_symbol": sink_symbol,
        },
    )


def test_three_callers_are_one_cluster_but_two_sink_symbols_stay_distinct(tmp_path):
    findings = [
        _flow_finding(tmp_path, "first", 5, "subprocess.run"),
        _flow_finding(tmp_path, "second", 8, "subprocess.run"),
        _flow_finding(tmp_path, "third", 13, "subprocess.run"),
        _flow_finding(tmp_path, "eval_path", 21, "eval"),
        _flow_finding(tmp_path, "exec_path", 22, "exec"),
    ]

    clusters = cluster_findings(findings, str(tmp_path))

    assert len(findings) == 5
    assert len(clusters) == 3
    subprocess_cluster = next(
        cluster for cluster in clusters if cluster.sink_symbol == "subprocess.run"
    )
    assert subprocess_cluster.member_indexes == (0, 1, 2)
    assert subprocess_cluster.primary_index == 0
    assert {cluster.sink_symbol for cluster in clusters} == {
        "subprocess.run",
        "eval",
        "exec",
    }


def test_cluster_ids_are_stable_across_raw_finding_order(tmp_path):
    findings = [
        _flow_finding(tmp_path, "first", 5, "subprocess.run"),
        _flow_finding(tmp_path, "second", 8, "subprocess.run"),
        _flow_finding(tmp_path, "third", 13, "subprocess.run"),
    ]

    forward_clusters = cluster_findings(findings, str(tmp_path))
    reversed_findings = list(reversed(findings))
    reverse_clusters = cluster_findings(reversed_findings, str(tmp_path))
    forward = {cluster.cluster_id for cluster in forward_clusters}
    reverse = {cluster.cluster_id for cluster in reverse_clusters}

    assert forward == reverse
    assert findings[forward_clusters[0].primary_index].metadata["caller"] == "first"
    assert (
        reversed_findings[reverse_clusters[0].primary_index].metadata["caller"]
        == "first"
    )


def test_json_and_sarif_preserve_raw_traces_and_expose_cluster_counts(tmp_path):
    result = ScanResult(findings=[
        _flow_finding(tmp_path, "first", 5, "subprocess.run"),
        _flow_finding(tmp_path, "second", 8, "subprocess.run"),
        _flow_finding(tmp_path, "third", 13, "subprocess.run"),
    ])

    data = json.loads(to_json(result, str(tmp_path)))
    assert data["summary"]["total"] == 3
    assert data["summary"]["raw_total"] == 3
    assert data["summary"]["clustered_total"] == 1
    assert len(data["findings"]) == 3
    assert len(data["clusters"]) == 1
    assert data["clusters"][0]["finding_indexes"] == [0, 1, 2]
    assert len(data["clusters"][0]["paths"]) == 3
    assert sum(finding["root_cause_primary"] for finding in data["findings"]) == 1

    sarif = to_sarif(result, str(tmp_path))
    run = sarif["runs"][0]
    assert len(run["results"]) == 3
    assert all("codeFlows" in item for item in run["results"])
    assert run["properties"]["rowanRawFindingCount"] == 3
    assert run["properties"]["rowanRootCauseCount"] == 1
    assert len({item["properties"]["rootCauseId"] for item in run["results"]}) == 1
    assert len({
        item["partialFingerprints"]["rowanRootCause/v1"]
        for item in run["results"]
    }) == 1

    text = to_text(result)
    assert "Review clusters: 1" in text
    assert "3 raw flow variants" in text
    assert text.count("Variant:") == 3


def test_authorization_boundaries_never_cluster_from_shared_location():
    findings = [
        Finding(
            rule_id="AUTHZ-BOLA-001",
            message=f"missing authorization for boundary {boundary}",
            severity=Severity.HIGH,
            category=Category.AUTH,
            file_path="routes.py",
            start_line=10,
            engine="authz",
        )
        for boundary in ("tenant", "owner")
    ]

    assert len(cluster_findings(findings)) == 2


def test_cross_file_pass_emits_three_clusterable_raw_variants(tmp_path):
    sink = tmp_path / "sink.py"
    sink.write_text(
        "import pickle\n"
        "def dangerous(payload):\n"
        "    return pickle.loads(payload)\n",
        encoding="utf-8",
    )
    for caller in ("first", "second", "third"):
        (tmp_path / f"{caller}.py").write_text(
            "from flask import request\n"
            "from sink import dangerous\n"
            f"def {caller}():\n"
            "    payload = request.args.get('payload')\n"
            "    return dangerous(payload)\n",
            encoding="utf-8",
        )

    root_finding = Finding(
        rule_id="NS-DESER-001",
        message="pickle.loads() allows arbitrary code execution",
        severity=Severity.HIGH,
        category=Category.DESERIALIZATION,
        file_path=str(sink.resolve()),
        start_line=3,
        engine="opengrep",
    )
    context = ScanContext(
        target_path=tmp_path,
        config=ScanConfig(target=tmp_path),
        result=ScanResult(findings=[root_finding]),
    )

    raw = [
        finding
        for finding in CrossFilePass().run(context).findings
        if finding.rule_id == "CF-SINK-001"
    ]
    clusters = cluster_findings(raw, str(tmp_path))

    assert len(raw) == 3
    assert {finding.metadata["sink_rule_id"] for finding in raw} == {"NS-DESER-001"}
    assert {finding.metadata["sink_symbol"] for finding in raw} == {"pickle.loads"}
    assert len(clusters) == 1
    assert clusters[0].member_indexes == (0, 1, 2)
