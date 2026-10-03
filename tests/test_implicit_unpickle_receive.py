"""Regression tests for NS-DESER-012 / NS-DESER-013 (implicit-unpickle receive).

Some receive APIs call pickle.loads() for you: zmq's Socket.recv_pyobj() and
multiprocessing.connection.Connection.recv(). Nothing in the caller's source
shows a deserializer, so the taint engine has no source-to-sink flow to follow
(TNT-DESER-004 only fires on the explicit recv_multipart() -> pickle.loads()
shape). Before these rules, the idiomatic SGLang-style broker below produced no
deserialization finding at all, which is the shape of CVE-2026-3059 and
CVE-2026-3060.

Both a true positive and a true negative are asserted for each rule, since the
whole point of the narrowing is that recv_json() (JSON, not pickle) and a
Unix-socket Listener (filesystem-permission guarded) must stay quiet.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import Severity
from rowan.core.rules import load_neuroscan_rules
from rowan.pipeline import ScanPipeline

RULES_PATH = Path(__file__).parent.parent / "rules" / "security_surface.yaml"

FIXTURES: dict[str, str] = {
    # TP: zmq broker bound to all interfaces, unpickles every frame.
    "zmq_broker.py": (
        "import zmq\n"
        "\n"
        "ctx = zmq.Context()\n"
        "sock = ctx.socket(zmq.REP)\n"
        'sock.bind("tcp://*:5555")\n'
        "while True:\n"
        "    obj = sock.recv_pyobj()\n"
        '    sock.send_pyobj({"echo": obj})\n'
    ),
    # TN: same shape over JSON, which is not pickle and not RCE.
    "zmq_json.py": (
        "import zmq\n"
        "\n"
        "ctx = zmq.Context()\n"
        "sock = ctx.socket(zmq.REP)\n"
        'sock.bind("tcp://*:5555")\n'
        "while True:\n"
        "    obj = sock.recv_json()\n"
        '    sock.send_json({"echo": obj})\n'
    ),
    # TP: Listener on a host/port tuple accepts network peers whose recv()
    # unpickles.
    "mp_net.py": (
        "import multiprocessing.connection\n"
        "\n"
        'listener = multiprocessing.connection.Listener(("0.0.0.0", 6000))\n'
        "conn = listener.accept()\n"
        "payload = conn.recv()\n"
    ),
    # TN: a string address is a Unix socket / named pipe, guarded by
    # filesystem permissions rather than open to the network.
    "mp_unix.py": (
        "import multiprocessing.connection\n"
        "\n"
        'listener = multiprocessing.connection.Listener("/tmp/rowan.sock")\n'
        "conn = listener.accept()\n"
        "payload = conn.recv()\n"
    ),
    # TN: authkey means an unauthenticated peer never reaches the unpickle.
    # Deliberately on one line, so the rule's pattern genuinely matches here
    # and only the authkey exclusion suppresses it.
    "mp_authed.py": (
        "import multiprocessing.connection\n"
        "\n"
        "listener = multiprocessing.connection.Listener("
        '("0.0.0.0", 6000), authkey=b"s3cret")\n'
        "conn = listener.accept()\n"
        "payload = conn.recv()\n"
    ),
}


def _write_fixtures(root: Path) -> Path:
    src = root / "src"
    src.mkdir()
    for name, body in FIXTURES.items():
        (src / name).write_text(body, encoding="utf-8")
    return src


@pytest.fixture(scope="module")
def scan_findings(tmp_path_factory) -> list:
    """Run the default (converted-rule / Opengrep) engine once for all cases.

    Scoped to the module because this is the path a real user gets, and it
    costs an Opengrep subprocess per invocation.
    """
    root = tmp_path_factory.mktemp("implicit_unpickle")
    _write_fixtures(root)
    config = ScanConfig(
        target=root,
        no_sca=True,
        no_cross_file=True,
        languages=["python"],
    )
    return ScanPipeline(config).run().findings


def _hits(findings: list, rule_id: str, filename: str) -> list:
    return [
        f
        for f in findings
        if f.rule_id == rule_id and Path(f.file_path).name == filename
    ]


class TestDefaultEngine:
    """End-to-end through the converted rules the shipped scanner actually
    runs, not just the source YAML."""

    def test_recv_pyobj_is_reported(self, scan_findings):
        hits = _hits(scan_findings, "NS-DESER-012", "zmq_broker.py")
        assert hits, (
            "recv_pyobj() unpickles the frame it receives and must be reported; "
            f"got: {[(f.rule_id, Path(f.file_path).name) for f in scan_findings]}"
        )
        assert hits[0].severity in (Severity.HIGH, Severity.CRITICAL)

    def test_recv_json_is_not_reported(self, scan_findings):
        assert not _hits(scan_findings, "NS-DESER-012", "zmq_json.py")

    def test_network_listener_is_reported(self, scan_findings):
        hits = _hits(scan_findings, "NS-DESER-013", "mp_net.py")
        assert hits, (
            "A Listener on a host/port tuple unpickles whatever a network peer "
            f"sends; got: {[(f.rule_id, Path(f.file_path).name) for f in scan_findings]}"
        )
        assert hits[0].severity in (Severity.HIGH, Severity.CRITICAL)

    def test_unix_socket_listener_is_not_reported(self, scan_findings):
        assert not _hits(scan_findings, "NS-DESER-013", "mp_unix.py")

    def test_authkey_listener_is_not_reported(self, scan_findings):
        assert not _hits(scan_findings, "NS-DESER-013", "mp_authed.py")


class TestSourceRules:
    """Same expectations against the authored YAML via the legacy regex
    engine, so a conversion regression is distinguishable from a rule bug."""

    @pytest.fixture(scope="class")
    def rules(self):
        return [
            r
            for r in load_neuroscan_rules(RULES_PATH)
            if r.metadata.id in ("NS-DESER-012", "NS-DESER-013")
        ]

    @pytest.fixture(scope="class")
    def src(self, tmp_path_factory):
        return _write_fixtures(tmp_path_factory.mktemp("implicit_unpickle_src"))

    @pytest.mark.parametrize(
        ("filename", "rule_id"),
        [
            ("zmq_broker.py", "NS-DESER-012"),
            ("mp_net.py", "NS-DESER-013"),
        ],
    )
    def test_true_positives(self, rules, src, filename, rule_id):
        rule = next(r for r in rules if r.metadata.id == rule_id)
        assert rule.check(src / filename)

    @pytest.mark.parametrize(
        ("filename", "rule_id"),
        [
            ("zmq_json.py", "NS-DESER-012"),
            ("mp_unix.py", "NS-DESER-013"),
            ("mp_authed.py", "NS-DESER-013"),
        ],
    )
    def test_true_negatives(self, rules, src, filename, rule_id):
        rule = next(r for r in rules if r.metadata.id == rule_id)
        assert not rule.check(src / filename)
