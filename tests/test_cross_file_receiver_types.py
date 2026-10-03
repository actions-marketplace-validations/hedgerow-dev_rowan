"""Receiver type inference + inherited-method resolution (#158, Phase C1).

Each test writes a small multi-file project to a tmp dir and runs the real
CrossFilePass, asserting that a method call resolves to the *typed receiver's*
defining file -- not merely a same-named method on an unrelated class.
"""

from __future__ import annotations

import ast
from pathlib import Path

from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.passes.base import ScanConfig, ScanContext
from rowan.passes.cross_file import (
    CrossFilePass,
    _build_class_model,
    _ClassModel,
    _infer_receiver_class,
    _infer_var_types,
    _resolve_method_file,
)


def _write(root: Path, rel: str, body: str) -> str:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return str(p.resolve())


def _sink_finding(file_str: str, line: int) -> Finding:
    """A NeuroScan-style command-injection sink marker on the callee's sink
    line -- in the real pipeline TaintPass/FileScanPass produce this; here we
    inject it so the callee function is flagged has_sink and cross-file
    propagation can run. `_is_sink_rule` recognizes the NS-CMDI prefix."""
    return Finding(
        rule_id="NS-CMDI-001",
        message="os.system on tainted data",
        severity=Severity.HIGH,
        category=Category.COMMAND_INJECTION,
        file_path=file_str,
        start_line=line,
        engine="neuroscan",
    )


def _os_system_line(file_str: str) -> int:
    for i, ln in enumerate(Path(file_str).read_text().splitlines(), start=1):
        if "os.system(" in ln:
            return i
    raise AssertionError(f"no os.system( in {file_str}")


def _run(root: Path, findings: list[Finding] | None = None) -> list[Finding]:
    ctx = ScanContext(
        target_path=root,
        config=ScanConfig(target=root),
        result=ScanResult(findings=findings or []),
    )
    return CrossFilePass().run(ctx).findings


def _cf(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.engine == "crossfile"]


# --------------------------------------------------------------------------- #
# Unit-level helper tests
# --------------------------------------------------------------------------- #

def _model_from(sources: dict[str, str]) -> _ClassModel:
    parsed = [(name, ast.parse(src)) for name, src in sources.items()]
    return _build_class_model(parsed)


def test_build_class_model_records_methods_bases_attrs():
    model = _model_from({
        "a.py": (
            "class Base:\n"
            "    def persist(self, x): ...\n"
            "class Repo(Base):\n"
            "    def __init__(self):\n"
            "        self.db = Database()\n"
            "    def save(self, x): ...\n"
        ),
    })
    repo = model.registry[("a.py", "Repo")]
    assert repo.bases == ["Base"]
    assert "save" in repo.methods
    assert repo.attr_types == {"db": "Database"}
    assert {ci.name for ci in model.by_name["Repo"]} == {"Repo"}


def test_infer_var_types_from_assignment_and_annotation():
    src = (
        "def h(self, repo: UserRepo):\n"
        "    other = AuditRepo()\n"
        "    return repo, other\n"
    )
    func = ast.parse(src).body[0]
    var_types = _infer_var_types(func, enclosing_class="Handler")
    assert var_types["repo"] == "UserRepo"
    assert var_types["other"] == "AuditRepo"
    assert var_types["self"] == "Handler"


def test_infer_var_types_unwraps_optional():
    src = "def h(cfg: Optional[Config], other: Thing | None): ...\n"
    func = ast.parse(src).body[0]
    var_types = _infer_var_types(func, enclosing_class=None)
    assert var_types["cfg"] == "Config"
    assert var_types["other"] == "Thing"


def test_resolve_method_file_walks_bases():
    model = _model_from({
        "base.py": "class Base:\n    def persist(self, x): ...\n",
        "impl.py": "class Concrete(Base):\n    def other(self): ...\n",
    })
    # persist is inherited from Base -> resolves to base.py
    assert _resolve_method_file("Concrete", "persist", model) == "base.py"
    # other is defined directly -> impl.py
    assert _resolve_method_file("Concrete", "other", model) == "impl.py"
    # unknown method -> None
    assert _resolve_method_file("Concrete", "nope", model) is None


def test_resolve_method_file_base_cycle_terminates():
    # Pathological mutual inheritance must not loop forever.
    model = _model_from({
        "x.py": "class A(B):\n    pass\nclass B(A):\n    def m(self): ...\n",
    })
    assert _resolve_method_file("A", "m", model) == "x.py"
    assert _resolve_method_file("A", "missing", model) is None


def test_infer_receiver_class_self_attr():
    model = _model_from({
        "a.py": (
            "class Handler:\n"
            "    def __init__(self):\n"
            "        self.repo = UserRepo()\n"
            "    def go(self):\n"
            "        self.repo.save(1)\n"
        ),
    })
    assert ("a.py", "Handler") in model.registry
    # find the self.repo.save(1) call node
    tree = ast.parse(
        "class Handler:\n"
        "    def __init__(self):\n"
        "        self.repo = UserRepo()\n"
        "    def go(self):\n"
        "        self.repo.save(1)\n"
    )
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "attr", None) == "save")
    var_types = {"self": "Handler"}
    assert _infer_receiver_class(call, var_types, model) == "UserRepo"


# --------------------------------------------------------------------------- #
# End-to-end pass tests
# --------------------------------------------------------------------------- #

_SINK_BODY = (
    "class {cls}:\n"
    "    def {method}(self, data):\n"
    "        import os\n"
    "        os.system(data)\n"
)

_BENIGN_BODY = (
    "class {cls}:\n"
    "    def {method}(self, data):\n"
    "        return len(data)\n"
)


def test_typed_local_resolves_to_correct_class(tmp_path):
    # UserRepo.save is a sink; AuditRepo.save is benign. A caller that reads a
    # source and calls a UserRepo instance's save() must resolve to UserRepo,
    # not the same-named AuditRepo.save.
    repos = _write(tmp_path, "repos.py", _SINK_BODY.format(cls="UserRepo", method="save"))
    _write(tmp_path, "audit.py", _BENIGN_BODY.format(cls="AuditRepo", method="save"))
    _write(
        tmp_path,
        "handler.py",
        (
            "from repos import UserRepo\n"
            "from flask import request\n"
            "def handle():\n"
            "    payload = request.args.get('x')\n"
            "    repo = UserRepo()\n"
            "    repo.save(payload)\n"
        ),
    )
    cf = _cf(_run(tmp_path, [_sink_finding(repos, _os_system_line(repos))]))
    assert any("handle" in f.message for f in cf), f"expected cross-file finding, got {[f.message for f in cf]}"
    # the resolved callee must be the sink file, not audit.py
    assert any("repos.py" in (f.metadata.get("callee_file") or "") for f in cf)
    assert not any("audit.py" in (f.metadata.get("callee_file") or "") for f in cf)


def test_annotated_param_resolves_across_files(tmp_path):
    repos = _write(tmp_path, "repos.py", _SINK_BODY.format(cls="UserRepo", method="run"))
    _write(
        tmp_path,
        "handler.py",
        (
            "from repos import UserRepo\n"
            "from flask import request\n"
            "def handle(repo: UserRepo):\n"
            "    payload = request.args.get('x')\n"
            "    repo.run(payload)\n"
        ),
    )
    cf = _cf(_run(tmp_path, [_sink_finding(repos, _os_system_line(repos))]))
    assert any("repos.py" in (f.metadata.get("callee_file") or "") for f in cf)


def test_inherited_method_resolves_to_base_file(tmp_path):
    base = _write(tmp_path, "base.py", _SINK_BODY.format(cls="Base", method="persist"))
    _write(
        tmp_path,
        "impl.py",
        "from base import Base\nclass Concrete(Base):\n    def extra(self): ...\n",
    )
    _write(
        tmp_path,
        "handler.py",
        (
            "from impl import Concrete\n"
            "from flask import request\n"
            "def handle():\n"
            "    payload = request.args.get('x')\n"
            "    c = Concrete()\n"
            "    c.persist(payload)\n"
        ),
    )
    cf = _cf(_run(tmp_path, [_sink_finding(base, _os_system_line(base))]))
    assert any("base.py" in (f.metadata.get("callee_file") or "") for f in cf)


def test_self_attr_resolves_across_files(tmp_path):
    repos = _write(tmp_path, "repos.py", _SINK_BODY.format(cls="UserRepo", method="save"))
    _write(
        tmp_path,
        "service.py",
        (
            "from repos import UserRepo\n"
            "from flask import request\n"
            "class Service:\n"
            "    def __init__(self):\n"
            "        self.repo = UserRepo()\n"
            "    def handle(self):\n"
            "        payload = request.args.get('x')\n"
            "        self.repo.save(payload)\n"
        ),
    )
    cf = _cf(_run(tmp_path, [_sink_finding(repos, _os_system_line(repos))]))
    assert any("repos.py" in (f.metadata.get("callee_file") or "") for f in cf)


def test_deep_untyped_chain_creates_no_edge(tmp_path):
    # a.b.c.method() with no type info stays unresolved -- must NOT fabricate a
    # cross-file edge to a same-named method elsewhere.
    repos = _write(tmp_path, "repos.py", _SINK_BODY.format(cls="UserRepo", method="save"))
    _write(
        tmp_path,
        "handler.py",
        (
            "from flask import request\n"
            "def handle(obj):\n"
            "    payload = request.args.get('x')\n"
            "    obj.a.b.save(payload)\n"
        ),
    )
    # Sink exists; the ONLY reason no edge should form is the unresolvable
    # deep receiver chain (obj.a.b) -- not a missing sink.
    cf = _cf(_run(tmp_path, [_sink_finding(repos, _os_system_line(repos))]))
    assert not any("repos.py" in (f.metadata.get("callee_file") or "") for f in cf)
