from pathlib import Path

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext
from rowan.passes.cross_file import CrossFilePass


def _scan(root: Path, source: str):
    (root / "native.py").write_text(source, encoding="utf-8")
    (root / "app.py").write_text("from native import dispatch\n", encoding="utf-8")
    findings = CrossFilePass().run(
        ScanContext(root, ScanConfig(root), ScanResult())
    ).findings
    return [f for f in findings if f.rule_id == "AGENT-REFLECTION-SURFACE-001"]


_BASE = """
class Actions:
    def search(self, query=''):
        return query
    def _debug_eval(self, expression=''):
        return eval(expression, {'__builtins__': {}}, {})

ACTIONS = Actions()
PUBLIC_ACTIONS = ('search',)

def action_schemas():
    return [{'type': 'function', 'function': {'name': name}} for name in PUBLIC_ACTIONS]
"""


def test_unconstrained_reflective_dispatch_exposes_hidden_method(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        _BASE + """
def dispatch(name, **kwargs):
    function = getattr(ACTIONS, name, None)
    if callable(function):
        return function(**kwargs)
""",
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.cwe_ids == [470]
    assert finding.metadata["advertised_surface"] == ["search"]
    assert finding.metadata["hidden_capabilities"] == ["code execution"]


def test_rejecting_advertised_surface_guard_suppresses(tmp_path: Path) -> None:
    assert _scan(
        tmp_path,
        _BASE + """
def dispatch(name, **kwargs):
    if name not in PUBLIC_ACTIONS:
        return {'error': 'not allowed'}
    function = getattr(ACTIONS, name, None)
    if callable(function):
        return function(**kwargs)
""",
    ) == []


def test_reflection_without_hidden_dangerous_capability_is_not_reported(tmp_path: Path) -> None:
    source = """
class Actions:
    def search(self, query=''):
        return query
    def format_result(self, value=''):
        return value.strip()

ACTIONS = Actions()
PUBLIC_ACTIONS = ('search',)

def action_schemas():
    return [{'function': {'name': name}} for name in PUBLIC_ACTIONS]

def dispatch(name, **kwargs):
    function = getattr(ACTIONS, name, None)
    if callable(function):
        return function(**kwargs)
"""
    assert _scan(tmp_path, source) == []


def test_introspection_without_invocation_is_not_dispatch(tmp_path: Path) -> None:
    assert _scan(
        tmp_path,
        _BASE + """
def describe(name):
    function = getattr(ACTIONS, name, None)
    return getattr(function, '__doc__', '')
""",
    ) == []
