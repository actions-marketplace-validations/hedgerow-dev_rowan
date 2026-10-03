"""Hidden-directory skipping must be judged relative to the scan root.

Several passes skip dot-prefixed paths. Testing that against the *absolute*
path means a project checked out under a dotted ancestor (a git worktree in
`.claude/worktrees/`, a cache under `~/.cache/`) has every one of its files
skipped, and the scan reports zero findings instead of an error -- a file that
was never analysed, indistinguishable from a clean one.
"""

from __future__ import annotations

from pathlib import Path

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.authz import AuthzPass
from rowan.passes.base import ScanContext
from rowan.passes.cross_file import _collect_python_files
from rowan.passes.js_cross_file import _collect_js_files
from rowan.passes.sources import filter_python_paths

_BOLA_VIEW = (
    "from django.http import HttpResponse\n"
    "def document_detail(request, pk):\n"
    "    doc = Document.objects.get(id=pk)\n"
    "    return render(doc)\n"
)
_PRINCIPAL = (
    "def whoami(request):\n"
    "    return request.user.id\n"
)


def _project_under_dotted_parent(tmp_path: Path) -> Path:
    root = tmp_path / ".worktrees" / "checkout"
    root.mkdir(parents=True)
    (root / "views.py").write_text(_BOLA_VIEW, encoding="utf-8")
    (root / "auth.py").write_text(_PRINCIPAL, encoding="utf-8")
    (root / "app.js").write_text("export function handler() {}\n", encoding="utf-8")
    return root


def test_authz_still_reports_under_a_dotted_ancestor(tmp_path):
    root = _project_under_dotted_parent(tmp_path)
    ctx = ScanContext(
        target_path=root,
        config=ScanConfig(target=root, enable_authz=True),
        result=ScanResult(),
    )
    result = AuthzPass().run(ctx)
    assert [f for f in result.findings if f.rule_id == "AUTHZ-BOLA-001"]


def test_collectors_see_files_under_a_dotted_ancestor(tmp_path):
    root = _project_under_dotted_parent(tmp_path)

    assert {p.name for p in _collect_python_files(root)} == {"views.py", "auth.py"}
    assert {p.name for p in _collect_js_files(root)} == {"app.js"}
    assert {
        p.name for p in filter_python_paths(root, root.rglob("*.py"), [], skip_tests=False)
    } == {"views.py", "auth.py"}


def test_hidden_directories_inside_the_root_are_still_skipped(tmp_path):
    root = _project_under_dotted_parent(tmp_path)
    (root / ".venv").mkdir()
    (root / ".venv" / "vendored.py").write_text("x = 1\n", encoding="utf-8")
    (root / ".next").mkdir()
    (root / ".next" / "bundle.js").write_text("export function y() {}\n", encoding="utf-8")

    assert "vendored.py" not in {p.name for p in _collect_python_files(root)}
    assert "bundle.js" not in {p.name for p in _collect_js_files(root)}
