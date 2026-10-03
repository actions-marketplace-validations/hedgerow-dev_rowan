"""Tests for the optional Express/Mongoose BOLA/IDOR pass (JSAuthzPass)."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult, Severity
from rowan.passes.base import ScanContext
from rowan.passes.js_authz import JSAuthzPass
from rowan.passes.js_cross_file import TREE_SITTER_AVAILABLE

pytestmark = pytest.mark.skipif(not TREE_SITTER_AVAILABLE, reason="tree-sitter not installed")


def _run_js(source: str, *, enable_authz: bool = True) -> ScanResult:
    root = Path(tempfile.mkdtemp(prefix="rowan_js_authz_"))
    (root / "app.js").write_text(source, encoding="utf-8")
    config = ScanConfig(target=root, enable_authz=enable_authz)
    ctx = ScanContext(target_path=root, config=config, result=ScanResult())
    return JSAuthzPass().run(ctx)


def _bola(result: ScanResult):
    return [f for f in result.findings if f.rule_id == "AUTHZ-BOLA-001"]


def test_express_findbyid_without_owner_guard_is_high():
    result = _run_js(
        "app.use((req, res, next) => { req.user = auth(req); next(); });\n"
        "app.get('/doc/:id', async (req, res) => {\n"
        "  const doc = await Doc.findById(req.params.id);\n"
        "  res.json(doc);\n"
        "});\n"
    )
    findings = _bola(result)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].metadata["model"] == "Doc"


def test_js_authz_finding_carries_remediation_guidance():
    result = _run_js(
        "app.use((req, res, next) => { req.user = auth(req); next(); });\n"
        "app.get('/doc/:id', async (req, res) => {\n"
        "  const doc = await Doc.findById(req.params.id);\n"
        "  res.json(doc);\n"
        "});\n"
    )
    assert "owner" in _bola(result)[0].metadata["remediation"]


def test_express_dominating_owner_guard_suppresses():
    result = _run_js(
        "app.get('/doc/:id', async (req, res) => {\n"
        "  const doc = await Doc.findById(req.params.id);\n"
        "  if (doc.ownerId !== req.user.id) return res.sendStatus(403);\n"
        "  res.json(doc);\n"
        "});\n"
    )
    assert _bola(result) == []


def test_express_guard_after_response_is_medium():
    result = _run_js(
        "app.get('/doc/:id', async (req, res) => {\n"
        "  const doc = await Doc.findById(req.params.id);\n"
        "  res.json(doc);\n"
        "  if (doc.ownerId !== req.user.id) return res.sendStatus(403);\n"
        "});\n"
    )
    findings = _bola(result)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].metadata["reason"] == "guard_not_dominating"


def test_express_equality_inverted_owner_guard_suppresses():
    result = _run_js(
        "app.get('/doc/:id', async (req, res) => {\n"
        "  const doc = await Doc.findById(req.params.id);\n"
        "  if (doc.ownerId === req.user.id) {\n"
        "    res.status(200).json(doc);\n"
        "  } else {\n"
        "    res.status(403).json({ error: 'forbidden' });\n"
        "  }\n"
        "});\n"
    )
    assert _bola(result) == []


def test_express_chained_status_response_without_guard_is_high():
    result = _run_js(
        "app.use((req, res, next) => { req.user = auth(req); next(); });\n"
        "app.get('/doc/:id', async (req, res) => {\n"
        "  const doc = await Doc.findById(req.params.id);\n"
        "  res.status(200).json(doc);\n"
        "});\n"
    )
    findings = _bola(result)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_express_query_fused_owner_read_suppresses():
    result = _run_js(
        "app.get('/doc/:id', async (req, res) => {\n"
        "  const doc = await Doc.findOne({ _id: req.params.id, ownerId: req.user.id });\n"
        "  res.json(doc);\n"
        "});\n"
    )
    assert _bola(result) == []


def test_express_sequelize_findbypk_without_guard_is_high():
    result = _run_js(
        "app.use((req, res, next) => { req.user = auth(req); next(); });\n"
        "app.get('/doc/:id', async (req, res) => {\n"
        "  const doc = await Doc.findByPk(req.params.id);\n"
        "  res.json(doc);\n"
        "});\n"
    )
    findings = _bola(result)
    assert len(findings) == 1
    assert findings[0].metadata["model"] == "Doc"


def test_express_prisma_findunique_without_guard_is_high():
    result = _run_js(
        "app.use((req, res, next) => { req.user = auth(req); next(); });\n"
        "app.get('/doc/:id', async (req, res) => {\n"
        "  const doc = await prisma.doc.findUnique({ where: { id: req.params.id } });\n"
        "  res.json(doc);\n"
        "});\n"
    )
    findings = _bola(result)
    assert len(findings) == 1
    assert findings[0].metadata["model"] == "doc"


def test_express_prisma_where_owner_fused_suppresses():
    result = _run_js(
        "app.get('/doc/:id', async (req, res) => {\n"
        "  const doc = await prisma.doc.findUnique({\n"
        "    where: { id: req.params.id, ownerId: req.user.id },\n"
        "  });\n"
        "  res.json(doc);\n"
        "});\n"
    )
    assert _bola(result) == []


def test_koa_ctx_body_without_guard_is_high():
    result = _run_js(
        "app.use((ctx, next) => { ctx.state.user = auth(ctx); next(); });\n"
        "router.get('/doc/:id', async (ctx) => {\n"
        "  const doc = await Doc.findById(ctx.params.id);\n"
        "  ctx.body = doc;\n"
        "});\n"
    )
    findings = _bola(result)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_koa_ctx_throw_owner_guard_suppresses():
    result = _run_js(
        "router.get('/doc/:id', async (ctx) => {\n"
        "  const doc = await Doc.findById(ctx.params.id);\n"
        "  if (doc.ownerId !== ctx.state.user.id) ctx.throw(403);\n"
        "  ctx.body = doc;\n"
        "});\n"
    )
    assert _bola(result) == []


def test_koa_guard_after_body_is_medium():
    result = _run_js(
        "router.get('/doc/:id', async (ctx) => {\n"
        "  const doc = await Doc.findById(ctx.params.id);\n"
        "  ctx.body = doc;\n"
        "  if (doc.ownerId !== ctx.state.user.id) ctx.throw(403);\n"
        "});\n"
    )
    findings = _bola(result)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_nextjs_pages_api_without_guard_is_high():
    result = _run_js(
        "export const auth = (req) => req.user;\n"
        "export default async function handler(req, res) {\n"
        "  const doc = await Doc.findById(req.query.id);\n"
        "  res.json(doc);\n"
        "}\n"
    )
    findings = _bola(result)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_nextjs_pages_api_owner_guard_suppresses():
    result = _run_js(
        "export default async function handler(req, res) {\n"
        "  const doc = await Doc.findById(req.query.id);\n"
        "  if (doc.ownerId !== req.user.id) return res.sendStatus(403);\n"
        "  res.json(doc);\n"
        "}\n"
    )
    assert _bola(result) == []


def test_nextjs_app_router_get_destructured_params_high():
    result = _run_js(
        "export const session = (req) => req.user;\n"
        "export async function GET(req, { params }) {\n"
        "  const { id } = params;\n"
        "  const doc = await Doc.findById(id);\n"
        "  return NextResponse.json(doc);\n"
        "}\n"
    )
    findings = _bola(result)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_nextjs_app_router_post_nexturl_searchparams_high():
    result = _run_js(
        "export const session = (req) => req.user;\n"
        "export async function POST(req) {\n"
        "  const doc = await Doc.findById(req.nextUrl.searchParams.get('id'));\n"
        "  return Response.json(doc);\n"
        "}\n"
    )
    findings = _bola(result)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_express_string_wrapped_owner_guard_suppresses():
    result = _run_js(
        "app.get('/doc/:id', async (req, res) => {\n"
        "  const doc = await Doc.findById(req.params.id);\n"
        "  if (String(doc.ownerId) !== String(req.user.id)) return res.sendStatus(403);\n"
        "  res.json(doc);\n"
        "});\n"
    )
    assert _bola(result) == []


def test_mongoose_findbyidandupdate_without_guard_is_high():
    result = _run_js(
        "app.use((req, res, next) => { req.user = auth(req); next(); });\n"
        "app.post('/doc/:id', async (req, res) => {\n"
        "  const doc = await Doc.findByIdAndUpdate(req.params.id, req.body);\n"
        "  res.json(doc);\n"
        "});\n"
    )
    findings = _bola(result)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_prisma_delete_without_guard_is_high():
    result = _run_js(
        "app.use((req, res, next) => { req.user = auth(req); next(); });\n"
        "app.delete('/doc/:id', async (req, res) => {\n"
        "  await prisma.doc.delete({ where: { id: req.params.id } });\n"
        "  res.json({ ok: true });\n"
        "});\n"
    )
    findings = _bola(result)
    assert len(findings) == 1
    assert findings[0].metadata["model"] == "doc"


def test_disabled_by_default_emits_nothing():
    result = _run_js(
        "app.get('/doc/:id', async (req, res) => {\n"
        "  const doc = await Doc.findById(req.params.id);\n"
        "  res.json(doc);\n"
        "});\n",
        enable_authz=False,
    )
    assert result.findings == []


def test_404_message_naming_the_variable_is_not_an_escape():
    """AZ-13: 'doc not found' mentions doc as text, not as the object."""
    result = _run_js(
        "app.get('/doc/:id', async (req, res) => {\n"
        "  const doc = await Doc.findById(req.params.id);\n"
        "  if (!doc) return res.status(404).json({ error: 'doc not found' });\n"
        "  if (doc.ownerId !== req.user.id) return res.sendStatus(403);\n"
        "  res.json(doc);\n"
        "});\n"
    )
    assert _bola(result) == []
