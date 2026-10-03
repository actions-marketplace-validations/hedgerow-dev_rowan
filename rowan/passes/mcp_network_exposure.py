"""Structural detection of exposed low-level MCP ASGI servers.

The FastMCP ``run(transport=...)`` rules cover the high-level API.  The
low-level SDK instead commonly builds an ASGI application with
``Server.streamable_http_app()`` or ``Server.sse_app()`` and hands that object
to Uvicorn.  A line-oriented rule cannot prove that the generic-looking ASGI
variable is an MCP application, so this pass keeps the association in the
Python AST.
"""

from __future__ import annotations

import ast
import logging
import re
import time
from pathlib import Path

from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.passes.base import ScanContext, scan_span
from rowan.passes.sources import iter_python_sources

logger = logging.getLogger(__name__)

_RULE_ID = "MCP-HTTP-BIND-001"
_MCP_APP_METHODS = frozenset({"streamable_http_app", "sse_app"})
_AUTH_WRAPPERS = frozenset(
    {
        "AuthenticationMiddleware",
        "AuthMiddleware",
        "BearerAuthMiddleware",
        "RequireAuthMiddleware",
    }
)


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _assigned_names(node: ast.AST) -> set[str]:
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        return {target.id for target in targets if isinstance(target, ast.Name)}
    return set()


def _call_kwarg(call: ast.Call, name: str) -> ast.AST | None:
    return next((kw.value for kw in call.keywords if kw.arg == name), None)


def _is_all_interfaces(value: ast.AST | None) -> bool:
    return isinstance(value, ast.Constant) and value.value in {"0.0.0.0", "::"}  # noqa: S104



_NEGATED_AUTH_NAME = re.compile(r"(?i)(?:disable|skip|no|without)_?auth|auth_?(?:optional|disabled)")

class MCPNetworkExposurePass:
    """Find a low-level MCP ASGI app served on every network interface.

    This is intentionally limited to an imported low-level ``Server`` object
    flowing into one of its documented ASGI app builders and then to
    ``uvicorn.run``.  Generic Starlette/Uvicorn applications are not in scope.
    """

    name = "mcp-network-exposure"

    def run(self, context: ScanContext) -> ScanResult:
        started = time.perf_counter()
        findings: list[Finding] = []
        files_scanned = 0
        all_interface_config, disabled_auth_config = self._insecure_config_defaults(context)
        for path, tree in iter_python_sources(context, owner=self.name, skip_tests=True):
            files_scanned += 1
            findings.extend(self._scan_file(path, tree, all_interface_config, disabled_auth_config))

        result = ScanResult(findings=findings, files_scanned=files_scanned)
        duration = time.perf_counter() - started
        scan_span(self.name, duration)
        logger.info("MCPNetworkExposurePass: %d finding(s) in %.2fs", len(findings), duration)
        return result

    def _scan_file(
        self,
        path: Path,
        tree: ast.Module,
        all_interface_config: set[str],
        disabled_auth_config: set[str],
    ) -> list[Finding]:
        server_names = self._low_level_server_names(tree)
        uvicorn_run_names = self._uvicorn_run_names(tree)
        if not uvicorn_run_names:
            return []
        findings: list[Finding] = []
        if server_names:
            self._scan_block(path, tree.body, server_names, uvicorn_run_names, findings, set())
        if (
            self._has_manual_mcp_http_transport(tree)
            or self._has_low_level_server(tree, server_names)
        ) and disabled_auth_config:
            for node in (item for item in ast.walk(tree) if isinstance(item, ast.Call)):
                if _dotted_name(node.func) not in uvicorn_run_names:
                    continue
                if self._has_visible_auth_wrapper(tree, self._uvicorn_app(node)):
                    continue
                host = _call_kwarg(node, "host")
                if (isinstance(host, ast.Attribute) and host.attr in all_interface_config) or (
                    isinstance(host, ast.Name) and host.id in all_interface_config
                ):
                    findings.append(self._make_finding(path, node, dynamic_default=True))
        return findings

    @staticmethod
    def _uvicorn_app(node: ast.Call) -> ast.AST | None:
        return node.args[0] if node.args else _call_kwarg(node, "app")

    @staticmethod
    def _has_visible_auth_wrapper(tree: ast.Module, app: ast.AST | None) -> bool:
        if isinstance(app, ast.Call):
            return _dotted_name(app.func).rsplit(".", 1)[-1] in _AUTH_WRAPPERS
        if not isinstance(app, ast.Name):
            return False
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            if app.id not in _assigned_names(node):
                continue
            value = getattr(node, "value", None)
            if (
                isinstance(value, ast.Call)
                and _dotted_name(value.func).rsplit(".", 1)[-1] in _AUTH_WRAPPERS
            ):
                return True
        return False

    def _scan_block(
        self,
        path: Path,
        statements: list[ast.stmt],
        server_names: set[str],
        uvicorn_run_names: set[str],
        findings: list[Finding],
        server_vars: set[str],
    ) -> None:
        """Track local variables in statement order within one lexical scope.

        ``app = Server(...).streamable_http_app(); app = Starlette()`` must
        not retain MCP provenance after the rebind.  Conversely, aliases and
        non-auth ASGI middleware preserve the provenance into ``uvicorn.run``.
        """
        app_vars: dict[str, bool] = {}  # name -> visibly protected by auth
        for stmt in statements:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._scan_block(
                    path, stmt.body, server_names, uvicorn_run_names, findings, server_vars.copy()
                )
                continue
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                value = getattr(stmt, "value", None)
                names = _assigned_names(stmt)
                if not names or value is None:
                    continue
                for name in names:
                    server_vars.discard(name)
                    app_vars.pop(name, None)
                if isinstance(value, ast.Call) and _dotted_name(value.func) in server_names:
                    server_vars.update(names)
                    continue
                provenance = self._app_provenance(value, server_vars, app_vars)
                if provenance is not None:
                    app_vars.update({name: provenance for name in names})
                continue
            for call in (node for node in ast.walk(stmt) if isinstance(node, ast.Call)):
                if _dotted_name(call.func) in uvicorn_run_names:
                    self._record_uvicorn_exposure(path, call, server_vars, app_vars, findings)

    @staticmethod
    def _app_provenance(
        value: ast.AST, server_vars: set[str], app_vars: dict[str, bool]
    ) -> bool | None:
        if isinstance(value, ast.Name) and value.id in app_vars:
            return app_vars[value.id]
        if not isinstance(value, ast.Call):
            return None
        if (
            isinstance(value.func, ast.Attribute)
            and value.func.attr in _MCP_APP_METHODS
            and isinstance(value.func.value, ast.Name)
            and value.func.value.id in server_vars
        ):
            return False
        wrapped_apps = [
            arg for arg in value.args if isinstance(arg, ast.Name) and arg.id in app_vars
        ]
        if not wrapped_apps:
            return None
        wrapper = _dotted_name(value.func).split(".")[-1]
        return wrapper in _AUTH_WRAPPERS

    def _record_uvicorn_exposure(
        self,
        path: Path,
        node: ast.Call,
        server_vars: set[str],
        app_vars: dict[str, bool],
        findings: list[Finding],
    ) -> None:
        app = self._uvicorn_app(node)
        if app is None:
            return
        protected = False
        if isinstance(app, ast.Name):
            if app.id not in app_vars:
                return
            protected = app_vars[app.id]
        else:
            provenance = self._app_provenance(app, server_vars, app_vars)
            if provenance is None:
                return
            protected = provenance
        if protected:
            return
        host = _call_kwarg(node, "host")
        if host is None and len(node.args) > 1:
            host = node.args[1]
        if not _is_all_interfaces(host):
            return
        findings.append(self._make_finding(path, node))

    def _make_finding(self, path: Path, node: ast.Call, dynamic_default: bool = False) -> Finding:
        evidence = (
            "MCP HTTP host defaults to all interfaces and its authentication setting defaults off."
            if dynamic_default
            else "Low-level MCP Server ASGI app is exposed through Uvicorn on all interfaces without visible application authentication."
        )
        return Finding(
            rule_id=_RULE_ID,
            message=(
                f"{evidence} Bind to localhost/private ingress or add and verify "
                "authentication before exposing the MCP HTTP endpoint."
            ),
            severity=Severity.HIGH,
            category=Category.AI_ML,
            file_path=str(path),
            start_line=node.lineno,
            end_line=getattr(node, "end_lineno", node.lineno),
            start_column=getattr(node, "col_offset", 0),
            confidence=0.85,
            cwe_ids=[306, 668],
            engine=self.name,
            metadata={"evidence_tier": "engine", "structural_evidence": True},
        )

    @staticmethod
    def _low_level_server_names(tree: ast.Module) -> set[str]:
        names: set[str] = set()
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module
                and node.module.startswith("mcp.server")
            ):
                names.update(
                    alias.asname or alias.name for alias in node.names if alias.name == "Server"
                )
        return names

    @staticmethod
    def _uvicorn_run_names(tree: ast.Module) -> set[str]:
        names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "uvicorn":
                        names.add(f"{alias.asname or alias.name}.run")
            elif isinstance(node, ast.ImportFrom) and node.module == "uvicorn":
                names.update(
                    alias.asname or alias.name for alias in node.names if alias.name == "run"
                )
        return names

    @staticmethod
    def _has_manual_mcp_http_transport(tree: ast.Module) -> bool:
        return any(
            isinstance(node, ast.Call)
            and _dotted_name(node.func).rsplit(".", 1)[-1]
            in {"SseServerTransport", "StreamableHTTPServerTransport"}
            for node in ast.walk(tree)
        )

    @staticmethod
    def _has_low_level_server(tree: ast.Module, server_names: set[str]) -> bool:
        return any(
            isinstance(node, ast.Call) and _dotted_name(node.func) in server_names
            for node in ast.walk(tree)
        )

    @staticmethod
    def _insecure_config_defaults(context: ScanContext) -> tuple[set[str], set[str]]:
        all_interfaces: set[str] = set()
        disabled_auth: set[str] = set()
        # Config defaults may live in test settings too, so tests are kept.
        for _path, tree in iter_python_sources(
            context, owner="mcp-network-exposure-config", skip_tests=False
        ):
            for node in ast.walk(tree):
                if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
                    continue
                names = _assigned_names(node)
                constants = {
                    item.value
                    for item in ast.walk(node.value)
                    if isinstance(item, ast.Constant) and isinstance(item.value, str)
                }
                if constants & {"0.0.0.0", "::"}:  # noqa: S104
                    all_interfaces.update(names)
                for name in names:
                    if "auth" not in name.lower():
                        continue
                    # DISABLE_AUTH / SKIP_AUTH / AUTH_OPTIONAL invert the
                    # meaning: auth is off when they are true (AZ-19).
                    off_values = (
                        {"1", "true", "True"} if _NEGATED_AUTH_NAME.search(name) else {"0", "false", "False"}
                    )
                    if constants & off_values:
                        disabled_auth.add(name)
        return all_interfaces, disabled_auth
