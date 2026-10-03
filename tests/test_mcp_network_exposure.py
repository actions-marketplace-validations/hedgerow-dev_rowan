from __future__ import annotations

from pathlib import Path

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext
from rowan.passes.mcp_network_exposure import MCPNetworkExposurePass
from rowan.pipeline import ScanPipeline


def _scan(tmp_path: Path, source: str):
    (tmp_path / "server.py").write_text(source, encoding="utf-8")
    context = ScanContext(
        target_path=tmp_path,
        config=ScanConfig(target=tmp_path),
        result=ScanResult(),
    )
    return MCPNetworkExposurePass().run(context).findings


_LOW_LEVEL = """\
from mcp.server import Server
import uvicorn

server = Server("inventory")
starlette_app = server.streamable_http_app()
"""


def test_low_level_mcp_asgi_app_on_all_interfaces_is_flagged(tmp_path):
    findings = _scan(tmp_path, _LOW_LEVEL + "uvicorn.run(starlette_app, host='0.0.0.0')\n")
    assert [finding.rule_id for finding in findings] == ["MCP-HTTP-BIND-001"]


def test_aliased_uvicorn_and_positional_all_interfaces_are_flagged(tmp_path):
    source = _LOW_LEVEL.replace("import uvicorn", "import uvicorn as asgi")
    findings = _scan(tmp_path, source + "asgi.run(starlette_app, '::')\n")
    assert [finding.rule_id for finding in findings] == ["MCP-HTTP-BIND-001"]


def test_direct_low_level_app_expression_is_flagged(tmp_path):
    source = _LOW_LEVEL.replace(
        "starlette_app = server.streamable_http_app()\n",
        "uvicorn.run(server.streamable_http_app(), host='0.0.0.0')\n",
    )
    assert [finding.rule_id for finding in _scan(tmp_path, source)] == ["MCP-HTTP-BIND-001"]


def test_keyword_app_and_module_server_used_in_function_are_flagged(tmp_path):
    source = """\
from mcp.server import Server
import uvicorn

server = Server('inventory')
def main():
    app = server.streamable_http_app()
    uvicorn.run(app=app, host='0.0.0.0')
"""
    assert [finding.rule_id for finding in _scan(tmp_path, source)] == ["MCP-HTTP-BIND-001"]


def test_alias_and_non_auth_wrapper_preserve_mcp_app_provenance(tmp_path):
    source = (
        _LOW_LEVEL
        + """\
from starlette.middleware.cors import CORSMiddleware

public_app = CORSMiddleware(starlette_app, allow_origins=['*'])
uvicorn.run(public_app, host='0.0.0.0')
"""
    )
    assert [finding.rule_id for finding in _scan(tmp_path, source)] == ["MCP-HTTP-BIND-001"]


def test_low_level_mcp_asgi_app_on_localhost_is_not_flagged(tmp_path):
    assert _scan(tmp_path, _LOW_LEVEL + "uvicorn.run(starlette_app, host='127.0.0.1')\n") == []


def test_generic_starlette_app_on_all_interfaces_is_not_flagged(tmp_path):
    source = """\
from starlette.applications import Starlette
import uvicorn

starlette_app = Starlette()
uvicorn.run(starlette_app, host='0.0.0.0')
"""
    assert _scan(tmp_path, source) == []


def test_rebound_generic_app_is_not_flagged(tmp_path):
    source = (
        _LOW_LEVEL
        + """\
from starlette.applications import Starlette

starlette_app = Starlette()
uvicorn.run(starlette_app, host='0.0.0.0')
"""
    )
    assert _scan(tmp_path, source) == []


def test_authenticated_wrapper_is_not_flagged(tmp_path):
    source = (
        _LOW_LEVEL
        + """\
from starlette.middleware.authentication import AuthenticationMiddleware

protected_app = AuthenticationMiddleware(starlette_app, backend=backend)
uvicorn.run(protected_app, host='0.0.0.0')
"""
    )
    assert _scan(tmp_path, source) == []


def test_low_level_sse_with_fail_open_config_is_flagged(tmp_path):
    (tmp_path / "config.py").write_text(
        "class Config:\n"
        "    MCP_HOST = os.environ.get('MCP_HOST', '0.0.0.0')\n"
        "    REQUIRE_AUTH = os.environ.get('MCP_AUTH', '0') == '1'\n",
        encoding="utf-8",
    )
    findings = _scan(
        tmp_path,
        """\
from mcp.server.sse import SseServerTransport
import uvicorn
from config import Config

sse = SseServerTransport('/messages/')
starlette_app = Starlette()
uvicorn.run(starlette_app, host=Config.MCP_HOST)
""",
    )
    assert [finding.rule_id for finding in findings] == ["MCP-HTTP-BIND-001"]


def test_low_level_server_with_fail_open_config_is_flagged(tmp_path):
    (tmp_path / "config.py").write_text(
        "MCP_HOST = os.environ.get('MCP_HOST', '0.0.0.0')\n"
        "REQUIRE_AUTH = os.environ.get('MCP_AUTH', '0') == '1'\n",
        encoding="utf-8",
    )
    findings = _scan(
        tmp_path,
        """\
from mcp.server import Server
import uvicorn
from config import MCP_HOST

server = Server('inventory')
app = server.streamable_http_app()
uvicorn.run(app, host=MCP_HOST)
""",
    )
    assert [finding.rule_id for finding in findings] == ["MCP-HTTP-BIND-001"]


def test_fail_open_config_with_visible_auth_wrapper_is_not_flagged(tmp_path):
    (tmp_path / "config.py").write_text(
        "MCP_HOST = os.environ.get('MCP_HOST', '0.0.0.0')\n"
        "REQUIRE_AUTH = os.environ.get('MCP_AUTH', '0') == '1'\n",
        encoding="utf-8",
    )
    findings = _scan(
        tmp_path,
        """\
from mcp.server import Server
import uvicorn
from config import MCP_HOST
from starlette.middleware.authentication import AuthenticationMiddleware

server = Server('inventory')
app = server.streamable_http_app()
protected = AuthenticationMiddleware(app, backend=backend)
uvicorn.run(protected, host=MCP_HOST)
""",
    )
    assert findings == []


def test_pipeline_includes_low_level_mcp_exposure_check(tmp_path):
    (tmp_path / "server.py").write_text(
        _LOW_LEVEL + "uvicorn.run(starlette_app, host='0.0.0.0')\n",
        encoding="utf-8",
    )
    result = ScanPipeline(
        ScanConfig(
            target=tmp_path,
            no_taint=True,
            no_sca=True,
            no_cross_file=True,
        )
    ).run()
    assert any(finding.rule_id == "MCP-HTTP-BIND-001" for finding in result.findings)


_SETTINGS_SERVER = """\
import settings
import uvicorn
from mcp.server import Server
from mcp.server.sse import SseServerTransport

server = Server("inventory")
sse = SseServerTransport("/messages/")
app = server.streamable_http_app()
uvicorn.run(app, host=settings.HOST)
"""


def _scan_with_settings(tmp_path: Path, disable_auth_default: str):
    (tmp_path / "settings.py").write_text(
        "import os\n"
        'HOST = os.getenv("HOST", "0.0.0.0")\n'
        f'DISABLE_AUTH = os.getenv("DISABLE_AUTH", "{disable_auth_default}")\n',
        encoding="utf-8",
    )
    return [f.rule_id for f in _scan(tmp_path, _SETTINGS_SERVER)]


def test_disable_auth_false_is_not_disabled(tmp_path):
    """AZ-19: DISABLE_AUTH defaulting to "false" means auth is on."""
    assert "MCP-HTTP-BIND-001" not in _scan_with_settings(tmp_path, "false")


def test_disable_auth_true_is_disabled(tmp_path):
    assert "MCP-HTTP-BIND-001" in _scan_with_settings(tmp_path, "true")
