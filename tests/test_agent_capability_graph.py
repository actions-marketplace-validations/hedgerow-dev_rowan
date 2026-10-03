"""Registry-aware capability graph for model-selected agent tools."""

import ast

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext
from rowan.passes.cross_file import (
    CrossFilePass,
    _collect_confirmation_provenance_findings,
    _emit_cross_file_finding,
    _function_uses_principal_policy,
    _FunctionSig,
    _has_tool_feedback_loop,
)


def _scan(tmp_path, core: str, tools: str):
    (tmp_path / "tools.py").write_text(tools, encoding="utf-8")
    (tmp_path / "core.py").write_text(core, encoding="utf-8")
    ctx = ScanContext(
        target_path=tmp_path,
        config=ScanConfig(target=tmp_path),
        result=ScanResult(),
    )
    return [
        f for f in CrossFilePass().run(ctx).findings
        if f.rule_id == "AGENT-CAPABILITY-001"
    ]


def test_model_selected_registry_exposes_concrete_capabilities(tmp_path):
    tools = (
        "import requests\n\n"
        "def search(input):\n"
        "    return 'safe'\n\n"
        "def fetch(input):\n"
        "    return requests.get(input)\n\n"
        "def calculate(input):\n"
        "    return eval(input, {'__builtins__': {}}, {})\n\n"
        "TOOLS = {'search': search, 'fetch': fetch, 'calculate': calculate}\n"
    )
    core = (
        "from tools import TOOLS\n\n"
        "def run_agent(messages):\n"
        "    reply = chat(messages, tools=tool_schemas())\n"
        "    for call in reply['tool_calls']:\n"
        "        fn = TOOLS.get(call['name'])\n"
        "        if fn:\n"
        "            fn(**call.get('arguments', {}))\n"
    )

    hits = _scan(tmp_path, core, tools)
    assert len(hits) == 1
    assert hits[0].start_line == 6
    assert hits[0].metadata["capabilities"] == ["code execution", "network access"]
    assert hits[0].taint_flow is not None
    assert hits[0].taint_flow.source.line == 4


def test_safe_registry_is_not_reported(tmp_path):
    tools = (
        "def search(input):\n"
        "    return input.casefold()\n\n"
        "def calculate(input):\n"
        "    return int(input) + 1\n\n"
        "TOOLS = {'search': search, 'calculate': calculate}\n"
    )
    core = (
        "from tools import TOOLS\n\n"
        "def run_agent(messages):\n"
        "    reply = chat(messages, tools=tool_schemas())\n"
        "    call = reply['tool_calls'][0]\n"
        "    fn = TOOLS.get(call['name'])\n"
        "    return fn(**call.get('arguments', {}))\n"
    )
    assert _scan(tmp_path, core, tools) == []


def test_model_selected_dynamic_package_install_is_supply_chain_capability(tmp_path):
    tools = (
        "import subprocess\nimport sys\n\n"
        "def install_dependency(package='', input='', **_):\n"
        "    name = (package or input).strip()\n"
        "    return subprocess.run([sys.executable, '-m', 'pip', 'install', name])\n\n"
        "TOOLS = {'install_dependency': install_dependency}\n"
    )
    core = (
        "from tools import TOOLS\n\n"
        "def run_agent(messages):\n"
        "    reply = chat(messages, tools=tool_schemas())\n"
        "    call = reply['tool_calls'][0]\n"
        "    fn = TOOLS.get(call['name'])\n"
        "    return fn(**call.get('arguments', {}))\n"
    )
    hits = _scan(tmp_path, core, tools)
    assert len(hits) == 1
    assert hits[0].metadata["capabilities"] == [
        "unpinned package supply chain execution"
    ]
    assert 829 in hits[0].cwe_ids


def test_unrelated_noncall_assignments_do_not_break_package_analysis(tmp_path):
    tools = (
        "import subprocess\n\n"
        "def install_dependency(package):\n"
        "    target = '/tmp/' + package\n"
        "    return subprocess.run(['pip', 'install', package, '--target', target])\n\n"
        "TOOLS = {'install_dependency': install_dependency}\n"
    )
    core = (
        "from tools import TOOLS\n\n"
        "def run_agent(messages):\n"
        "    reply = chat(messages, tools=tool_schemas())\n"
        "    fn = TOOLS.get(reply['tool_calls'][0]['name'])\n"
        "    return fn(package=reply['tool_calls'][0]['arguments']['package'])\n"
    )
    hits = _scan(tmp_path, core, tools)
    assert hits[0].metadata["capabilities"] == [
        "unpinned package supply chain execution"
    ]


def test_reviewed_pinned_package_catalog_is_not_supply_chain_capability(tmp_path):
    tools = (
        "import subprocess\n\n"
        "PACKAGES = {'numpy': 'numpy==2.0.0'}\n\n"
        "def install_dependency(name):\n"
        "    pinned = PACKAGES.get(name)\n"
        "    if pinned is None:\n"
        "        raise ValueError('not allowed')\n"
        "    target = '/srv/plugins'\n"
        "    return subprocess.run(['pip', 'install', '--target', target, pinned])\n\n"
        "TOOLS = {'install_dependency': install_dependency}\n"
    )
    core = (
        "from tools import TOOLS\n\n"
        "def run_agent(messages):\n"
        "    reply = chat(messages, tools=tool_schemas())\n"
        "    call = reply['tool_calls'][0]\n"
        "    fn = TOOLS.get(call['name'])\n"
        "    return fn(**call.get('arguments', {}))\n"
    )
    hits = _scan(tmp_path, core, tools)
    assert len(hits) == 1
    assert hits[0].metadata["capabilities"] == ["shell execution"]


def test_constant_registry_dispatch_is_not_model_selected(tmp_path):
    tools = (
        "import requests\n\n"
        "def fetch(input):\n"
        "    return requests.get(input)\n\n"
        "TOOLS = {'fetch': fetch}\n"
    )
    core = (
        "from tools import TOOLS\n\n"
        "def run_agent(messages):\n"
        "    reply = chat(messages, tools=tool_schemas())\n"
        "    fn = TOOLS['fetch']\n"
        "    return fn('https://status.example.com')\n"
    )
    assert _scan(tmp_path, core, tools) == []


def test_untrusted_looking_parameter_without_model_call_is_not_reported(tmp_path):
    tools = (
        "import requests\n\n"
        "def fetch(input):\n"
        "    return requests.get(input)\n\n"
        "TOOLS = {'fetch': fetch}\n"
    )
    core = (
        "from tools import TOOLS\n\n"
        "def ordinary_dispatch(call):\n"
        "    fn = TOOLS.get(call['name'])\n"
        "    return fn(**call.get('arguments', {}))\n"
    )
    assert _scan(tmp_path, core, tools) == []


def test_constant_prompt_does_not_create_an_untrusted_capability_path(tmp_path):
    tools = (
        "import requests\n\n"
        "def fetch(input):\n"
        "    return requests.get(input)\n\n"
        "TOOLS = {'fetch': fetch}\n"
    )
    core = (
        "from tools import TOOLS\n\n"
        "def scheduled_agent():\n"
        "    reply = chat([{'role': 'user', 'content': 'health check'}], "
        "tools=tool_schemas())\n"
        "    call = reply['tool_calls'][0]\n"
        "    fn = TOOLS.get(call['name'])\n"
        "    return fn(**call.get('arguments', {}))\n"
    )
    assert _scan(tmp_path, core, tools) == []


def test_persisted_model_card_reaches_agent_capability_dispatch(tmp_path):
    (tmp_path / "models.py").write_text("class Model:\n    pass\n", encoding="utf-8")
    (tmp_path / "writer.py").write_text(
        "from flask import request\n"
        "from models import Model\n\n"
        "def create_model():\n"
        "    data = request.get_json()\n"
        "    return Model(model_card=data.get('model_card'))\n",
        encoding="utf-8",
    )
    tools = (
        "def run_sql(input):\n"
        "    return db.session.execute(input)\n\n"
        "TOOLS = {'run_sql': run_sql}\n"
    )
    core = (
        "from tools import TOOLS\n\n"
        "def run_agent(user_message, context_docs=None):\n"
        "    messages = []\n"
        "    for doc in context_docs or []:\n"
        "        messages.append(doc)\n"
        "    messages.append(user_message)\n"
        "    reply = chat(messages, tools=tool_schemas())\n"
        "    for call in reply['tool_calls']:\n"
        "        fn = TOOLS.get(call['name'])\n"
        "        fn(**call.get('arguments', {}))\n"
    )
    (tmp_path / "tools.py").write_text(tools, encoding="utf-8")
    (tmp_path / "core.py").write_text(core, encoding="utf-8")
    (tmp_path / "api.py").write_text(
        "from models import Model\n"
        "from core import run_agent\n\n"
        "def analyze(model_id):\n"
        "    model = db.session.get(Model, model_id)\n"
        "    docs = []\n"
        "    docs.append(model.model_card)\n"
        "    return run_agent('summarize this model', context_docs=docs)\n",
        encoding="utf-8",
    )
    ctx = ScanContext(
        target_path=tmp_path,
        config=ScanConfig(target=tmp_path),
        result=ScanResult(),
    )
    hits = [
        f for f in CrossFilePass().run(ctx).findings
        if f.rule_id == "AGENT-CAPABILITY-002" and f.metadata["indirect_context"]
    ]
    assert len(hits) == 1
    assert hits[0].start_line == 8
    assert hits[0].metadata["callee_name"] == "run_agent"
    assert hits[0].metadata["tool_feedback_loop"] is False


def test_unpersisted_model_field_does_not_arm_indirect_context(tmp_path):
    (tmp_path / "models.py").write_text("class Model:\n    pass\n", encoding="utf-8")
    (tmp_path / "tools.py").write_text(
        "def run_sql(input):\n"
        "    return db.session.execute(input)\n\n"
        "TOOLS = {'run_sql': run_sql}\n",
        encoding="utf-8",
    )
    (tmp_path / "core.py").write_text(
        "from tools import TOOLS\n\n"
        "def run_agent(user_message, context_docs=None):\n"
        "    messages = list(context_docs or [])\n"
        "    messages.append(user_message)\n"
        "    reply = chat(messages, tools=tool_schemas())\n"
        "    call = reply['tool_calls'][0]\n"
        "    fn = TOOLS.get(call['name'])\n"
        "    return fn(**call.get('arguments', {}))\n",
        encoding="utf-8",
    )
    (tmp_path / "api.py").write_text(
        "from models import Model\n"
        "from core import run_agent\n\n"
        "def analyze(model_id):\n"
        "    model = db.session.get(Model, model_id)\n"
        "    return run_agent('summarize', context_docs=[model.description])\n",
        encoding="utf-8",
    )
    ctx = ScanContext(
        target_path=tmp_path,
        config=ScanConfig(target=tmp_path),
        result=ScanResult(),
    )
    assert not [
        f for f in CrossFilePass().run(ctx).findings
        if f.rule_id == "AGENT-CAPABILITY-002" and f.metadata["indirect_context"]
    ]


def test_tool_result_feedback_inside_model_loop_is_recognized():
    func = ast.parse(
        "def run(messages):\n"
        "    for _ in range(3):\n"
        "        reply = chat(messages, tools=schemas)\n"
        "        fn = TOOLS.get(reply['name'])\n"
        "        result = fn(**reply['arguments'])\n"
        "        messages.append(str(result))\n"
    ).body[0]
    assert _has_tool_feedback_loop(func, {"fn"}) is True


def test_tool_result_not_returned_to_model_is_not_a_feedback_loop():
    func = ast.parse(
        "def run(messages):\n"
        "    reply = chat(messages, tools=schemas)\n"
        "    fn = TOOLS.get(reply['name'])\n"
        "    result = fn(**reply['arguments'])\n"
        "    return result\n"
    ).body[0]
    assert _has_tool_feedback_loop(func, {"fn"}) is False


def test_confirmation_marker_in_agent_transcript_is_spoofable(tmp_path):
    path = tmp_path / "core.py"
    tree = ast.parse(
        "CONFIRMATION_MARKER = '[user confirmed]'\n\n"
        "def run_agent_guarded(messages):\n"
        "    return _run_guarded_loop(\n"
        "        messages,\n"
        "        lambda msgs: CONFIRMATION_MARKER in conversation_text(msgs),\n"
        "    )\n"
    )
    findings = _collect_confirmation_provenance_findings([(str(path), tree)])
    assert len(findings) == 1
    assert findings[0].rule_id == "AGENT-CONFIRMATION-001"
    assert findings[0].start_line == 6


def test_out_of_band_boolean_confirmation_is_trusted_state(tmp_path):
    path = tmp_path / "core.py"
    tree = ast.parse(
        "def run_agent_with_signal(messages, confirmed: bool):\n"
        "    return _run_guarded_loop(messages, lambda _: bool(confirmed))\n"
    )
    assert _collect_confirmation_provenance_findings([(str(path), tree)]) == []


def test_confirmation_status_on_application_record_is_not_transcript_text(tmp_path):
    path = tmp_path / "approval.py"
    tree = ast.parse(
        "def approve_tool_call(approval):\n"
        "    if approval.status == 'confirmed':\n"
        "        execute_tool()\n"
    )
    assert _collect_confirmation_provenance_findings([(str(path), tree)]) == []


def test_authenticated_agent_call_without_principal_context_has_ambient_authority():
    caller = _FunctionSig(
        "chat", "/app/api.py", 10, [], [], has_source=True,
        authenticated_boundary=True,
    )
    callee = _FunctionSig(
        "run_agent", "/app/core.py", 20, ["user_message"], [],
        has_sink=True, agent_capability_sink=True,
        sink_detail="Model-selected registry exposes filesystem access.",
        sink_line=25,
    )
    findings = []
    _emit_cross_file_finding(
        findings, set(), caller, callee, (callee.file, callee.name), 0, "sink"
    )
    assert findings[0].metadata["ambient_authority"] is True
    assert "server process's broader authority" in findings[0].message


def test_unused_principal_parameter_does_not_prove_agent_authorization():
    caller = _FunctionSig(
        "chat", "/app/api.py", 10, [], [], has_source=True,
        authenticated_boundary=True,
    )
    callee = _FunctionSig(
        "run_agent", "/app/core.py", 20, ["user_message", "user_id"], [],
        has_sink=True, agent_capability_sink=True,
        sink_detail="Model-selected registry exposes filesystem access.",
        sink_line=25,
    )
    findings = []
    _emit_cross_file_finding(
        findings, set(), caller, callee, (callee.file, callee.name), 0, "sink"
    )
    assert findings[0].metadata["ambient_authority"] is True


def test_agent_executor_with_principal_policy_check_is_not_ambient_authority():
    caller = _FunctionSig(
        "chat", "/app/api.py", 10, [], [], has_source=True,
        authenticated_boundary=True,
    )
    callee = _FunctionSig(
        "run_agent", "/app/core.py", 20, ["user_message", "user_id"], [],
        has_sink=True, agent_capability_sink=True,
        principal_policy_used=True,
        sink_detail="Model-selected registry exposes filesystem access.",
        sink_line=25,
    )
    findings = []
    _emit_cross_file_finding(
        findings, set(), caller, callee, (callee.file, callee.name), 0, "sink"
    )
    assert findings[0].metadata["ambient_authority"] is False


def test_principal_must_feed_a_policy_decision():
    unused = ast.parse(
        "def run_agent(message, user_id):\n"
        "    logger.info(user_id)\n"
        "    return dispatch(message)\n"
    ).body[0]
    checked = ast.parse(
        "def run_agent(message, user_id):\n"
        "    authorize_tool_call(user_id, message)\n"
        "    return dispatch(message)\n"
    ).body[0]
    assert _function_uses_principal_policy(unused) is False
    assert _function_uses_principal_policy(checked) is True
