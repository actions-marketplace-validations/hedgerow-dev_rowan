"""Sandbox and code-interpreter escape configuration (issue #189, epic #183).

`NS-AIML-010`/`NS-AIML-011` flag that an agent code-execution tool *exists*
as a bare presence signal. Neither inspects the sandbox that is supposed to
contain it -- an agent with a code interpreter running in a locked-down
microVM and one running `subprocess.run(shell=True)` directly on the host
got the exact same finding. This file covers the six configuration-weakness
categories that make that distinction visible:

  ns-aiml-163  escape-grade Docker config (privileged, docker.sock, host net/pid)
  ns-aiml-164  hosted sandbox (E2B/Modal) with no visible network restriction or timeout
  ns-aiml-165  sandbox inherits the full host environment or cloud credentials
  ns-aiml-166  exec() "sandboxed" via a trivial/empty globals dict
  ns-aiml-167  host root/home directory bind-mounted into a sandbox
  ns-aiml-168  agent code-execution tool with no recognized sandbox anywhere
               nearby -- the confirmatory escalation of NS-AIML-010/011

Also covers the `TNT-INJECT-003` `RestrictedPython` sanitizer fix
(`rules/python_taint_extended.yaml`): the bare word was a DEF-43-shaped
dead sanitizer -- verified it never suppressed anything under any tested
shape, including the exact code a real, correct RestrictedPython usage
would produce -- replaced with the actual `compile_restricted(...)` API
call.

Scope note (also in each new rule's own message, per the issue's own
instruction): these detect sandbox CONFIGURATION weaknesses visible in
source. They do not verify a sandbox is actually enforcing at runtime --
that is a different product's job.

Every new rule is tested on both scan engines: the legacy per-line
NeuroScan matcher, and the real Opengrep binary against the converted
rules -- the actual default-scan path (`ScanConfig.legacy_neuroscan`
defaults to `False`). See DEF-45 in BACKLOG.md for why a bare unanchored
sanitizer term does not suppress anything in the converted engine and an
anchored forward-span `pattern-not` is required instead.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.core.rules import load_neuroscan_rules
from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_PATH = Path(__file__).parent.parent / "rules" / "ai_security.yaml"
CONVERTED_RULES_PATH = Path(__file__).parent.parent / "rules" / "converted" / "ai_security.yaml"
TAINT_RULES_PATH = Path(__file__).parent.parent / "rules" / "python_taint_extended.yaml"
_NEUROSCAN_RULES = load_neuroscan_rules(RULES_PATH)

_adapter = OpengrepAdapter()
_needs_opengrep = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _legacy_scan(tmp_path: Path, filename: str, source: str, rule_id: str) -> list:
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    rule = next(r for r in _NEUROSCAN_RULES if r.metadata.id == rule_id)
    return rule.check(fp)


def _converted_scan(tmp_path: Path, filename: str, source: str, rule_id: str, lang="python") -> list:
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(tmp_path, [CONVERTED_RULES_PATH], languages=[lang])
    return [f for f in findings if f.rule_id == rule_id and Path(f.file_path).name == filename]


def _both_engines(tmp_path: Path, filename: str, source: str, rule_id: str, lang="python") -> tuple[list, list]:
    return (
        _legacy_scan(tmp_path, filename, source, rule_id),
        _converted_scan(tmp_path, filename, source, rule_id, lang),
    )


# ---------------------------------------------------------------------------
# ns-aiml-163: escape-grade Docker config
# ---------------------------------------------------------------------------


class TestNsAiml140DockerEscape:
    def test_privileged_true_flagged(self, tmp_path):
        src = (
            "import docker\n"
            "client = docker.from_env()\n"
            'client.containers.run("agent-sandbox:latest", command="run.py", privileged=True)\n'
        )
        legacy, converted = _both_engines(tmp_path, "run.py", src, "ns-aiml-163")
        assert legacy and converted

    def test_docker_socket_bind_flagged(self, tmp_path):
        src = (
            "import docker\n"
            "client = docker.from_env()\n"
            "client.containers.run(\n"
            '    "agent-sandbox:latest",\n'
            '    volumes={"/var/run/docker.sock": {"bind": "/var/run/docker.sock", "mode": "rw"}},\n'
            ")\n"
        )
        legacy, converted = _both_engines(tmp_path, "run.py", src, "ns-aiml-163")
        assert legacy and converted

    def test_compose_privileged_flagged(self, tmp_path):
        src = (
            "services:\n"
            "  agent-sandbox:\n"
            "    image: agent-sandbox:latest\n"
            "    privileged: true\n"
        )
        legacy, converted = _both_engines(tmp_path, "docker-compose.yaml", src, "ns-aiml-163", "yaml")
        assert legacy and converted

    def test_rootless_no_socket_not_flagged(self, tmp_path):
        """TN (issue's own acceptance criterion): a rootless container with
        no socket mount."""
        src = (
            "import docker\n"
            "client = docker.from_env()\n"
            'client.containers.run("agent-sandbox:latest", network_disabled=True, read_only=True)\n'
        )
        legacy, converted = _both_engines(tmp_path, "run.py", src, "ns-aiml-163")
        assert not legacy and not converted


# ---------------------------------------------------------------------------
# ns-aiml-164: hosted sandbox network/timeout
# ---------------------------------------------------------------------------


class TestNsAiml141HostedSandboxOpen:
    def test_e2b_no_restriction_flagged(self, tmp_path):
        src = (
            "from e2b_code_interpreter import Sandbox\n\n"
            "sbx = Sandbox()\n"
            "result = sbx.run_code(agent_generated_code)\n"
        )
        legacy, converted = _both_engines(tmp_path, "run.py", src, "ns-aiml-164")
        assert legacy and converted

    def test_modal_no_restriction_flagged(self, tmp_path):
        src = (
            "import modal\n\n"
            "sbx = modal.Sandbox.create(app=app, image=image)\n"
            'sbx.exec("python", "run.py")\n'
        )
        legacy, converted = _both_engines(tmp_path, "run.py", src, "ns-aiml-164")
        assert legacy and converted

    def test_e2b_configured_not_flagged(self, tmp_path):
        """TN (issue's own acceptance criterion): a correctly configured
        E2B sandbox -- network off, timeout set."""
        src = (
            "from e2b_code_interpreter import Sandbox\n\n"
            "sbx = Sandbox(timeout=30, allow_internet=False)\n"
            "result = sbx.run_code(agent_generated_code)\n"
        )
        legacy, converted = _both_engines(tmp_path, "run.py", src, "ns-aiml-164")
        assert not legacy and not converted

    @_needs_opengrep
    def test_def46_unrestricted_with_adjacent_restricted_sibling_still_flagged(self, tmp_path):
        """DEF-46 (found via issue #197's benchmark work, first caught on
        #187's ns-aiml-133): the anchored-span pattern-not this rule uses
        (see #187/DEF-45) has no notion of a function boundary on its own --
        an unrestricted Sandbox() in one function sitting close to a
        restricted one in the very next function let the second function's
        own allow_internet=/timeout= terms leak backward across the def
        line and suppress the first function's genuine finding."""
        src = (
            "from e2b_code_interpreter import Sandbox\n\n"
            "def start_unrestricted_sandbox():\n"
            "    sbx = Sandbox()\n"
            "    return sbx\n\n"
            "def start_restricted_sandbox():\n"
            "    sbx = Sandbox(timeout=30, allow_internet=False)\n"
            "    return sbx\n"
        )
        findings = _converted_scan(tmp_path, "sandboxes.py", src, "ns-aiml-164")
        assert findings, "the unrestricted Sandbox() must still be flagged despite the restricted sibling nearby"
        assert findings[0].start_line == 4, "the finding must land on start_unrestricted_sandbox, not its sibling"


# ---------------------------------------------------------------------------
# ns-aiml-165: credential inheritance
# ---------------------------------------------------------------------------


class TestNsAiml142CredentialInheritance:
    def test_full_environ_passthrough_flagged(self, tmp_path):
        src = (
            "from e2b_code_interpreter import Sandbox\n"
            "import os\n\n"
            "sbx = Sandbox(envs=os.environ)\n"
            "sbx.run_code(agent_generated_code)\n"
        )
        legacy, converted = _both_engines(tmp_path, "run.py", src, "ns-aiml-165")
        assert legacy and converted

    def test_aws_credential_mount_flagged(self, tmp_path):
        src = (
            "import docker\n"
            "client = docker.from_env()\n"
            "client.containers.run(\n"
            '    "agent-sandbox:latest",\n'
            '    volumes={"/home/user/.aws": {"bind": "/root/.aws", "mode": "ro"}},\n'
            ")\n"
        )
        legacy, converted = _both_engines(tmp_path, "run.py", src, "ns-aiml-165")
        assert legacy and converted

    def test_scoped_env_dict_not_flagged(self, tmp_path):
        """TN: a scoped env dict, not the full host environment."""
        src = (
            "from e2b_code_interpreter import Sandbox\n\n"
            'sbx = Sandbox(envs={"TASK_ID": task_id})\n'
            "sbx.run_code(agent_generated_code)\n"
        )
        legacy, converted = _both_engines(tmp_path, "run.py", src, "ns-aiml-165")
        assert not legacy and not converted

    def test_python_type_annotation_not_flagged(self, tmp_path):
        """Regression: a Python type-annotated function parameter
        (`env_file: str = None,`) shares the same `env_file:` colon syntax
        as compose's directive -- found scanning scan-targets/autogen's own
        agbench/run_cmd.py during development."""
        src = (
            "def run_scenario(\n"
            "    docker_image,\n"
            "    env_file: str = None,\n"
            ") -> None:\n"
            "    pass\n"
        )
        legacy, converted = _both_engines(tmp_path, "run_cmd.py", src, "ns-aiml-165")
        assert not legacy and not converted

    def test_unrelated_env_variable_copy_not_flagged(self, tmp_path):
        """Regression: `env = os.environ.copy()` is an ordinary local
        variable copy, not a sandbox's `envs=` kwarg -- found scanning
        scan-targets/crewai's own tool_credentials.py during development."""
        src = (
            "import os\n\n"
            "def build_env():\n"
            "    env = os.environ.copy()\n"
            "    return env\n"
        )
        legacy, converted = _both_engines(tmp_path, "creds.py", src, "ns-aiml-165")
        assert not legacy and not converted

    def test_uvicorn_env_file_kwarg_not_flagged(self, tmp_path):
        """Regression: uvicorn's own `env_file=` reload-watch parameter --
        found scanning scan-targets/autogen's own autogenstudio/cli.py."""
        src = "uvicorn.run(app, reload=True, env_file=env_file_path)\n"
        legacy, converted = _both_engines(tmp_path, "cli.py", src, "ns-aiml-165")
        assert not legacy and not converted


# ---------------------------------------------------------------------------
# ns-aiml-166: fake in-process sandbox (empty globals dict)
# ---------------------------------------------------------------------------


class TestNsAiml143FakeInProcessSandbox:
    def test_exec_empty_globals_flagged(self, tmp_path):
        src = (
            "from flask import request\n\n"
            "def handler():\n"
            "    code = request.json.get('code')\n"
            "    exec(code, {})\n"
        )
        legacy, converted = _both_engines(tmp_path, "handler.py", src, "ns-aiml-166")
        assert legacy and converted

    def test_exec_empty_globals_and_locals_flagged(self, tmp_path):
        src = (
            "from flask import request\n\n"
            "def handler():\n"
            "    code = request.json.get('code')\n"
            "    exec(code, {}, {})\n"
        )
        legacy, converted = _both_engines(tmp_path, "handler.py", src, "ns-aiml-166")
        assert legacy and converted

    def test_named_restricted_globals_not_flagged(self, tmp_path):
        """TN: a named globals dict is outside this narrow rule's scope --
        it targets the specific `exec(code, {})` literal-empty-dict
        misconception, not every exec() call."""
        src = (
            "from flask import request\n\n"
            'SAFE_GLOBALS = {"__builtins__": {}}\n\n'
            "def handler():\n"
            "    code = request.json.get('code')\n"
            "    exec(code, SAFE_GLOBALS)\n"
        )
        legacy, converted = _both_engines(tmp_path, "handler.py", src, "ns-aiml-166")
        assert not legacy and not converted


# ---------------------------------------------------------------------------
# ns-aiml-167: sandbox filesystem scope
# ---------------------------------------------------------------------------


class TestNsAiml144FilesystemScope:
    def test_root_mount_flagged(self, tmp_path):
        src = (
            "import docker\n"
            "client = docker.from_env()\n"
            "client.containers.run(\n"
            '    "agent-sandbox:latest",\n'
            '    volumes={"/": {"bind": "/host", "mode": "rw"}},\n'
            ")\n"
        )
        legacy, converted = _both_engines(tmp_path, "run.py", src, "ns-aiml-167")
        assert legacy and converted

    def test_home_mount_flagged(self, tmp_path):
        src = (
            "import docker\n"
            "client = docker.from_env()\n"
            "client.containers.run(\n"
            '    "agent-sandbox:latest",\n'
            '    volumes={"~": {"bind": "/host-home", "mode": "rw"}},\n'
            ")\n"
        )
        legacy, converted = _both_engines(tmp_path, "run.py", src, "ns-aiml-167")
        assert legacy and converted

    def test_compose_root_mount_flagged(self, tmp_path):
        src = "services:\n  agent-sandbox:\n    volumes:\n      - /:/host\n"
        legacy, converted = _both_engines(tmp_path, "docker-compose.yaml", src, "ns-aiml-167", "yaml")
        assert legacy and converted

    def test_scoped_workspace_mount_not_flagged(self, tmp_path):
        src = (
            "import docker\n"
            "client = docker.from_env()\n"
            "client.containers.run(\n"
            '    "agent-sandbox:latest",\n'
            '    volumes={"/home/user/project/workspace": {"bind": "/workspace", "mode": "rw"}},\n'
            ")\n"
        )
        legacy, converted = _both_engines(tmp_path, "run.py", src, "ns-aiml-167")
        assert not legacy and not converted


# ---------------------------------------------------------------------------
# ns-aiml-168: no sandbox at all (escalates NS-AIML-010/011)
# ---------------------------------------------------------------------------


class TestNsAiml145NoSandboxAtAll:
    def test_unsandboxed_shell_tool_flagged(self, tmp_path):
        src = (
            "import subprocess\n"
            "from crewai.tools import tool\n\n"
            '@tool("RunCommand")\n'
            "def run_command(cmd: str) -> str:\n"
            "    return subprocess.run(cmd, shell=True).stdout\n"
        )
        legacy, converted = _both_engines(tmp_path, "tools.py", src, "ns-aiml-168")
        assert legacy and converted

    @_needs_opengrep
    def test_unsandboxed_exec_tool_flagged_by_default_engine(self, tmp_path):
        """The decorator-to-exec multi-line span only works in the
        converted (default) engine -- the legacy per-line matcher cannot
        span the decorator line and the exec() call on a different line.
        Documented engine limitation, not a bug."""
        src = (
            'from crewai.tools import tool\n\n@tool("RunCode")\ndef run_code(code: str) -> str:\n    exec(code)\n'
        )
        converted = _converted_scan(tmp_path, "tools.py", src, "ns-aiml-168")
        assert converted

    def test_e2b_sandboxed_tool_not_flagged(self, tmp_path):
        src = (
            "from crewai.tools import tool\n"
            "from e2b_code_interpreter import Sandbox\n\n"
            '@tool("RunCode")\n'
            "def run_code(code: str) -> str:\n"
            "    sbx = Sandbox()\n"
            "    return sbx.run_code(code)\n"
        )
        legacy, converted = _both_engines(tmp_path, "tools.py", src, "ns-aiml-168")
        assert not legacy and not converted

    def test_docker_sandboxed_tool_not_flagged(self, tmp_path):
        src = (
            "import subprocess\n"
            "from crewai.tools import tool\n\n"
            '@tool("RunCommand")\n'
            "def run_command(cmd: str) -> str:\n"
            '    return subprocess.run(["docker", "run", "--rm", "sandboxed-runner", cmd], '
            "capture_output=True).stdout\n"
        )
        legacy, converted = _both_engines(tmp_path, "tools.py", src, "ns-aiml-168")
        assert not legacy and not converted


# ---------------------------------------------------------------------------
# TNT-INJECT-003: RestrictedPython sanitizer fix
# ---------------------------------------------------------------------------


@_needs_opengrep
class TestRestrictedPythonSanitizerFix:
    """DEF-43-shaped bug: the bare word `RestrictedPython` was a taint
    sanitizer with zero connection to the actual exec() call it was meant
    to guard -- verified it never suppressed anything under any tested
    shape, including a real, correctly-implemented compile_restricted()
    usage."""

    def _scan(self, tmp_path, source):
        fp = tmp_path / "handler.py"
        fp.write_text(source, encoding="utf-8")
        adapter = OpengrepAdapter()
        findings = adapter.scan_with_rules(tmp_path, [TAINT_RULES_PATH], languages=["python"])
        return [f for f in findings if f.rule_id == "TNT-INJECT-003"]

    def test_bare_import_no_real_sandboxing_flagged(self, tmp_path):
        src = (
            "import json\n"
            "import RestrictedPython\n"
            "from flask import request\n\n"
            "def handler():\n"
            "    data = json.loads(request.get_json())\n"
            "    exec(data)\n"
        )
        assert self._scan(tmp_path, src), (
            "importing RestrictedPython without calling compile_restricted() "
            "provides no protection at all and must still be flagged"
        )

    def test_real_compile_restricted_not_flagged(self, tmp_path):
        src = (
            "import json\n"
            "from RestrictedPython import compile_restricted\n"
            "from flask import request\n\n"
            "def handler():\n"
            "    data = json.loads(request.get_json())\n"
            "    byte_code = compile_restricted(data, '<inline>', 'exec')\n"
            "    exec(byte_code, {'__builtins__': {}}, {})\n"
        )
        assert not self._scan(tmp_path, src), (
            "a genuine compile_restricted() call must suppress -- this was "
            "the actual bug: the bare-word sanitizer never suppressed this "
            "either, identically to the unsandboxed case above"
        )

    def test_ast_literal_eval_still_suppresses(self, tmp_path):
        """Control: the other, genuinely call-shaped sanitizer must be
        unaffected by this fix."""
        src = (
            "import ast, json\n"
            "from flask import request\n\n"
            "def handler():\n"
            "    data = json.loads(request.get_json())\n"
            "    parsed = ast.literal_eval(data)\n"
            "    exec(parsed)\n"
        )
        assert not self._scan(tmp_path, src)


# ---------------------------------------------------------------------------
# Clean-corpus baseline
# ---------------------------------------------------------------------------


@_needs_opengrep
class TestCleanCorpusBaseline:
    """No new findings on the clean-corpus baseline. Checked against both
    scan-targets/autogen and scan-targets/crewai -- the extra crewai check
    (beyond what this issue required) is what caught the env_file/type-
    annotation and envs=/env= collisions fixed above before shipping."""

    _NEW_IDS = frozenset({
        "ns-aiml-163", "ns-aiml-164", "ns-aiml-165",
        "ns-aiml-166", "ns-aiml-167", "ns-aiml-168",
    })

    @pytest.mark.corpus
    @pytest.mark.parametrize("target", ["autogen", "crewai"])
    def test_baseline_matches_ns_aiml_010_011(self, target):
        """The escalation rule (ns-aiml-168) must not be noisier than the
        rule it escalates -- NS-AIML-010/011's own presence-signal baseline
        is the ceiling, not a new, looser one."""
        base = Path(__file__).parent.parent / "scan-targets" / target
        if not base.is_dir():
            pytest.skip(f"scan-targets/{target} not present in this checkout")
        adapter = OpengrepAdapter()
        new_hits = adapter.scan_with_rules(
            base, [CONVERTED_RULES_PATH], languages=["python", "yaml"]
        )
        new_count = sum(1 for f in new_hits if f.rule_id in self._NEW_IDS)

        neuroscan_path = Path(__file__).parent.parent / "rules" / "ai_ml_neuroscan.yaml"
        neuroscan_converted = Path(__file__).parent.parent / "rules" / "converted" / "ai_ml_neuroscan.yaml"
        baseline_hits = adapter.scan_with_rules(
            base, [neuroscan_converted if neuroscan_converted.exists() else neuroscan_path],
            languages=["python"],
        )
        baseline_count = sum(1 for f in baseline_hits if f.rule_id in ("NS-AIML-010", "NS-AIML-011"))

        assert new_count <= baseline_count * 3, (
            f"new rules produced {new_count} hits on {target} vs. "
            f"NS-AIML-010/011's own {baseline_count} -- disproportionate "
            f"noise for what is meant to be a same-evidence escalation"
        )
