"""LangFail: cross-agent injection propagation across agent frameworks
beyond CrewAI (AGENT-HANDOFF-001, MultiAgentPass).

Each framework contributes nodes + directed handoff edges to one unified
graph; the finding fires when an armed source (reads a request/CLI value or
holds a web-scraping tool) hands off to a privileged receiver (code / shell /
filesystem-write tool) with no output-schema gate. These tests exercise the
per-framework extractors added on top of the CrewAI original.
"""

from __future__ import annotations

import ast
from pathlib import Path

from rowan.passes.multiagent import MultiAgentPass


def _scan(source: str, tmp_path: Path) -> list:
    fp = tmp_path / "agents_app.py"
    fp.write_text(source, encoding="utf-8")
    return MultiAgentPass()._scan_tree(fp, ast.parse(source))


class TestOpenAIAgentsSDK:
    _IMPORTS = "from flask import request\nfrom agents import Agent, handoff\nfrom crewai_tools import CodeInterpreterTool\n\n"

    def test_armed_triage_handoff_to_privileged_agent_flagged(self, tmp_path):
        src = self._IMPORTS + (
            "executor = Agent(name='e', tools=[CodeInterpreterTool()])\n"
            "triage = Agent(name='t', instructions=request.args.get('q'), handoffs=[executor])\n"
        )
        findings = _scan(src, tmp_path)
        assert len(findings) == 1
        assert findings[0].rule_id == "AGENT-HANDOFF-001"
        assert findings[0].metadata["framework"] == "openai_agents"

    def test_handoff_helper_wrapper_flagged(self, tmp_path):
        src = self._IMPORTS + (
            "executor = Agent(name='e', tools=[CodeInterpreterTool()])\n"
            "triage = Agent(name='t', instructions=request.args.get('q'), handoffs=[handoff(executor)])\n"
        )
        assert len(_scan(src, tmp_path)) == 1

    def test_output_type_schema_gate_not_flagged(self, tmp_path):
        src = self._IMPORTS + (
            "class Plan(BaseModel):\n    step: str\n\n"
            "executor = Agent(name='e', tools=[CodeInterpreterTool()])\n"
            "triage = Agent(name='t', instructions=request.args.get('q'), handoffs=[executor], output_type=Plan)\n"
        )
        assert _scan(src, tmp_path) == []

    def test_non_privileged_receiver_not_flagged(self, tmp_path):
        src = self._IMPORTS + (
            "summarizer = Agent(name='s', tools=[])\n"
            "triage = Agent(name='t', instructions=request.args.get('q'), handoffs=[summarizer])\n"
        )
        assert _scan(src, tmp_path) == []

    def test_no_untrusted_source_not_flagged(self, tmp_path):
        src = self._IMPORTS + (
            "executor = Agent(name='e', tools=[CodeInterpreterTool()])\n"
            "triage = Agent(name='t', instructions='be helpful', handoffs=[executor])\n"
        )
        assert _scan(src, tmp_path) == []


class TestGoogleADK:
    _IMPORTS = "from flask import request\nfrom google.adk.agents import LlmAgent\nfrom crewai_tools import CodeInterpreterTool\n\n"

    def test_armed_root_delegates_to_privileged_sub_agent_flagged(self, tmp_path):
        src = self._IMPORTS + (
            "executor = LlmAgent(name='e', tools=[CodeInterpreterTool()])\n"
            "root = LlmAgent(name='r', instruction=request.args.get('q'), sub_agents=[executor])\n"
        )
        findings = _scan(src, tmp_path)
        assert len(findings) == 1
        assert findings[0].metadata["framework"] == "google_adk"

    def test_output_schema_gate_not_flagged(self, tmp_path):
        src = self._IMPORTS + (
            "executor = LlmAgent(name='e', tools=[CodeInterpreterTool()])\n"
            "root = LlmAgent(name='r', instruction=request.args.get('q'), sub_agents=[executor], output_schema=Plan)\n"
        )
        assert _scan(src, tmp_path) == []


class TestLangGraph:
    _IMPORTS = "from flask import request\nfrom langgraph.graph import StateGraph, START, END\nimport subprocess\n\n"

    def test_armed_node_edge_to_privileged_node_flagged(self, tmp_path):
        src = self._IMPORTS + (
            "def researcher(state):\n"
            "    state['q'] = request.args.get('q')\n"
            "    return state\n\n"
            "def executor(state):\n"
            "    subprocess.run(state['q'], shell=True)\n"
            "    return state\n\n"
            "g = StateGraph(dict)\n"
            "g.add_node('researcher', researcher)\n"
            "g.add_node('executor', executor)\n"
            "g.add_edge('researcher', 'executor')\n"
        )
        findings = _scan(src, tmp_path)
        assert len(findings) == 1
        assert findings[0].metadata["framework"] == "langgraph"

    def test_command_goto_edge_flagged(self, tmp_path):
        src = self._IMPORTS + (
            "from langgraph.types import Command\n\n"
            "def router(state):\n"
            "    q = request.args.get('q')\n"
            "    return Command(goto='executor', update={'q': q})\n\n"
            "def executor(state):\n"
            "    subprocess.run(state['q'], shell=True)\n"
            "    return state\n\n"
            "g = StateGraph(dict)\n"
            "g.add_node('router', router)\n"
            "g.add_node('executor', executor)\n"
        )
        assert len(_scan(src, tmp_path)) == 1

    def test_privileged_but_no_armed_source_not_flagged(self, tmp_path):
        src = self._IMPORTS + (
            "def planner(state):\n"
            "    state['plan'] = 'fixed'\n"
            "    return state\n\n"
            "def executor(state):\n"
            "    subprocess.run(['ls'])\n"
            "    return state\n\n"
            "g = StateGraph(dict)\n"
            "g.add_node('planner', planner)\n"
            "g.add_node('executor', executor)\n"
            "g.add_edge('planner', 'executor')\n"
        )
        assert _scan(src, tmp_path) == []

    def test_armed_but_receiver_not_privileged_not_flagged(self, tmp_path):
        src = self._IMPORTS + (
            "def researcher(state):\n"
            "    state['q'] = request.args.get('q')\n"
            "    return state\n\n"
            "def summarizer(state):\n"
            "    return {'summary': state['q'][:10]}\n\n"
            "g = StateGraph(dict)\n"
            "g.add_node('researcher', researcher)\n"
            "g.add_node('summarizer', summarizer)\n"
            "g.add_edge('researcher', 'summarizer')\n"
        )
        assert _scan(src, tmp_path) == []


class TestAutoGen:
    _IMPORTS = "from flask import request\nfrom autogen import AssistantAgent, UserProxyAgent\n\n"

    def test_armed_assistant_initiates_to_code_exec_proxy_flagged(self, tmp_path):
        src = self._IMPORTS + (
            "assistant = AssistantAgent(name='a', system_message=request.args.get('task'))\n"
            "user = UserProxyAgent(name='u', code_execution_config={'work_dir': 'coding'})\n"
            "assistant.initiate_chat(user, message='go')\n"
        )
        findings = _scan(src, tmp_path)
        assert len(findings) == 1
        assert findings[0].metadata["framework"] == "autogen"

    def test_code_execution_disabled_not_flagged(self, tmp_path):
        src = self._IMPORTS + (
            "assistant = AssistantAgent(name='a', system_message=request.args.get('task'))\n"
            "user = UserProxyAgent(name='u', code_execution_config=False)\n"
            "assistant.initiate_chat(user, message='go')\n"
        )
        assert _scan(src, tmp_path) == []

    def test_no_armed_source_not_flagged(self, tmp_path):
        src = self._IMPORTS + (
            "assistant = AssistantAgent(name='a', system_message='be helpful')\n"
            "user = UserProxyAgent(name='u', code_execution_config={'work_dir': 'coding'})\n"
            "assistant.initiate_chat(user, message='go')\n"
        )
        assert _scan(src, tmp_path) == []


class TestAutoGenAgentChat:
    """AZ-16: the 0.4+ `autogen_agentchat` API wires agents through teams."""

    _IMPORTS = (
        "import sys\n"
        "from autogen_agentchat.agents import AssistantAgent, CodeExecutorAgent\n"
        "from autogen_agentchat.teams import RoundRobinGroupChat\n\n"
    )

    def test_autogen_agentchat_round_robin_handoff(self, tmp_path):
        src = self._IMPORTS + (
            "planner = AssistantAgent('planner', model_client=m, system_message=sys.argv[1])\n"
            "executor = CodeExecutorAgent('executor', code_executor=LocalCommandLineCodeExecutor())\n"
            "team = RoundRobinGroupChat([planner, executor])\n"
        )
        findings = _scan(src, tmp_path)
        assert [f.start_line for f in findings] == [6]

    def test_participants_kwarg_is_read(self, tmp_path):
        src = self._IMPORTS + (
            "planner = AssistantAgent('planner', model_client=m, system_message=sys.argv[1])\n"
            "executor = CodeExecutorAgent('executor', code_executor=LocalCommandLineCodeExecutor())\n"
            "team = SelectorGroupChat(participants=[planner, executor], model_client=m)\n"
        )
        assert len(_scan(src, tmp_path)) == 1

    def test_team_without_code_executor_not_flagged(self, tmp_path):
        src = self._IMPORTS + (
            "planner = AssistantAgent('planner', model_client=m, system_message=sys.argv[1])\n"
            "writer = AssistantAgent('writer', model_client=m)\n"
            "team = RoundRobinGroupChat([planner, writer])\n"
        )
        assert _scan(src, tmp_path) == []
