"""Data-analysis agents on smolagents."""

from __future__ import annotations

from smolagents import CodeAgent, LiteLLMModel
from smolagents.local_python_executor import LocalPythonExecutor

model = LiteLLMModel(model_id="openai/gpt-4o")

analysis_agent = CodeAgent(
    tools=[],
    model=model,
    executor_type="local",
    additional_authorized_imports=["os", "subprocess", "pandas"],
)


def analyse(task: str) -> str:
    return str(analysis_agent.run(task))


def build_sandboxed_agent() -> CodeAgent:
    return CodeAgent(
        tools=[],
        model=model,
        executor_type="e2b",
        additional_authorized_imports=["pandas"],
    )


def analyse_sandboxed(task: str) -> str:
    return str(build_sandboxed_agent().run(task))


def run_snippet(code: str) -> str:
    """Execute a model-written snippet directly, outside the agent loop."""
    executor = LocalPythonExecutor(additional_authorized_imports=["os", "subprocess"])
    executor.send_tools({})
    output = executor(code)
    return str(output.output)
