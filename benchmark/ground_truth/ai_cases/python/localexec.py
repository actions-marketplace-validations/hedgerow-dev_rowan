"""smolagents CodeAgent with a local executor and os/subprocess authorised (tnt-py-ai-localexec-001, CWE-94)."""

from smolagents import CodeAgent, LiteLLMModel

agent = CodeAgent(
    tools=[],
    model=LiteLLMModel(model_id="openai/gpt-4o"),
    executor_type="local",
    additional_authorized_imports=["os", "subprocess"],
)


def analyse(task: str) -> str:
    return str(agent.run(task))
