"""Reduced source snapshot: langchain-core==1.2.21 prompts/loading.py, 19f81cf6.

The three config-derived path reads below preserve the relevant upstream
control flow. Other prompt construction and format handling are omitted.
"""

# ruff: noqa: F821 -- unrelated upstream helpers are omitted from this static fixture

from pathlib import Path


def _load_template(var_name: str, config: dict) -> dict:
    if f"{var_name}_path" in config:
        template_path = Path(config.pop(f"{var_name}_path"))
        if template_path.suffix == ".txt":
            template = template_path.read_text(encoding="utf-8")
        else:
            raise ValueError
        config[var_name] = template
    return config


def _load_examples(config: dict) -> dict:
    if isinstance(config["examples"], list):
        pass
    elif isinstance(config["examples"], str):
        path = Path(config["examples"])
        with path.open(encoding="utf-8") as f:
            examples = f.read()
        config["examples"] = examples
    return config


def _load_few_shot_prompt(config: dict):
    if "example_prompt_path" in config:
        config["example_prompt"] = load_prompt(config.pop("example_prompt_path"))
    return config
