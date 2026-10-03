"""Reduced source snapshot: langchain-core==1.2.22 prompts/loading.py, d22df945."""

# ruff: noqa: F821 -- unrelated upstream helpers are omitted from this static fixture

from pathlib import Path


def _validate_path(path: Path) -> None:
    if path.is_absolute():
        raise ValueError("absolute path")
    if ".." in path.parts:
        raise ValueError("parent traversal")


def _load_template(
    var_name: str, config: dict, *, allow_dangerous_paths: bool = False
) -> dict:
    if f"{var_name}_path" in config:
        template_path = Path(config.pop(f"{var_name}_path"))
        if not allow_dangerous_paths:
            _validate_path(template_path)
        if template_path.suffix == ".txt":
            template = template_path.read_text(encoding="utf-8")
        else:
            raise ValueError
        config[var_name] = template
    return config


def _load_examples(config: dict, *, allow_dangerous_paths: bool = False) -> dict:
    if isinstance(config["examples"], list):
        pass
    elif isinstance(config["examples"], str):
        path = Path(config["examples"])
        if not allow_dangerous_paths:
            _validate_path(path)
        with path.open(encoding="utf-8") as f:
            examples = f.read()
        config["examples"] = examples
    return config


def _load_few_shot_prompt(config: dict, *, allow_dangerous_paths: bool = False):
    if "example_prompt_path" in config:
        example_prompt_path = Path(config.pop("example_prompt_path"))
        if not allow_dangerous_paths:
            _validate_path(example_prompt_path)
        config["example_prompt"] = load_prompt(
            example_prompt_path, allow_dangerous_paths=allow_dangerous_paths
        )
    return config
