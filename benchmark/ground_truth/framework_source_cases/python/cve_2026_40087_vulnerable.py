"""Reduced source snapshot: langchain-core==1.2.27 prompts/string.py, 64864041.

This version rejects traversal in top-level fields but ignores format_spec.
"""

# ruff: noqa: F821 -- unrelated upstream helpers are omitted from this static fixture

from string import Formatter


def get_template_variables(template: str, template_format: str) -> list[str]:
    if template_format == "jinja2":
        input_variables = _get_jinja2_variables_from_template(template)
    elif template_format == "f-string":
        input_variables = {
            v for _, v, _, _ in Formatter().parse(template) if v is not None
        }
    elif template_format == "mustache":
        input_variables = mustache_template_vars(template)
    else:
        msg = f"Unsupported template format: {template_format}"
        raise ValueError(msg)

    if template_format == "f-string":
        for var in input_variables:
            if "." in var or "[" in var or "]" in var:
                msg = f"Invalid variable name {var!r} in f-string template."
                raise ValueError(msg)
            if var.isdigit():
                msg = f"Invalid variable name {var!r} in f-string template."
                raise ValueError(msg)

    return sorted(input_variables)
