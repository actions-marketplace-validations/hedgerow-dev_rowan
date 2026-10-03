"""Reduced source snapshot: langchain-core==1.0.6 prompts/string.py, 6f677ef5.

This preserves the f-string field extraction and return path from upstream.
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

    return sorted(input_variables)
