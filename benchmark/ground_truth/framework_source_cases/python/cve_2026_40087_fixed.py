"""Reduced source snapshot: langchain-core==1.2.28 prompts/string.py, dd7c3eb3."""

# ruff: noqa: F821 -- unrelated upstream helpers are omitted from this static fixture

from string import Formatter


def _parse_f_string_fields(template: str) -> list[tuple[str, str | None]]:
    fields = []
    for _, field_name, format_spec, _ in Formatter().parse(template):
        if field_name is not None:
            fields.append((field_name, format_spec))
    return fields


def validate_f_string_template(template: str) -> list[str]:
    input_variables = set()
    for var, format_spec in _parse_f_string_fields(template):
        if "." in var or "[" in var or "]" in var:
            raise ValueError(f"Invalid variable name {var!r}")
        if var.isdigit():
            raise ValueError(f"Invalid variable name {var!r}")
        if format_spec and ("{" in format_spec or "}" in format_spec):
            raise ValueError("Nested replacement fields are not allowed")
        input_variables.add(var)
    return sorted(input_variables)


def get_template_variables(template: str, template_format: str) -> list[str]:
    if template_format == "jinja2":
        input_variables = sorted(_get_jinja2_variables_from_template(template))
    elif template_format == "f-string":
        input_variables = validate_f_string_template(template)
    elif template_format == "mustache":
        input_variables = mustache_template_vars(template)
    else:
        raise ValueError(f"Unsupported template format: {template_format}")
    return sorted(input_variables)
