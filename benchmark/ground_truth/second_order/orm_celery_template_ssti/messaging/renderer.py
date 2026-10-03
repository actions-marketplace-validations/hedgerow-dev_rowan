"""Jinja rendering for notification bodies."""

from jinja2 import Environment, select_autoescape

_ENV = Environment(autoescape=select_autoescape(["html"]))


def render_body(source, context):
    template = _ENV.from_string(source)
    return template.render(**context)
