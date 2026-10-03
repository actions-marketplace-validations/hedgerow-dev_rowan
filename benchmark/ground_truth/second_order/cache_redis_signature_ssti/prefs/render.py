"""Signature rendering.

Signatures support a small set of merge fields (`{{ user.name }}`), so they
go through Jinja rather than plain string substitution.
"""

from jinja2 import Environment, select_autoescape

_ENV = Environment(autoescape=select_autoescape(["html"]))


def render_signature(markup, user):
    template = _ENV.from_string(markup)
    return template.render(user=user)
