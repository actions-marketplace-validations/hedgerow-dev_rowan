from flask import request


def build(TemplateEngine):
    value = request.get_json()["value"]
    return TemplateEngine(template="Result: {value}").format(value=value)
