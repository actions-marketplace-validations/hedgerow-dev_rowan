from flask import request


def build(TemplateEngine):
    template = request.get_json()["template"]
    return TemplateEngine(template=template)
