from flask import request


def render(context):
    template = request.args["template"]
    return template.format_map(context)
