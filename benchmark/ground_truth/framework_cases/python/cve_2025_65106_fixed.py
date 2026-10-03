from flask import request


def render():
    value = request.args["value"]
    return "Hello {value}".format(value=value)
