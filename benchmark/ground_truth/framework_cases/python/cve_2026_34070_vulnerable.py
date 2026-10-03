from flask import request


def load_named():
    return load_config(request.args["path"])
