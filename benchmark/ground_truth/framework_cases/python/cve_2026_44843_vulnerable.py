from flask import request


def restore(runtime):
    return runtime.load(request.get_json(), allowed_objects="all")
