from flask import request


def restore(runtime, Message):
    return runtime.load(request.get_json(), allowed_objects=[Message])
