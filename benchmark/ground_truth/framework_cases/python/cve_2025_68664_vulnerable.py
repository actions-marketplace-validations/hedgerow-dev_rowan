from flask import request
import framework.serialization


def restore():
    value = request.get_json()
    encoded = framework.serialization.dumps(value)
    return framework.serialization.loads(encoded)
