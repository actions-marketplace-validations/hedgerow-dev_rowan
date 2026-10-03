from flask import request
import json


def restore(MessagePayload):
    value = json.loads(request.data)
    return MessagePayload.model_validate(value)
