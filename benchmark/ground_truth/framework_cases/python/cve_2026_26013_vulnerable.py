from flask import request


def count(model):
    url = request.get_json()["image_url"]
    messages = [{"content": [{"type": "image_url", "url": url}]}]
    return model.get_num_tokens_from_messages(messages)
