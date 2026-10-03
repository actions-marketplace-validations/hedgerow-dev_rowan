from flask import request


def count(model):
    image_url = request.get_json()["image_url"]
    messages = [{"content": [{"type": "image_url", "url": image_url}]}]
    return model.get_num_tokens_from_messages(messages, allow_fetching_images=False)
