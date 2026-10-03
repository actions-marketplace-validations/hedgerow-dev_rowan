from flask import request


def fetch_image():
    return ssrf_safe_get(request.get_json()["image_url"])
