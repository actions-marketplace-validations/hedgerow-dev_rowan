"""Thin HTTP client shared by the delivery workers."""

import requests

DELIVERY_TIMEOUT = 10


def post_json(url, body, headers=None):
    response = requests.post(url, json=body, headers=headers, timeout=DELIVERY_TIMEOUT)
    response.raise_for_status()
    return response.status_code
