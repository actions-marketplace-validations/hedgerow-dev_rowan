from flask import request
from httpx import Request


def handler():
    q = request.args.get('q')
    return Request(q)
