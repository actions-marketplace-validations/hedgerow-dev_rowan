from flask import request
from b import relay


def handler():
    q = request.args.get('q')
    relay(q)
