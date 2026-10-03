from flask import request


def read_input():
    return request.args.get("q")
