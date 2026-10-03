from flask import request
from c import run_it as go


def handler():
    q = request.args.get('q')
    go(q)
