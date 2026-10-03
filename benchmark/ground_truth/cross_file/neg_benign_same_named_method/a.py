from flask import request
from c import Safe


def handler():
    q = request.args.get('q')
    s = Safe()
    s.run(q)
