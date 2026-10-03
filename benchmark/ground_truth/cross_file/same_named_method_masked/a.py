from flask import request
from c import Shell


def handler():
    q = request.args.get('q')
    s = Shell()
    s.run(q)
