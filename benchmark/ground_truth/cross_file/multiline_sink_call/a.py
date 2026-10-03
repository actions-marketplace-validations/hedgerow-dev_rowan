from flask import request
from c import run_it


def handler():
    q = request.args.get('q')
    run_it(q)
