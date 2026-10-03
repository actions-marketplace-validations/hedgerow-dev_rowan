from flask import request
from pkg import run_it


def handler():
    q = request.args.get('q')
    run_it(q)
