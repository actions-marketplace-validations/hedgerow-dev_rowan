from flask import request
from c import run_kw, run_pos


def handler():
    q = request.args.get('q')
    run_kw(cmd=q)
    run_pos(q)
