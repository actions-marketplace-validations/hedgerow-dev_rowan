from flask import request
from c import *


def handler():
    q = request.args.get('q')
    run_it(q)
