from flask import request
import pkg.impl


def handler():
    q = request.args.get('q')
    pkg.impl.run_it(q)
