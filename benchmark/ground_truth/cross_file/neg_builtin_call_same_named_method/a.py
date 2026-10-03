from flask import request
from c import run_it


class Store:
    def open(self, cmd):
        run_it(cmd)


def handler():
    q = request.args.get('q')
    return open(q).read()
