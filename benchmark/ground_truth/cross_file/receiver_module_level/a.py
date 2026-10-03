from flask import request
from svc import Svc

svc = Svc()


def handler():
    q = request.args.get('q')
    svc.go(q)
