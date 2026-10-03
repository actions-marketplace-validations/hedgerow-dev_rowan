from flask import request
from safe import Safe
from svc import Svc

svc = Safe()
unused = Svc


def handler():
    q = request.args.get('q')
    svc.go(q)
