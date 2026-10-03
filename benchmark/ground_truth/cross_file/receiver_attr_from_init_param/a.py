from flask import request
from runner import Runner
from svc import Svc


def handler():
    q = request.args.get('q')
    Svc(Runner()).go(q)
