from flask import request
from safe_runner import SafeRunner
from svc import Svc


def handler():
    q = request.args.get('q')
    Svc(SafeRunner()).go(q)
