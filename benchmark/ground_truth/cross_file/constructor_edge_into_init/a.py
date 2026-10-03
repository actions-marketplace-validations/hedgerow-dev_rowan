from flask import request
from job import Job


def handler():
    q = request.args.get('q')
    Job(q)
