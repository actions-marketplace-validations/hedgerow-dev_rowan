from flask import request
from job import run_job


def handler():
    q = request.args.get('q')
    run_job(q)
