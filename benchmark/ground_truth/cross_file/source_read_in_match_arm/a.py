from flask import request
from c import run_it


def handler():
    match request.method:
        case "POST":
            q = request.args.get("q")
            run_it(q)
