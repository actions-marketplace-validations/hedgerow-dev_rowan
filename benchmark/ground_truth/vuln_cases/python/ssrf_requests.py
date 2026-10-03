import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch_preview():
    target = request.args.get("url")
    resp = requests.get(target, timeout=5)
    return resp.text
