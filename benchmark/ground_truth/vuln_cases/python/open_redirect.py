from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/login")
def login():
    next_url = request.args.get("next")
    return redirect(next_url)
