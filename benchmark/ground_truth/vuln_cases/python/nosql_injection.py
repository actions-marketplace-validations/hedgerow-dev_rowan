from flask import Flask, request
from pymongo import MongoClient

app = Flask(__name__)
db = MongoClient().app


@app.route("/login", methods=["POST"])
def login():
    return str(db.users.find_one({"user": request.json["user"], "pw": request.json["pw"]}))
