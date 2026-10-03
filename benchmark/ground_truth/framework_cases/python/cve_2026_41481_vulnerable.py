from flask import request


def split(splitter):
    return splitter.split_text_from_url(request.args["url"])
