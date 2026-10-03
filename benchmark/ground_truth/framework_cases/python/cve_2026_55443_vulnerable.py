from flask import request


def search(index):
    return index.search_files(
        pattern=request.args["pattern"],
        path=request.args["path"],
    )
