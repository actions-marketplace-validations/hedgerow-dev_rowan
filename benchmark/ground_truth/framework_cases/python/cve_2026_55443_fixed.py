from flask import request
from werkzeug.utils import secure_filename


def search(index):
    pattern = secure_filename(request.args["pattern"])
    return index.search_files(pattern=pattern, path="/srv/data")
