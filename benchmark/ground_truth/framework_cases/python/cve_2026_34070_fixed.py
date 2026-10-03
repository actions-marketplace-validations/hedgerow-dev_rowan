from flask import request
from werkzeug.utils import secure_filename


def load_named():
    safe_name = secure_filename(request.args["path"])
    return load_config(safe_name)
