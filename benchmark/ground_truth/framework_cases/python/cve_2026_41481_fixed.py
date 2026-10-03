from flask import request


def split():
    return ssrf_safe_get(request.args["url"], revalidate_redirects=True)
