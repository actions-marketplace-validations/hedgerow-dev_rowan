"""Page refresher used by the citation checker."""

import requests

REFRESH_TIMEOUT = 8


def fetch_page(url):
    response = requests.get(url, timeout=REFRESH_TIMEOUT)
    response.raise_for_status()
    return response.text
