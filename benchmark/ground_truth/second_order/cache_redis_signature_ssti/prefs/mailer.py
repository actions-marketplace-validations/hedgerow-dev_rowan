"""Outbound mail assembly.

Called from the digest scheduler, not from the preferences API.
"""

import redis

from prefs.render import render_signature
from prefs.settings import DEFAULT_SIGNATURE

cache = redis.Redis.from_url("redis://localhost:6379/2")


def build_message(user, subject, body_html):
    cached = cache.get(f"prefs:signature:{user.id}")
    markup = cached.decode("utf-8") if cached else DEFAULT_SIGNATURE

    signature = render_signature(markup, user)
    return {
        "to": user.email,
        "subject": subject,
        "html": f"{body_html}<hr>{signature}",
    }
