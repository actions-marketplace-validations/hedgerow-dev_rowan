"""First-run provisioning.

Registers the one internal webhook the platform ships with. The target URL
comes from deployment configuration, never from a request.
"""

import secrets

from notify.models import Webhook, db
from notify.settings import INTERNAL_CALLBACK_URL, SYSTEM_OWNER_ID


def ensure_internal_webhook():
    existing = Webhook.query.filter_by(owner_id=SYSTEM_OWNER_ID).first()
    if existing is not None:
        return existing

    hook = Webhook(
        owner_id=SYSTEM_OWNER_ID,
        target_url=INTERNAL_CALLBACK_URL,
        secret=secrets.token_hex(16),
        active=True,
    )
    db.session.add(hook)
    db.session.commit()
    return hook
