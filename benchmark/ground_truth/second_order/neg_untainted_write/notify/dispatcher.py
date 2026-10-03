"""Background delivery loop.

Structurally identical to the positive webhook case: same model, same read
idiom, same cross-file sink. The only difference is that nothing untrusted
ever reaches `Webhook.target_url`.
"""

import logging

from notify.http_client import post_json
from notify.models import Webhook, db

logger = logging.getLogger(__name__)


def deliver_event(owner_id, event):
    hook = Webhook.query.filter_by(owner_id=owner_id, active=True).first()
    if hook is None:
        logger.info("no active webhook for owner %s", owner_id)
        return False

    body = {"event": event["name"], "payload": event["payload"]}
    try:
        post_json(hook.target_url, body, headers={"X-Signature": hook.secret})
    except Exception:
        hook.failure_count += 1
        db.session.commit()
        return False
    return True
