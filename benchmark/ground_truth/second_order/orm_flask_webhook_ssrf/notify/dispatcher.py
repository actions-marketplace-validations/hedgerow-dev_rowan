"""Background delivery loop.

Runs out of a scheduler process. Nothing in `notify.views` calls into this
module and nothing here calls back, so the only thing connecting the two is
the `webhooks` table.
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
        logger.warning("delivery failed for webhook %s", hook.id)
        return False
    return True
