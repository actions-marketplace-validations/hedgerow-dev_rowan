"""Partner delivery loop.

Touches `target_url` and `secret` only. `display_label` -- the one field the
customer controls -- is never read here, so the write channel and the read
are on different fields of the same model.
"""

import logging

from integrations.http_client import post_json
from integrations.models import PartnerHook

logger = logging.getLogger(__name__)


def deliver_event(owner_id, event):
    hook = PartnerHook.query.filter_by(owner_id=owner_id, active=True).first()
    if hook is None:
        logger.info("no partner integration for owner %s", owner_id)
        return False

    post_json(hook.target_url, {"event": event}, headers={"X-Signature": hook.secret})
    return True
