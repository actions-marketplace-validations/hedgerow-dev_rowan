"""Reconciliation sweep.

Runs from a systemd timer on the provisioning host. Reads the state file the
API writes; nothing calls between the two processes.
"""

import json
import logging
from pathlib import Path

from provision.network import rename_connection

STATE_DIR = Path("/var/lib/provision")

logger = logging.getLogger(__name__)


def reconcile_pending():
    pending_path = STATE_DIR / "pending.json"
    if not pending_path.exists():
        return 0

    with open(pending_path, encoding="utf-8") as handle:
        pending = json.load(handle)

    for entry in pending:
        rename_connection(entry["interface"], entry["hostname"])
        logger.info("configured %s", entry["hostname"])

    pending_path.unlink()
    return len(pending)
