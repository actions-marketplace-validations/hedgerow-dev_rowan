"""Archive worker.

Reads `ArchiveJob.archive_name` back out of the database and shells out with
it. Safe only because of the allowlist in `archive.views`.
"""

import logging

from archive.compress import compress
from archive.models import ArchiveJob

logger = logging.getLogger(__name__)


def run_next_job():
    job = ArchiveJob.objects.filter(state=ArchiveJob.QUEUED).first()
    if job is None:
        return None

    path = compress(job.archive_name)
    job.state = ArchiveJob.DONE
    job.save(update_fields=["state"])
    logger.info("archived %s", path)
    return path
