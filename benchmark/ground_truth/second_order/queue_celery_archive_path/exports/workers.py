"""Archive worker.

Runs in the Celery worker process. `build_archive` is only ever reached
through the broker.
"""

import logging

from celery import shared_task

from exports.packaging import package_directory

logger = logging.getLogger(__name__)


@shared_task(name="exports.workers.build_archive")
def build_archive(prefix, retention_days):
    archive = package_directory(prefix)
    logger.info("built %s (retention %sd)", archive, retention_days)
    return str(archive)
