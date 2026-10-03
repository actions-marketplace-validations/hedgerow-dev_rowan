"""Export worker process.

Started by systemd, polls the job table. It has no caller in the web tier.
"""

import logging
import time

from reports.conversion import convert_to_pdf
from reports.models import ExportJob

logger = logging.getLogger(__name__)
POLL_INTERVAL = 5


def run_next_job():
    job = ExportJob.objects.filter(state=ExportJob.QUEUED).first()
    if job is None:
        return None

    job.state = ExportJob.RUNNING
    job.save(update_fields=["state"])

    pdf_path = convert_to_pdf(job.output_name)

    job.state = ExportJob.DONE
    job.save(update_fields=["state"])
    logger.info("wrote %s", pdf_path)
    return pdf_path


def main():
    while True:
        if run_next_job() is None:
            time.sleep(POLL_INTERVAL)
