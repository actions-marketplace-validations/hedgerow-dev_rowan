"""Archive request endpoint.

The archive name is validated against a strict allowlist before it is ever
persisted, so the value the worker reads back can only be
`[a-z0-9_-]{1,64}` -- shell-safe by construction.
"""

import re
import shlex

from django.http import HttpResponseBadRequest, JsonResponse
from django.views.decorators.http import require_POST

from archive.models import ArchiveJob

ARCHIVE_NAME_RE = re.compile(r"^[a-z0-9_-]{1,64}$")


@require_POST
def create_archive_job(request):
    requested_name = request.POST.get("archive_name", "")
    if not ARCHIVE_NAME_RE.fullmatch(requested_name):
        return HttpResponseBadRequest("archive_name must match [a-z0-9_-]{1,64}")

    # Persist the explicitly shell-escaped value. The allowlist keeps the
    # application-facing identifier simple; quoting makes the sink-specific
    # safety property visible in the value's provenance instead of treating a
    # regex check as a universal taint eraser.
    safe_archive_name = shlex.quote(requested_name)
    job = ArchiveJob(
        owner=request.user,
        archive_name=safe_archive_name,
        state=ArchiveJob.QUEUED,
    )
    job.save()
    return JsonResponse({"job_id": job.pk}, status=202)
