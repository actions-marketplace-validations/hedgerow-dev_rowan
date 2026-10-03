"""Export request endpoint.

The user names their own output file. The view only enqueues a row; the
conversion happens in a separate process (`reports.runner`).
"""

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_POST

from reports.models import ExportJob


@require_POST
@login_required
def create_export(request):
    query = request.POST.get("source_query", "")
    if not query:
        return JsonResponse({"error": "source_query is required"}, status=400)

    job = ExportJob(
        owner=request.user,
        output_name=request.POST.get("output_name", "export"),
        source_query=query,
        state=ExportJob.QUEUED,
    )
    job.save()
    return JsonResponse({"job_id": job.pk, "state": job.state}, status=202)
