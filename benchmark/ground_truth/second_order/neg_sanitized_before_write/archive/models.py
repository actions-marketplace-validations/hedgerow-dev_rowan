from django.db import models


class ArchiveJob(models.Model):
    QUEUED = "queued"
    DONE = "done"

    owner = models.ForeignKey("auth.User", on_delete=models.CASCADE)
    archive_name = models.CharField(max_length=64)
    state = models.CharField(max_length=16, default=QUEUED)
    created_at = models.DateTimeField(auto_now_add=True)
