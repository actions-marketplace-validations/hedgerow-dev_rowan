from django.db import models


class ExportJob(models.Model):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"

    STATE_CHOICES = [
        (QUEUED, "Queued"),
        (RUNNING, "Running"),
        (DONE, "Done"),
    ]

    owner = models.ForeignKey("auth.User", on_delete=models.CASCADE)
    output_name = models.CharField(max_length=255)
    source_query = models.TextField()
    state = models.CharField(max_length=16, choices=STATE_CHOICES, default=QUEUED)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]
