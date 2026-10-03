from django.db import models


class Invoice(models.Model):
    """Customer-facing invoice, owned by the billing team."""

    account = models.ForeignKey("accounts.Account", on_delete=models.PROTECT)
    number = models.CharField(max_length=32, unique=True)
    amount_cents = models.BigIntegerField()
    notes = models.TextField(blank=True)
    issued_at = models.DateTimeField(auto_now_add=True)
