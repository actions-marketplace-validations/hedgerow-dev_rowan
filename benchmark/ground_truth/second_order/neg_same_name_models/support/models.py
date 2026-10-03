from django.db import models


class Invoice(models.Model):
    """Vendor invoice attached to a support contract.

    Same class name as `billing.models.Invoice` and the same `notes` field,
    but a completely unrelated table. Only staff write to it.
    """

    contract = models.ForeignKey("support.Contract", on_delete=models.CASCADE)
    vendor_reference = models.CharField(max_length=64)
    notes = models.TextField(blank=True)
    approved = models.BooleanField(default=False)
