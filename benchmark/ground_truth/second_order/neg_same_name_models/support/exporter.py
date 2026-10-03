"""Vendor invoice export.

Reads `support.models.Invoice` -- NOT the billing model of the same name --
and puts its notes into a shell command. The billing app's tainted write to
`Invoice.notes` must not arm this read.
"""

from pathlib import Path

from support.models import Invoice
from support.pdfgen import render_with_footer

STAGING_DIR = Path("/var/spool/support-html")


def export_approved_invoice(contract_id):
    invoice = Invoice.objects.filter(contract_id=contract_id, approved=True).first()
    if invoice is None:
        return None

    html_path = STAGING_DIR / f"{invoice.vendor_reference}.html"
    return render_with_footer(html_path, invoice.notes)
