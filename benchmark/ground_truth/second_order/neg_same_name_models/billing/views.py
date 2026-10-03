"""Billing invoice creation.

The customer-supplied memo goes onto the billing invoice. Nothing in the
billing app renders or shells out with it.
"""

from django.http import JsonResponse
from django.views.decorators.http import require_POST

from billing.models import Invoice


@require_POST
def create_invoice(request):
    invoice = Invoice(
        account_id=request.POST["account_id"],
        number=request.POST["number"],
        amount_cents=int(request.POST["amount_cents"]),
        notes=request.POST.get("memo", ""),
    )
    invoice.save()
    return JsonResponse({"id": invoice.pk}, status=201)
