from django.http import HttpResponse
from django.views import View
from .models import Document


class DocDetail(View):
    def get(self, request, *args, **kwargs):
        doc = Document.objects.get(pk=kwargs["pk"])
        return HttpResponse(doc.body)


class MineDetail(View):
    def get(self, request, *args, **kwargs):
        doc = Document.objects.get(pk=kwargs["pk"], owner=request.user)
        return HttpResponse(doc.body)
