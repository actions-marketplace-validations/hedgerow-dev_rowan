from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import Document


class DocViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]

    def retrieve(self, request, pk=None):
        doc = Document.objects.get(pk=pk)
        return Response(doc.body)

    def list(self, request):
        return Response([d.id for d in Document.objects.filter(owner=request.user)])
