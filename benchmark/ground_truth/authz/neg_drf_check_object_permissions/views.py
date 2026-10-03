from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import Document


class DocView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        doc = get_object_or_404(Document, pk=pk)
        self.check_object_permissions(request, doc)
        return Response(doc.body)


class OtherView(APIView):
    def get(self, request, pk):
        doc = Document.objects.get(pk=pk)
        if doc.owner != request.user:
            return Response(status=403)
        return Response(doc.body)
