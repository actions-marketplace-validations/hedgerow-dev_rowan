from django.db import models


class Document(models.Model):
    owner = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    body = models.TextField()
