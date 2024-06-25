from django.db import models
from django.utils.timezone import now


class Article(models.Model):

    statuses = [
        ("d", "Draft"),
        ("p", "Published"),
        ("w", "Withdrawn"),
    ]
    slug = models.SlugField(max_length=1024, unique=True)
    title = models.CharField(max_length=1024)
    status = models.CharField(max_length=256, choices=statuses)
    created_date = models.DateTimeField(default=now)
