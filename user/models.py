from django.db import models
from post.models import Post
from django.utils import timezone
from django.conf import settings

class Notification(models.Model):
    id = models.AutoField(primary_key = True, db_column='notification_id')
    account = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE) #related_name이 미정이므로 역참조시 Notification_set으로 참조
    post = models.ForeignKey(Post, on_delete=models.CASCADE)
    content = models.TextField()
    is_checked = models.BooleanField()
    created_at = models.DateTimeField(default=timezone.now)