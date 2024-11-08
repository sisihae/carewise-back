from django.db import models
from django.utils import timezone
from post.models import Post
from django.conf import settings

class Comment(models.Model):
    id = models.AutoField(primary_key = True, db_column='comment_id')
    post = models.ForeignKey(Post, on_delete=models.CASCADE) #related_name이 미정이므로 역참조시 Comment_set으로 참조
    account = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)

class Comment_like(models.Model):
    id = models.AutoField(primary_key = True, db_column='comment_like_id')
    comment = models.ForeignKey(Comment, on_delete=models.CASCADE)
    account = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)