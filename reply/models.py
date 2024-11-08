from django.db import models
from django.utils import timezone
from comment.models import Comment
from post.models import Post
from django.conf import settings

class Reply(models.Model):
    id = models.AutoField(primary_key = True, db_column='reply_id')
    comment = models.ForeignKey(Comment, on_delete=models.CASCADE) #related_name이 미정이므로 역참조시 Reply_set으로 참조
    account = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    post = models.ForeignKey(Post, on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)

class Reply_like(models.Model):
    id = models.AutoField(primary_key = True, db_column='reply_like_id')
    reply = models.ForeignKey(Reply, on_delete=models.CASCADE)
    account = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    