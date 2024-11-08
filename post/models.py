from django.db import models
from django.utils import timezone
from django.conf import settings

class Post(models.Model):
    id = models.AutoField(primary_key = True, db_column='post_id')
    account = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE) #related_name이 미정이므로 역참조시 Post_set으로 참조
    title = models.TextField()
    content = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)
    is_image = models.BooleanField()

class Post_like(models.Model):
    id = models.AutoField(primary_key = True, db_column='post_like_id')
    post = models.ForeignKey(Post, on_delete=models.CASCADE)
    account = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

class Post_dislike(models.Model):
    id = models.AutoField(primary_key = True, db_column='post_dislike_id')
    post = models.ForeignKey(Post, on_delete=models.CASCADE)
    account = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

class Image(models.Model):
    id = models.AutoField(primary_key = True, db_column='image_id')
    post = models.ForeignKey(Post, on_delete=models.CASCADE)
    image_link = models.TextField()