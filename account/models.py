from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings

#migration 전에 꼭 덮어씌우는 User을 등록하는 작업하기 

class Account(AbstractUser):
    account_id = models.AutoField(primary_key = True)
    username = models.CharField(max_length = 50, unique = True, null = False)
    password = models.CharField(max_length = 50, null = False)
    profile_image_link = models.URLField(max_length = 255, null = False)
    email = models.EmailField(max_length = 50, unique = True, null = False)
    nickname = models.CharField(max_length = 50, unique = True, null=False)
    is_active = models.BooleanField()
    is_social = models.BooleanField()
    social_id = models.CharField(max_length = 50)
