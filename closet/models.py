from django.db import models
from django.conf import settings

class Clothes(models.Model):
    id = models.AutoField(primary_key = True, db_column='cloth_id')
    account = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE) #related_name이 미정이므로 역참조시 Clothes_set으로 참조
    nickname = models.CharField(max_length = 50, unique = True, null=False)
    image = models.URLField(max_length = 255, null=False)
    type = models.IntegerField(null=False)
    label_num = models.CharField(max_length = 50)