from django.urls import path, include
from .views import UsernameView, NicknameView, EmailView

app_name = 'account'
urlpatterns = [
  path('check/username', UsernameView.as_view()),
  path('check/nickname', NicknameView.as_view()),
  path('check/email', EmailView.as_view()),
]