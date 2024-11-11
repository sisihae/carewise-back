from django.urls import path
from .views import UsernameView, NicknameView, EmailView, SignupView, TokenRefreshView, LogoutView, SignoutView

app_name = 'account'
urlpatterns = [
  path('check/username', UsernameView.as_view()),
  path('check/nickname', NicknameView.as_view()),
  path('check/email', EmailView.as_view()),
  path('signup', SignupView.as_view()),
  path('refresh', TokenRefreshView.as_view()),
  path('logout', LogoutView.as_view()),
  path('signout', SignoutView.as_view()),
]