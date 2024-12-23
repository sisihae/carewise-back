"""
URL configuration for carewise project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from account.views import EmailVerificationView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/v1/account/', include('account.urls')),
    path('api/v1/user/', include('user.urls')),
    path('api/v1/post/', include('post.urls')),
    path('api/v1/comment/', include('comment.urls')),
    path('api/v1/reply/', include('reply.urls')),
    path('api/v1/report/', include('report.urls')),
    path('api/v1/closet/', include('closet.urls')),
    path('api/v1/search/', include('search.urls')),
    path('account/email/<str:encoded_uid>/<str:token_uid>', EmailVerificationView.as_view()),
]
