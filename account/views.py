from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Account
from django.core.validators import RegexValidator

USERNAME_REGEX = r'^[a-zA-Z0-9]{1,50}$'
username_validator = RegexValidator(
    regex=USERNAME_REGEX,
    message='Username must be between 1 and 50 characters and contain only alphabet letters and numbers.'
)

# Create your views here.
class UsernameView(APIView):
  def get(self, request):
    username = request.data.get('request_username')

    # 유저네임 형식 검사
    try:
        username_validator(username)
    except:
        return Response({'result': 0}, status=status.HTTP_200_OK)

    # 중복 검사
    if Account.objects.filter(username=username).exists():
        return Response({'result': 10}, status=status.HTTP_200_OK)

    # 유효하고 중복이 없는 경우
    return Response({'result': 11}, status=status.HTTP_200_OK)
  

class NicknameView(APIView):
  def get(self, request):
    nickname = request.data.get('request_nickname')

    # 닉네임 형식 검사
    try:
        username_validator(nickname)
    except:
        return Response({'result': 0}, status=status.HTTP_200_OK)

    # 중복 검사
    if Account.objects.filter(nickname=nickname).exists():
        return Response({'result': 10}, status=status.HTTP_200_OK)

    # 유효하고 중복이 없는 경우
    return Response({'result': 11}, status=status.HTTP_200_OK)
  

class EmailView(APIView):
  def get(self, request):
    email = request.data.get('request_email')

    # 이메일 형식 검사
    try:
        username_validator(email)
    except:
        return Response({'result': 0}, status=status.HTTP_200_OK)

    # 중복 검사
    if Account.objects.filter(email=email).exists():
        return Response({'result': 10}, status=status.HTTP_200_OK)

    # 유효하고 중복이 없는 경우
    return Response({'result': 11}, status=status.HTTP_200_OK)