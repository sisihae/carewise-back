from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Account
from django.core.validators import RegexValidator, validate_email
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
import jwt
from django.conf import settings
from datetime import datetime, timedelta, timezone
import redis

USERNAME_REGEX = r'^[a-zA-Z0-9]{1,50}$'
username_validator = RegexValidator(
    regex=USERNAME_REGEX,
    message='Username must be between 1 and 50 characters and contain only alphabet letters and numbers.'
)

# Redis 연결 설정
redis_instance = redis.StrictRedis(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    db=0,
    decode_responses=True
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
        validate_email(email)
    except ValidationError:
      return Response({'result': 0}, status=status.HTTP_200_OK)
    
    # 중복 검사
    if Account.objects.filter(email=email).exists():
        return Response({'result': 10}, status=status.HTTP_200_OK)

    # 유효하고 중복이 없는 경우
    return Response({'result': 11}, status=status.HTTP_200_OK)
  

class SignupView(APIView):
    def post(self, request):
        # 필수 필드 가져오기
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')
        nickname = request.data.get('nickname')

        # 입력 필드 검증
        if not username:
            return Response({'error': 'no username'}, status=status.HTTP_400_BAD_REQUEST)
        if not email:
            return Response({'error': 'no email'}, status=status.HTTP_400_BAD_REQUEST)
        if not password:
            return Response({'error': 'no password'}, status=status.HTTP_400_BAD_REQUEST)
        if not nickname:
            return Response({'error': 'no nickname'}, status=status.HTTP_400_BAD_REQUEST)

        # 중복 검사
        if Account.objects.filter(username=username).exists():
            return Response({'error': 'username already exists'}, status=status.HTTP_409_CONFLICT)
        if Account.objects.filter(email=email).exists():
            return Response({'error': 'email already exists'}, status=status.HTTP_409_CONFLICT)
        if Account.objects.filter(nickname=nickname).exists():  
            return Response({'error': 'nickname already exists'}, status=status.HTTP_409_CONFLICT)

        # 이메일 인증 링크 생성 및 전송
        account = Account(username=username, email=email, nickname=nickname, is_active=False, is_social = False, social_id = "-", profile_image_link = "default_image_link")
        account.set_password(password)
        account.save()

        encoded_uid = force_str(urlsafe_base64_encode(force_bytes(account.account_id)))
        token_uid = jwt.encode({'user_id': account.account_id}, settings.SECRET_KEY, algorithm='HS256')
        activation_link = f"http://carewise-snu.com/account/email/{encoded_uid}/{token_uid}"

        send_mail(
            'Carewise Email Verification',
            f'Please verify your email using the following link: {activation_link} ',
            from_email = settings.EMAIL_HOST_USER,
            recipient_list = [email],
        )

        return Response({'message': 'Account created successfully'}, status=status.HTTP_201_CREATED)
    

class EmailVerificationView(APIView):
    def get(self, request, encoded_uid, token_uid):
        try:
            # encoded_uid에서 user_id 추출
            decoded_uid = force_str(urlsafe_base64_decode(encoded_uid))
            user_id_from_encoded_uid = int(decoded_uid)

            # token_uid에서 user_id 추출
            decoded_token = jwt.decode(token_uid, settings.SECRET_KEY, algorithms=['HS256'])
            user_id_from_token_uid = decoded_token.get('user_id')

            # 두 user_id가 일치하는지 확인
            if user_id_from_encoded_uid != user_id_from_token_uid:
                return Response({'error': 'Verification failed'}, status=status.HTTP_400_BAD_REQUEST)

            # user_id에 해당하는 User 객체 가져오기
            try:
                account = Account.objects.get(account_id=user_id_from_encoded_uid)
            except Account.DoesNotExist:
                return Response({'error': 'User Not Found'}, status=status.HTTP_404_NOT_FOUND)

            # is_active 값 변경
            account.is_active = True
            account.save()

            return Response({'message': 'Email verified successfully'}, status=status.HTTP_200_OK)

        except (ValueError, jwt.ExpiredSignatureError, jwt.InvalidTokenError) as e:
            return Response({'error': 'Verification failed'}, status=status.HTTP_400_BAD_REQUEST)
        

class TokenRefreshView(APIView):
    def post(self, request):
        # Refresh token 가져오기
        refresh_token = request.data.get('refresh')
        
        if not refresh_token:
            return Response({'error': 'no refresh token'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Refresh token 검증
            decoded_refresh = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_refresh.get('user_id')
            
            if not user_id:
                return Response({'error': 'Invalid refresh token'}, status=status.HTTP_401_UNAUTHORIZED)
            
            # 새로운 Access token 생성
            new_access_token = jwt.encode(
                {
                    'user_id': user_id,
                    'exp': datetime.now(timezone.utc) + timedelta(minutes=15)  # Access token 만료시간 설정
                },
                settings.SECRET_KEY,
                algorithm='HS256'
            )

            # 새로운 Access token을 Set-Cookie에 담아 응답
            response = Response(status=status.HTTP_201_CREATED)
            response.set_cookie(
                key='access_token',
                value=new_access_token,
                httponly=True,
                secure=True,
                samesite='Lax'
            )
            return response

        except jwt.ExpiredSignatureError:
            # Refresh token이 만료된 경우
            return Response({'error': 'Please signin again'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            # Refresh token이 유효하지 않은 경우
            return Response({'error': 'Invalid refresh token'}, status=status.HTTP_401_UNAUTHORIZED)
        

class LogoutView(APIView):
    def delete(self, request):
        # Access token 확인
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith("Bearer "):
            return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Access token에서 사용자 정보 추출
        access_token = auth_header.split(" ")[1]
        try:
            decoded_access = jwt.decode(access_token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_access.get('user_id')
            
            if not user_id:
                return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)
        
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)

        # Refresh token 확인
        refresh_token = request.data.get('refresh')
        if not refresh_token:
            return Response({'error': 'no refresh token'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Refresh token 검증 및 블랙리스트 처리
        try:
            decoded_refresh = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=['HS256'])
            if decoded_refresh.get('user_id') != user_id:
                return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)

            # Redis에 refresh token을 블랙리스트로 추가
            ttl = timedelta(days=7)  # 예: 7일 후 만료
            redis_instance.setex(f"blacklist:{refresh_token}", int(ttl.total_seconds()), "blacklisted")
            
            return Response(status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError:
            return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({'error': 'Invalid refresh token'}, status=status.HTTP_401_UNAUTHORIZED)
        

class SignoutView(APIView):
    def delete(self, request):
        # Access token 확인
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith("Bearer "):
            return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)
        
        access_token = auth_header.split(" ")[1]
        try:
            # Access token에서 사용자 정보 추출
            decoded_access = jwt.decode(access_token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_access.get('user_id')
            
            if not user_id:
                return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)

            # User 찾기
            try:
                user = Account.objects.get(id=user_id)
            except Account.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

            # Refresh token 확인
            refresh_token = request.data.get('refresh')
            if not refresh_token:
                return Response({'error': 'no refresh token'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Refresh token 검증
            decoded_refresh = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=['HS256'])
            if decoded_refresh.get('user_id') != user_id:
                return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)

            # 유저 삭제 (cascade 옵션 적용)
            user.delete()

            # Redis에 refresh token을 블랙리스트로 추가
            ttl = timedelta(days=7)  # 예: 7일 후 만료
            redis_instance.setex(f"blacklist:{refresh_token}", int(ttl.total_seconds()), "blacklisted")

            return Response(status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError:
            return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({'error': 'Invalid token'}, status=status.HTTP_401_UNAUTHORIZED)