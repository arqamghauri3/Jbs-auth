from django.shortcuts import render
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView
from .models import CustomUser
from .serializers import *
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
# views.py
import requests 
from django.conf import settings

class SocialLoginView(APIView):
    def post(self, request):
        provider = request.data.get('provider')
        access_token = request.data.get('access_token')

        if provider == 'google':
            user_info = self.validate_google_token(access_token)
        elif provider == 'facebook':
            user_info = self.validate_facebook_token(access_token)
        else:
            return Response({"error": "Unsupported provider"}, status=status.HTTP_400_BAD_REQUEST)

        if not user_info:
            return Response({"error": "Invalid social token"}, status=status.HTTP_400_BAD_REQUEST)

        email = user_info.get('email')
        first_name = user_info.get('first_name', '')
        last_name = user_info.get('last_name', '')

        if not email:
            return Response({"error": "No email provided by social provider"}, status=status.HTTP_400_BAD_REQUEST)

        user, created = CustomUser.objects.get_or_create(
            email=email,
            defaults={
                'first_name': first_name,
                'last_name': last_name,
                'provider': provider
            }
        )

        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })

    def validate_google_token(self, token):
        try:
            google_response = requests.get(
                'https://www.googleapis.com/oauth2/v3/userinfo',
                headers={'Authorization': f'Bearer {token}'}
            )
            if google_response.status_code == 200:
                return google_response.json()
        except Exception:
            return None
        return None

    def validate_facebook_token(self, token):
        try:
            app_id = "YOUR_FACEBOOK_APP_ID"
            app_secret = "YOUR_FACEBOOK_APP_SECRET"
            fb_response = requests.get(
                f"https://graph.facebook.com/me?fields=id,email,first_name,last_name&access_token={token}"
            )
            if fb_response.status_code == 200:
                return fb_response.json()
        except Exception:
            return None
        return None

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")

            if not refresh_token:
                return Response({"detail": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

            token = RefreshToken(refresh_token)

            token.blacklist()

            return Response({"detail": "Successfully logged out."}, status=status.HTTP_205_RESET_CONTENT)

        except TokenError:
            return Response({"detail": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)

class CustomTokenObtainPairView(TokenObtainPairView):
    permission_classes = [AllowAny]
    serializer_class = CustomLoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            provider = serializer.validated_data.get('provider', None)

            user = authenticate(email=email, password=password)

            if user is not None:
                if provider and user.provider != provider:
                    return Response({'detail': 'Provider mismatch.'}, status=status.HTTP_400_BAD_REQUEST)

                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                return Response({
                    'access': access_token,
                    'refresh': str(refresh),
                }, status=status.HTTP_200_OK)

            return Response({'detail': 'Invalid credentials or provider mismatch.'}, status=status.HTTP_401_UNAUTHORIZED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CustomUserView(ListAPIView):
    serializer_class = CustomUserSerializer
    queryset = CustomUser.objects.all()
    permission_classes = (IsAuthenticated, )
    pass

class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)