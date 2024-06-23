import datetime
import random

from django.core.mail import send_mail
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_jwt.settings import api_settings
from .models import User, UserRole, OTP
from .serializers import UserSerializer, LoginSerializer, OTPLoginSerializer

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER


class RegisterView(APIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=400)


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            payload = jwt_payload_handler(user)
            token = jwt_encode_handler(payload)
            return Response({'token': token}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=400)


class OTPLoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = OTPLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            payload = jwt_payload_handler(user)
            token = jwt_encode_handler(payload)
            return Response({'token': token}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GenerateOTPView(APIView):
    permission_classes = [permissions.AllowAny]

    def send_email(self, to_email, message):
        send_mail(
            'Your OTP Code',
            message,
            'ahujaserena@gmail.com',  # Replace with your "from" email address
            [to_email],
            fail_silently=False,
        )
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
            otp = str(random.randint(100000, 999999))
            user_otp = OTP.objects.get(user=user)
            if user_otp:
                user_otp.otp = otp
                user_otp.updated_at = datetime.datetime.now()
                user_otp.save()
            else:
                OTP.objects.create(user=user, otp=otp)
            # self.send_email(user.email, f'Your OTP is {otp}')
            return Response({'message': 'OTP sent to email'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
