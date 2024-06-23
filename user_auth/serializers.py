from rest_framework import serializers
from .models import User, RoleMaster, UserRole, OTP
from django.contrib.auth import authenticate


class UserSerializer(serializers.ModelSerializer):
    role = serializers.CharField(write_only=True)
    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'role']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            password=validated_data['password']
        )
        role = RoleMaster.objects.get(role_name=validated_data['role'])
        UserRole.objects.create(user=user, role=role)
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(**data)
        if user and user.is_active:
            return user
        raise serializers.ValidationError("Incorrect Credentials")


class OTPLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6, write_only=True)

    def validate(self, data):
        try:
            user = User.objects.get(email=data['email'])
            otp_record = OTP.objects.get(user=user, otp=data['otp'])
            if otp_record.is_valid():
                return user
            else:
                raise serializers.ValidationError("OTP has expired")
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found")
        except OTP.DoesNotExist:
            raise serializers.ValidationError("Invalid OTP")
