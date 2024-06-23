from rest_framework import serializers
from .models import User, RoleMaster, UserRole, OTP, UserProfile
from django.contrib.auth import authenticate, password_validation


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['bio', 'location']

    def update(self, instance, validated_data):
        instance.bio = validated_data.get('bio')
        instance.location = validated_data.get('location')
        instance.save()
        return instance


class UserSerializer(serializers.ModelSerializer):
    role = serializers.CharField(write_only=True)
    profile = UserProfileSerializer(required=False)
    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'role', 'profile']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            password=validated_data['password']
        )
        UserProfile.objects.create(user=user)
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


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect.")
        return value

    def validate_new_password(self, value):
        password_validation.validate_password(value)
        return value

    def save(self):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        user = User.objects.filter(email=value).first()
        if not user:
            raise serializers.ValidationError("User with this email does not exist.")
        return value

    def save(self):
        user = User.objects.get(email=self.validated_data['email'])
        return user
