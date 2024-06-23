from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.db import models
from django.utils import timezone
import datetime


class BaseModel(models.Model):
    created_at = models.DateTimeField(auto_now=True)
    updated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        abstract = True


class UserManager(BaseUserManager):
    """
    Custom User Manager.
    """
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True')

        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True')

        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, BaseModel):
    """
    Custom User model.
    """
    email = models.EmailField(max_length=255, unique=True)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    objects = UserManager()

    def __str__(self):
        return self.email

    class Meta:
        db_table = "rbac_user"


class RoleMaster(BaseModel):
    """
    Defines Roles Master - Admin, Solution Seeker, Solution Provider.
    """
    role_name = models.CharField('Role Name', unique=True, max_length=255)
    role_desc = models.CharField("Role Description", null=True, max_length=255)

    class Meta:
        db_table = "rbac_role"


class UserRole(BaseModel):
    """
    Defines relation between user and role.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.ForeignKey(RoleMaster, on_delete=models.SET_NULL, null=True)


class OTP(BaseModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)

    def is_valid(self):
        # OTP is valid for 5 minutes
        return self.updated_at >= timezone.now() - datetime.timedelta(minutes=5)

