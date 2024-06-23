from rest_framework.permissions import BasePermission

from user_auth.models import UserRole


class IsAdminUser(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and UserRole.objects.filter(user=request.user, role__role_name='Admin').exists())


class IsSolutionProvider(BasePermission):
    def has_permission(self, request, view):
        return bool(
            request.user and UserRole.objects.filter(user=request.user, role__role_name='Solution Provider').exists())


class IsSolutionSeeker(BasePermission):
    def has_permission(self, request, view):
        return bool(
            request.user and UserRole.objects.filter(user=request.user, role__role_name='Solution Seeker').exists())
