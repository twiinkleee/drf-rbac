# DRF RBAC Implementation

This project implements Role-Based Access Control (RBAC) using Django REST Framework (DRF), allowing users with different roles to access and manage their profiles.

NOTE - The project is implemented on development branch.

### Features:

- **Authentication:** JWT authentication for secure API access.
- **Roles:** Admin, Solution Provider, and Solution Seeker roles with custom permissions.
- **User Operations:** Register, Login, Change Password, Forgot Password (via Email), and CRUD operations on user profiles.
- **Permissions:** Custom permissions (`IsAdminUser`, `IsSolutionProvider`, `IsSolutionSeeker`) for role-based access.

### Project Structure:

- **`user_auth` App:** Handles user authentication, profiles, roles, and permissions.
  - `models.py`: Defines `User`, `UserProfile`, `RoleMaster`, and `Permissions` models.
  - `serializers.py`: Serializes user and profile data for API interaction.
  - `views.py`: Contains API views for user registration, login, profile management.
  - `permissions.py`: Custom permission classes (`IsAdminUser`, `IsSolutionProvider`, `IsSolutionSeeker`).

### Setup:

1. **Dependencies:**
   - Python 3.x
   - Django
   - Django REST Framework

2. **Installation:**
   ```bash
   pip install -r requirements.txt

3. **Database Setup:** 
   Configure your database in settings.py.
   ```bash
   python manage.py makemigrations
   python manage.py migrate

   Run Server:
   ```bash
   python manage.py runserver
