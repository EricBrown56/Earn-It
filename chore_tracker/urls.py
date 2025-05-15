"""
URL configuration for chore_tracker project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
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
# chores/urls.py (Create this file inside the 'chores' app directory)

from django.urls import path
from . import views

# app_name = 'chores' # Optional: Define app namespace if needed for {% url 'chores:...' %}

urlpatterns = [
    # --- Authentication URLs ---
    # Signup page (GET displays form, POST processes registration)
    path('signup/', views.SignUpView.as_view(), name='signup'),

    # Login page (GET displays form with client-side Firebase login, POST verifies ID token)
    path('login/', views.LoginView.as_view(), name='login'),

    # Logout action (clears Django session)
    path('logout/', views.logout_view, name='logout'),

    # --- Core Application URLs ---
    # Main dashboard (routes to parent or child view based on role)
    path('dashboard/', views.dashboard, name='dashboard'),

    # --- Action URLs (typically called via POST from forms) ---
    # Add a new chore definition (Parent)
    path('chores/add/', views.add_chore, name='add_chore'),

    # Assign an existing chore to a child (Parent)
    path('chores/assign/', views.assign_chore, name='assign_chore'),

    # Mark a chore as completed (Child) - requires assignment ID
    path('chores/complete/<str:assignment_id>/', views.complete_chore, name='complete_chore'),

    # Verify a completed chore (Parent) - requires assignment ID
    path('chores/verify/<str:assignment_id>/', views.verify_chore, name='verify_chore'),

    # --- Reward Checking URL ---
    # Page for parents to see who is eligible for rewards
    path('rewards/', views.check_rewards, name='check_rewards'),

    # Add other URLs as needed (e.g., edit chore, manage family, profile settings)
    # path('chores/edit/<str:chore_id>/', views.edit_chore, name='edit_chore'),
    # path('family/manage/', views.manage_family, name='manage_family'),
]
#python
# chore_tracker/urls.py (Main project URLs - in the 'chore_tracker' directory)

from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect
from django.conf import settings # Import settings
from django.conf.urls.static import static # Import static helper

urlpatterns = [
    # Django admin site (optional, but useful for superuser access)
    path('admin/', admin.site.urls),

    # Include the URLs from the 'chores' app, prefixing them with 'app/'
    # Example: /app/login/, /app/dashboard/, /app/chores/add/
    path('app/', include('chores.urls')),

    # Redirect the root URL ('/')
    # If the user is logged in (session exists), redirect to the dashboard.
    # Otherwise, redirect to the login page.
    path('', lambda request: redirect('dashboard' if request.session.get('user_uid') else 'login', permanent=False)),

    # Add other top-level URL patterns for your project if needed
    # path('api/', include('api.urls')), # Example for a separate API app
]

# --- Static files serving configuration (for Development ONLY) ---
# In production, your web server (like Nginx or Apache) or hosting service
# should be configured to serve static files directly.
if settings.DEBUG:
    # This tells Django's development server how to serve static files
    # collected by `python manage.py collectstatic` or found in STATICFILES_DIRS.
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

    # If you were using media files (user-uploaded files), you would add:
    # urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

