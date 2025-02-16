"""
URL routing configuration for authentication-related endpoints.

Defines all user account management URLs including login, registration,
and password reset workflows. Integrates custom views with Django's
built-in authentication views while overriding default templates.
"""

from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

# Authentication URL patterns
urlpatterns = [
    # Custom authentication views
    path("login/", views.login, name="login"),
    path("signup/", views.signup, name="signup"),
    
    # Password change workflow
    path('password_change/', views.password_change, name='password_change'),
    path(
        'password_change/done/', 
        auth_views.PasswordChangeDoneView.as_view(
            template_name='registration/password_change_done.html'
        ), 
        name='password_change_done'
    ),
    
    # Password reset workflow
    path('password_reset/', views.password_reset, name='password_reset'),
    path(
        'password_reset/done/', 
        auth_views.PasswordResetDoneView.as_view(
            template_name='registration/password_reset_done.html'
        ), 
        name='password_reset_done'
    ),
    path(
        'reset/<uidb64>/<token>/',  # Token-based reset confirmation
        views.password_reset_confirm, 
        name='password_reset_confirm'
    ),
    path(
        'reset/done/',  # Final reset completion page
        auth_views.PasswordResetCompleteView.as_view(
            template_name='registration/password_reset_complete.html'
        ), 
        name='password_reset_complete'
    ),
]