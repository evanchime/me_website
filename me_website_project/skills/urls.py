"""
URL configuration for the skills app.

Defines the root endpoint for the skills page when included under 
'/skills/' in the project's main URLs. The actual accessible path will 
be '/skills/'.
"""

from django.urls import path
from . import views

urlpatterns = [
    # Maps to '/skills/' (app's root via project inclusion)
    # The empty path '' combines with the project's 'skills/' prefix
    path('', views.skills, name='skills'),
]