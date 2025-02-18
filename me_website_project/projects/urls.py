"""
URL configuration for the projects app.

Defines the root endpoint for the projects page when included under 
'/projects/' in the project's main URLs. The actual accessible path will 
be '/projects/'.
"""

from django.urls import path
from . import views

urlpatterns = [
    # Maps to '/projects/' (app's root via project inclusion)
    # The empty path '' combines with the project's 'projects/' prefix
    path('', views.projects, name='projects'),
]