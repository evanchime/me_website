"""
URL configuration for the experience app.

Defines the root endpoint for the experience page when included under 
'/experience/' in the project's main URLs. The actual accessible path 
will be '/experience/'.
"""

from django.urls import path
from . import views

urlpatterns = [
    # Maps to '/experience/' (app's root via project inclusion)
    # The empty path '' combines with the project's 'experience/' prefix
    path('', views.experience, name='experience'),
]