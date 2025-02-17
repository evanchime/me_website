"""
URL configuration for the education app.

Defines the root endpoint for the education page when included under 
'/education/' in the project's main URLs. The actual accessible path 
will be '/education/'.
"""

from django.urls import path
from . import views

urlpatterns = [
    # Maps to '/education/' (app's root via project inclusion)
    # The empty path '' combines with the project's 'education/' prefix
    path('', views.education, name='education'),
]