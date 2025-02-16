"""
URL configuration for the about app.

Defines the root endpoint for the about page when included under '/about/' 
in the project's main URLs. The actual accessible path will be '/about/'.
"""

from django.urls import path
from . import views

urlpatterns = [
    # Maps to '/about/' (app's root via project inclusion)
    # The empty path '' combines with the project's 'about/' prefix
    path('', views.about, name='about'),
]