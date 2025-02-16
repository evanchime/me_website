"""
URL configuration for the contact app.

Defines the root endpoint for the contact page when included under 
'/contact/' in the project's main URLs. The actual accessible path will 
be '/contact/'.
"""

from django.urls import path
from . import views

urlpatterns = [
    # Maps to '/contact/' (app's root via project inclusion)
    # The empty path '' combines with the project's 'contact/' prefix
    path('', views.contact, name='contact'),
]