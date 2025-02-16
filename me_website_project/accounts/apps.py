"""
Django application configuration for the accounts app.

Defines settings and metadata for the accounts application within a Django project.
"""

from django.apps import AppConfig

class AccountsConfig(AppConfig):
    """
    Configuration class for the accounts application.
    
    Provides default settings and initialization for the Django accounts app.
    """
    
    # Set default primary key field type for models
    default_auto_field = 'django.db.models.BigAutoField'
    
    # Name of the application as defined in the project's settings
    name = 'accounts'