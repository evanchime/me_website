"""
Pytest configuration file.

This file configures pytest for Django testing.
"""

import os
import sys
import django

# Add the project root directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'me_website_project')))

# Setup Django
def pytest_configure():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'me_website_project.settings_test')
    django.setup()