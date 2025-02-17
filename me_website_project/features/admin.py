"""
Django admin configuration for registering models with the 
administration site.

This module imports relevant models from the current application and 
registers them with the Django admin interface. Registration allows 
authorized users to perform CRUD (Create, Read, Update, Delete) 
operations on the models through the admin dashboard.

Registered Models:
    Post: Represents a blog post
    Question: Represents a poll question object
    Choice: Represents an answer choice associated with the poll 
    Question.
"""

from django.contrib import admin
from .models import Post, Question, Choice

# Register models with the default ModelAdmin configurations
# This enables basic admin functionality without customizations
admin.site.register(Post)    
admin.site.register(Question)
admin.site.register(Choice)
