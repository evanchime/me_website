"""
View for handling skills page requests
"""

from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.views.decorators.cache import never_cache

@never_cache
def skills(request):
    """
    Display the skills page. Ensure that no intermediary (like a browser or 
    proxy server) caches the response
    
    Args:
        request: HttpRequest object containing session/metadata
    
    Returns:
        HttpResponse: Rendered skills page
    
    """
    return render(request, 'skills.html')
