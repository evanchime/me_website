"""
View for handling projects page requests
"""

from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.views.decorators.cache import never_cache

@never_cache
def projects(request):
    """
    Display the projects page. Ensure that no intermediary (like a browser or
    proxy server) caches the response
    
    Args:
        request: HttpRequest object containing session/metadata
    
    Returns:
        HttpResponse: Rendered projects page
    
    """
    return render(request, 'projects.html')
