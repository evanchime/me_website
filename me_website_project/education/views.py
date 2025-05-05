"""
View for handling education page requests
"""

from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.views.decorators.cache import never_cache

@never_cache
def education(request):
    """
    Display the education page. Ensure that no intermediary (like a browser or 
    proxy server) caches the response
    
    
    Args:
        request: HttpRequest object containing session/metadata
    
    Returns:
        HttpResponse: Rendered education page 
    
    """
    return render(request, 'education.html')
