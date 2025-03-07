"""
Views for handling contact page requests with authentication checks.
"""

from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.views.decorators.cache import never_cache

@never_cache
def contact(request):
    """
    Display the contact page for authenticated users. Redirects 
    unauthenticated users to login page while preserving the contact page 
    request intent. Ensure that no intermediary (like a browser or 
    proxy server) caches the response
    
    Args:
        request: HttpRequest object containing session/metadata
    
    Returns:
        HttpResponse: Rendered contact page for authenticated users
        HttpResponseRedirect: To login page for unauthenticated users
    
    Behavior:
        - Sets session flag when unauthorized access is attempted
        - Maintains request context through login redirect chain
        - Uses reverse() for URL resolution to avoid hardcoding
    """
    if not request.user.is_authenticated:
        # Flag in session to redirect back to contact page after login
        request.session['contact'] = 'yes'
        return HttpResponseRedirect(reverse('login'))
    else:
        # Clear session flag if present for clean state
        request.session.pop('contact', None)
        return render(request, 'contact.html')