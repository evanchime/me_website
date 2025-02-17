"""
Views for handling about page requests with authentication checks.
"""

from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.urls import reverse

def about(request):
    """
    Display the about page for authenticated users. Redirects 
    unauthenticated users to login page while preserving the about page 
    request intent.
    
    Args:
        request: HttpRequest object containing session/metadata
    
    Returns:
        HttpResponse: Rendered about page for authenticated users
        HttpResponseRedirect: To login page for unauthenticated users
    
    Behavior:
        - Sets session flag when unauthorized access is attempted
        - Maintains request context through login redirect chain
        - Uses reverse() for URL resolution to avoid hardcoding
    """
    if not request.user.is_authenticated:
        # Flag in session to redirect back to about page after login
        request.session['about'] = 'yes'
        return HttpResponseRedirect(reverse('login'))
    else:
        # Clear session flag if present for clean state
        request.session.pop('about', None)
        return render(request, 'about.html')