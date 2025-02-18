"""
Views for handling skills page requests with authentication checks.
"""

from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.urls import reverse

def skills(request):
    """
    Display the skills page for authenticated users. Redirects 
    unauthenticated users to login page while preserving the skills page 
    request intent.
    
    Args:
        request: HttpRequest object containing session/metadata
    
    Returns:
        HttpResponse: Rendered skills page for authenticated users
        HttpResponseRedirect: To login page for unauthenticated users
    
    Behavior:
        - Sets session flag when unauthorized access is attempted
        - Maintains request context through login redirect chain
        - Uses reverse() for URL resolution to avoid hardcoding
    """
    if not request.user.is_authenticated:
        # Flag in session to redirect back to skills page after login
        request.session['skills'] = 'yes'
        return HttpResponseRedirect(reverse('login'))
    else:
        # Clear session flag if present for clean state
        request.session.pop('skills', None)
        return render(request, 'skills.html')