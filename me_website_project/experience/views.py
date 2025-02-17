"""
Views for handling experience page requests with authentication checks.
"""

from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.urls import reverse

def experience(request):
    """
    Display the experience page for authenticated users. Redirects 
    unauthenticated users to login page while preserving the experience 
    page request intent.
    
    Args:
        request: HttpRequest object containing session/metadata
    
    Returns:
        HttpResponse: Rendered experience page for authenticated users
        HttpResponseRedirect: To login page for unauthenticated users
    
    Behavior:
        - Sets session flag when unauthorized access is attempted
        - Maintains request context through login redirect chain
        - Uses reverse() for URL resolution to avoid hardcoding
    """
    if not request.user.is_authenticated:
        # Flag in session to redirect back to experience page after 
        # login
        request.session['experience'] = 'yes'
        return HttpResponseRedirect(reverse('login'))
    else:
        # Clear session flag if present for clean state
        request.session.pop('experience', None)
        return render(request, 'experience.html')