"""
Views for handling education page requests with authentication checks.
"""

from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.urls import reverse

def education(request):
    """
    Display the education page for authenticated users. Redirects 
    unauthenticated users to login page while preserving the education 
    page request intent.
    
    Args:
        request: HttpRequest object containing session/metadata
    
    Returns:
        HttpResponse: Rendered education page for authenticated users
        HttpResponseRedirect: To login page for unauthenticated users
    
    Behavior:
        - Sets session flag when unauthorized access is attempted
        - Maintains request context through login redirect chain
        - Uses reverse() for URL resolution to avoid hardcoding
    """
    if not request.user.is_authenticated:
        # Flag in session to redirect back to education page after login
        request.session['education'] = 'yes'
        return HttpResponseRedirect(reverse('login'))
    else:
        # Clear session flag if present for clean state
        request.session.pop('education', None)
        return render(request, 'education.html')