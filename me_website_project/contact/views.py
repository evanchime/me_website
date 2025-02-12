from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.urls import reverse

# Create your views here.
def contact(request):
    if not request.user.is_authenticated:
        request.session['contact'] = 'yes'
        return HttpResponseRedirect(reverse('login'))
    else:
        return render(request, 'contact.html')

