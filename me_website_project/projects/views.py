from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.urls import reverse

# Create your views here.
def projects(request):
    if not request.user.is_authenticated:
        request.session['projects'] = 'yes'
        return HttpResponseRedirect(reverse('login'))
    else:
        return render(request, 'projects.html')

