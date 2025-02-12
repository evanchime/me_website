from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.urls import reverse

# Create your views here.
def education(request):
    if not request.user.is_authenticated:
        request.session['education'] = 'yes'
        return HttpResponseRedirect(reverse('login'))
    else:
        return render(request, 'education.html')

