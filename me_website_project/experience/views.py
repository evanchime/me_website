from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.urls import reverse

# Create your views here.
def experience(request):
    if not request.user.is_authenticated:
        request.session['experience'] = 'yes'
        return HttpResponseRedirect(reverse('login'))
    else:
        return render(request, 'experience.html')

