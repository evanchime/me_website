from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.urls import reverse

# Create your views here.
def about(request):
    if not request.user.is_authenticated:
        request.session['about'] = 'yes'
        return HttpResponseRedirect(reverse('login'))
    else:
        return render(request, 'about.html')

