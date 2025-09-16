"""
Django view functions for blog and polls features with authentication 
handling.

This module contains view functions that handle HTTP requests for blog 
posts and polls. All views require user authentication, redirecting 
unauthenticated users to the login page while preserving the exact URL 
they were trying to access in the session.
"""

from django.shortcuts import get_object_or_404, render
from django.http import HttpResponseRedirect
from django.urls import reverse
from .models import Question, Choice, Post
from django.views.decorators.cache import never_cache


@never_cache
def blog_index(request ):
    """
    Display latest blog posts. If unauthenticated, redirects to login
    and saves the intended destination in the session.
    """
    if not request.user.is_authenticated:
        request.session['intended_destination'] = reverse('blog_index')
        return HttpResponseRedirect(reverse('login'))
        
    posts = Post.objects.order_by('-date')[:5]
    return render(request, "features/blog/blog.html", {"object_list": posts})


@never_cache
def blog_detail(request, pk):
    """
    Show detailed view of a blog post. If unauthenticated, redirects to
    login and saves the intended destination in the session.
    """
    if not request.user.is_authenticated:
        request.session['intended_destination'] = reverse(
            'blog_detail', args=[pk]
        )
        return HttpResponseRedirect(reverse('login'))
        
    post = get_object_or_404(Post, pk=pk)
    return render(request, "features/blog/post.html", {"post": post})


@never_cache
def polls_index(request):
    """
    Display latest poll questions. If unauthenticated, redirects to login
    and saves the intended destination in the session.
    """
    if not request.user.is_authenticated:
        request.session['intended_destination'] = reverse('polls_index')
        return HttpResponseRedirect(reverse('login'))

    latest_question_list = (
        Question.objects.order_by('-pub_date')
        .prefetch_related('choice_set')[:5]
    )
    context = {'latest_question_list': latest_question_list}
    return render(request, "features/polls/poll.html", context)


@never_cache
def polls_detail(request, question_id):
    """
    Show voting form for a poll. If unauthenticated, redirects to login
    and saves the intended destination in the session.
    """
    if not request.user.is_authenticated: 
        request.session['intended_destination'] = reverse(
            'polls_detail', args=[question_id]
        )
        return HttpResponseRedirect(reverse('login'))
        
    question = get_object_or_404(Question, pk=question_id) 
    return render(request, 'features/polls/detail.html', {'question': question})


@never_cache
def polls_results(request, question_id):
    """
    Display voting results for a poll. If unauthenticated, redirects to
    login and saves the intended destination in the session.
    """
    if not request.user.is_authenticated:
        request.session['intended_destination'] = reverse(
            'polls_results', args=[question_id]
        )
        return HttpResponseRedirect(reverse('login'))
        
    question = get_object_or_404(
        Question.objects.prefetch_related('choice_set'), 
        pk=question_id
    )
    return render(
        request, 
        'features/polls/results.html', 
        {'question': question}
    )


@never_cache
def polls_vote(request, question_id):
    """
    Process a vote submission. If unauthenticated, redirects to login
    and saves the intended destination in the session.
    """
    if not request.user.is_authenticated:
        request.session['intended_destination'] = reverse(
            'polls_results', args=[question_id]
        )
        return HttpResponseRedirect(reverse('login'))
        
    question = get_object_or_404(Question, pk=question_id)
    try:
        selected_choice = question.choice_set.get(pk=request.POST['choice'])
    except (KeyError, Choice.DoesNotExist):
        return render(request, 'features/polls/detail.html', {
            'question': question,
            'error_message': "You didn't select a choice."
        })
    selected_choice.votes += 1
    selected_choice.save()
    return HttpResponseRedirect(reverse('polls_results', args=(question_id,)))
