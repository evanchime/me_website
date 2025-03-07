"""
Django view functions for blog and polls features with authentication 
handling.

This module contains view functions that handle HTTP requests for blog 
posts and polls. All views require user authentication, redirecting 
unauthenticated users to the login page while preserving state through 
session variables. Includes full CRUD operations for blog posts and 
complete voting workflow for polls.
"""

from django.shortcuts import get_object_or_404, render
from django.http import HttpResponseRedirect
from django.urls import reverse
from .models import Question, Choice, Post
from django.views.decorators.cache import never_cache


@never_cache
def blog_index(request):
    """Display latest blog posts with authentication check. Ensure that 
    no intermediary (like a browser or proxy server) caches the response
    
    Args:
        request: HttpRequest object
        
    Returns:
        Rendered blog index template with latest 5 posts if 
        authenticated, redirects to login page with session preservation 
        if not authenticated.
        
    Session Variables:
        Sets 'blog_index' flag if unauthenticated
    """
    if not request.user.is_authenticated:
        request.session['blog_index'] = 'yes'
        return HttpResponseRedirect(reverse('login'))
    posts = Post.objects.order_by('-date')[:5]
    return render(request, "features/blog/blog.html", {"object_list": posts})


@never_cache
def blog_detail(request, pk):
    """Show detailed view of individual blog post. Ensure that no 
    intermediary (like a browser or proxy server) caches the response
    
    Args:
        request: HttpRequest object
        pk: Primary key of blog post to display
        
    Returns:
        Rendered blog detail template if authenticated,
        redirects to login while preserving post ID if not.
        
    Session Variables:
        Sets 'blog_detail_id' with post PK if unauthenticated
    """
    if not request.user.is_authenticated:
        request.session['blog_detail_id'] = pk
        return HttpResponseRedirect(reverse('login'))
    post = get_object_or_404(Post, pk=pk)
    return render(request, "features/blog/post.html", {"post": post})


@never_cache
def polls_index(request):
    """Display latest poll questions with authentication check. Ensure 
    that no intermediary (like a browser or proxy server) caches the 
    response
    
    Args:
        request: HttpRequest object
        
    Returns:
        Rendered polls index template with latest 5 questions if 
        authenticated, redirects to login with session preservation if 
        not.
        
    Session Variables:
        Sets 'polls_index' flag if unauthenticated
    """
    if not request.user.is_authenticated:
        request.session['polls_index'] = 'yes'
        return HttpResponseRedirect(reverse('login'))
    latest_question_list = Question.objects.order_by('-pub_date')[:5]
    context = {'latest_question_list': latest_question_list}
    return render(request, "features/polls/poll.html", context)


@never_cache
def polls_detail(request, question_id):
    """Show voting form for specific poll question. Ensure that no 
    intermediary (like a browser or proxy server) caches the response
    
    Args:
        request: HttpRequest object
        question_id: ID of poll question to display
        
    Returns:
        Rendered poll detail template if authenticated,
        redirects to login while preserving question ID if not.
        
    Session Variables:
        Sets 'polls_detail_question_id' if unauthenticated
    """
    if not request.user.is_authenticated: 
        request.session['polls_detail_question_id'] = question_id
        return HttpResponseRedirect(reverse('login'))
    question = get_object_or_404(Question, pk=question_id) 
    return render(request, 'features/polls/detail.html', {'question': question})


@never_cache
def polls_results(request, question_id):
    """Display voting results for specific poll question. Ensure that no 
    intermediary (like a browser or proxy server) caches the response
    
    Args:
        request: HttpRequest object
        question_id: ID of poll question to show results for
        
    Returns:
        Rendered results template if authenticated,
        redirects to login with question ID preservation if not.
        
    Session Variables:
        Sets 'polls_results_question_id' if unauthenticated
    """
    if not request.user.is_authenticated:
        request.session['polls_results_question_id'] = question_id
        return HttpResponseRedirect(reverse('login'))
    question = get_object_or_404(Question, pk=question_id)
    return render(request, 'features/polls/results.html', {'question': question})


@never_cache
def polls_vote(request, question_id):
    """Process voting submissions for poll questions. Ensure that no 
    intermediary (like a browser or proxy server) caches the response
    
    Args:
        request: HttpRequest object containing POST data
        question_id: ID of poll question being voted on
        
    Returns:
        - Redirect to results page after successful vote
        - Re-display voting form with error message if no choice 
        selected
        - Redirect to login if unauthenticated with question ID 
        preservation
        
    Raises:
        KeyError: If no choice selected in POST data
        Choice.DoesNotExist: If invalid choice ID submitted
        
    Session Variables:
        Sets 'polls_vote_question_id' if unauthenticated
    """
    if not request.user.is_authenticated:
        request.session['polls_vote_question_id'] = question_id
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