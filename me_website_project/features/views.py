from django.shortcuts import get_object_or_404, render
from django.http import HttpResponseRedirect
from django.urls import reverse
from .models import Question, Choice, Post

# Create your views here.

def blog_index(request):
    if not request.user.is_authenticated:
        request.session['blog_index'] = 'yes'
        return HttpResponseRedirect(reverse('login'))
    posts = Post.objects.order_by('-date')[:5]
    return render(request, "features/blog/blog.html", {"object_list": posts})

def blog_detail(request, pk):
    if not request.user.is_authenticated:
        request.session['blog_detail_id'] = pk
        return HttpResponseRedirect(reverse('login'))
    post = get_object_or_404(Post, pk=pk)
    return render(request, "features/blog/post.html", {"post": post})

def polls_index(request):
    if not request.user.is_authenticated:
        request.session['polls_index'] = 'yes'
        return HttpResponseRedirect(reverse('login'))
    latest_question_list = Question.objects.order_by('-pub_date')[:5]
    context = {'latest_question_list': latest_question_list}
    return render(request, "features/polls/poll.html", context)

def polls_detail(request, question_id): 
    if not request.user.is_authenticated: 
        # If user is not authenticated, but is about to vote, send them 
        # to the login page, after saving the question_id
        request.session['polls_detail_question_id'] = question_id
        return HttpResponseRedirect(reverse('login'))
    question = get_object_or_404(Question, pk=question_id) 
    return render(
        request, 'features/polls/detail.html', {'question': question}
    )

def polls_results(request, question_id):
    if not request.user.is_authenticated:
        request.session['polls_results_question_id'] = question_id
        return HttpResponseRedirect(reverse('login'))
    question = get_object_or_404(Question, pk=question_id)
    return render(
        request, 'features/polls/results.html', {'question': question}
    )

def polls_vote(request, question_id):
    if not request.user.is_authenticated:
        request.session['polls_vote_question_id'] = question_id
        return HttpResponseRedirect(reverse('login'))
    question = get_object_or_404(Question, pk=question_id)
    try:
        selected_choice = question.choice_set.get(
            pk=request.POST['choice']
        )
    except (KeyError, Choice.DoesNotExist):
        # Redisplay the question voting form
        return render(request, 'features/polls/detail.html', {
                'question': question,
                'error_message': "You didn't select a choice."
            }
        )
    else:
        selected_choice.votes += 1
        selected_choice.save()
        # Always return an HttpResponseRedirect after successfully
        # dealing with POST data. This prevents data from being
        # posted twice if a
        # user hits the Back button.
        return HttpResponseRedirect(
            reverse('polls_results', args=(question_id,))
        )
