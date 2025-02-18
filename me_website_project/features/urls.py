"""
URL configuration for the features app, defining routes for blog and 
polls features.

This module maps URL patterns to corresponding view functions, allowing 
navigation between different pages of the blog and polls features. 
The patterns include parameter capturing for dynamic resource handling.

URL Patterns:
    blog/ 
        - Route: 'blog/'
        - View: blog_index
        - Name: 'blog_index'
        - Description: Displays the main blog page listing all blog 
        posts.
    blog/<int:pk>/ 
        - Route: 'blog/<int:pk>/'
        - View: blog_detail
        - Name: 'blog_detail'
        - Description: Shows detailed view of a single blog post 
        identified by its primary key (pk).

    polls/ 
        - Route: 'polls/'
        - View: polls_index
        - Name: 'polls_index'
        - Description: Renders the main polls page listing all available 
        questions.

    polls/<int:question_id> 
        - Route: 'polls/<int:question_id>'
        - View: polls_detail
        - Name: 'polls_detail'
        - Description: Displays details for a specific poll question 
        identified by question_id.

    polls/<int:question_id>/results/ 
        - Route: 'polls/<int:question_id>/results/'
        - View: polls_results
        - Name: 'polls_results'
        - Description: Shows results for a specific poll question 
        identified by question_id.

    polls/<int:question_id>/vote/ 
        - Route: 'polls/<int:question_id>/vote/'
        - View: polls_vote
        - Name: 'polls_vote'
        - Description: Handles voting submissions for a specific poll 
        question identified by question_id.
"""

from django.urls import path
from . import views


urlpatterns = [
    path('blog/', views.blog_index, name='blog_index'),
    path('blog/<int:pk>/', views.blog_detail, name='blog_detail'),
    path('polls/', views.polls_index, name='polls_index'),
    path(
        'polls/<int:question_id>', 
        views.polls_detail, 
        name='polls_detail'
    ),
    path(
        'polls/<int:question_id>/results/', 
        views.polls_results, 
        name='polls_results'
    ),
    path(
        'polls/<int:question_id>/vote/', 
        views.polls_vote, 
        name='polls_vote'
    )
]