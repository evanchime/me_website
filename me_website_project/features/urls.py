from django.urls import path
from . import views


urlpatterns = [
    path('blog/', views.blog_index, name='blog_index'),
    path('blog/<int:pk>/', views.blog_detail, name='blog_detail'),
    path('polls/', views.polls_index, name='polls_index'),
    path('polls/<int:question_id>', views.polls_detail, name='polls_detail'),
    path(
        'polls/<int:question_id>/results/', 
        views.polls_results, 
        name='polls_results'
    ),
    path('polls/<int:question_id>/vote/', views.polls_vote, name='polls_vote')
]

