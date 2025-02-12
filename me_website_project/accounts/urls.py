from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path("login/", views.login, name="login"),
    path("signup/", views.signup, name="signup"),
    path('password_change/', (views.password_change), name='password_change'),
    path(
        'password_change/done/', 
        auth_views.PasswordChangeDoneView.as_view(
            template_name='registration/password_change_done.html'
        ), 
        name='password_change_done'
    ),
    path('password_reset/', views.password_reset, name='password_reset'),
    path(
        'password_reset/done/', 
        auth_views.PasswordResetDoneView.as_view(
            template_name='registration/password_reset_done.html'
        ), 
        name='password_reset_done'
    ),
    path(
        'reset/<uidb64>/<token>/', 
        views.password_reset_confirm, 
        name='password_reset_confirm'
    ),
    path(
        'reset/done/', 
        auth_views.PasswordResetCompleteView.as_view(
            template_name='registration/password_reset_complete.html'
        ), 
        name='password_reset_complete'
    ),
]