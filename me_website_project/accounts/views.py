from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib.auth import (
    authenticate, login as auth_login, update_session_auth_hash
)
from django.urls import reverse
from .forms import (
    LoginForm, 
    SignUpForm, 
    MyPasswordChangeForm, 
    MyPasswordResetForm,
    MyPasswordResetConfirmForm
)
from django.http import HttpResponseRedirect
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.auth import get_user_model


def login(request):
    """
    Handle user login authentication and session management.
    
    Processes login form submissions, authenticates users, manages 
    session expiration based on 'remember me' selection, and redirects 
    to protected pages users tried to access before logging in.
    
    Uses LoginForm for validation and implements Post/Redirect/Get 
    pattern to prevent duplicate form submissions.
    """
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            remember_me = form.cleaned_data.get('remember_me', False)
            user = authenticate(request, username=username, password=password)
            if user is not None:
                auth_login(request, user)
                request.session.set_expiry(1209600 if remember_me else 0)
                request.session.modified = True
                # Redirect to blog page the user was trying to access
                if request.session.pop('blog_index', None):
                    return redirect('blog_index')
                # Redirect to blog page the user was trying to access
                elif request.session.get('blog_detail_id', None):
                    pk = request.session.pop('blog_detail_id', None)
                    return redirect('blog_detail', args=(pk,))
                # Redirect to polls page the user was trying to access
                elif request.session.pop('polls_index', None):
                    return redirect('polls_index')
                # Redirect to polls page the user was trying to access
                elif request.session.get('polls_detail_question_id', None):
                    question_id = request.session.pop(
                        'polls_detail_question_id', None
                    ) 
                    return redirect('polls_detail', args=(question_id,))
                # Redirect to polls page the user was trying to access
                elif request.session.get('polls_results_question_id', None):
                    question_id = request.session.pop(
                        'polls_results_question_id', None
                    )
                    return redirect('polls_results', args=(question_id,))
                # Redirect to polls page the user was trying to access
                elif request.session.get('polls_vote_question_id', None):
                    question_id = request.session.pop(
                        'polls_vote_question_id', None
                    )
                    return redirect('polls_results', args=(question_id,))
                else: # Redirect to home page
                    return redirect('home')
            else:
                form.add_error(None, 'Invalid username and/or password.')
        
        # Save form data and errors for Post/Redirect/Get pattern
        request.session['login_form_data'] = request.POST
        request.session['login_form_errors'] = form.errors
        return redirect(reverse("login"))
    else:
        form_data = request.session.pop('login_form_data', None)
        form_errors = request.session.pop('login_form_errors', None)
        
        form = LoginForm(form_data) if form_data else LoginForm()
        if form_errors:
            form._errors = form_errors

        return render(
            request, 
            'registration/login.html', 
            {'form': form, 'user': request.user}
        )


def signup(request):
    """
    Handle new user registration process.
    
    Validates user registration data using SignUpForm, saves new users,
    and redirects to login page on success. Implements Post/Redirect/Get
    pattern to maintain form state between submissions.
    """
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            form.save()
            return HttpResponseRedirect(reverse("login"))
        else:
            # For Post / Redirect / Get pattern
            request.session['signup_form_data'] = request.POST
            request.session['signup_form_errors'] = form.errors
            return HttpResponseRedirect(reverse("signup"))
    
    # For Post / Redirect / Get pattern
    form_data = request.session.pop('signup_form_data', None)
    form_errors = request.session.pop('signup_form_errors', None)

    if form_data:
        form = SignUpForm(form_data)
        if form_errors:
            form._errors = form_errors
    else:
        form = SignUpForm()

    return render(request, 'registration/signup.html', {'form': form})


@login_required
def password_change(request):
    """
    Handle password changes for authenticated users.
    
    Requires login, validates password change form, updates user password,
    and maintains session authentication. Uses MyPasswordChangeForm for
    validation and implements Post/Redirect/Get pattern.
    """
    if request.method == 'POST':
        form = MyPasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            form.save()  # Save the new password
            # Update the session auth hash to prevent logout
            update_session_auth_hash(request, form.user)
            return HttpResponseRedirect(reverse("password_change_done"))
        else:
            # For Post / Redirect / Get pattern
            request.session['password_change_form_data'] = request.POST
            request.session['password_change_form_errors'] = form.errors
            return HttpResponseRedirect(reverse("password_change"))
    
    # For Post / Redirect / Get pattern
    form_data = request.session.pop('password_change_form_data', None)
    form_errors = request.session.pop('password_change_form_errors', None)

    if form_data:
        form = MyPasswordChangeForm(request.user, form_data)
        if form_errors:
            form._errors = form_errors
    else:
        form = MyPasswordChangeForm(user=request.user)

    return render(
        request, 'registration/password_change_form.html', {'form': form}
    )


def password_reset(request):
    """
    Initiate password reset process via email.
    
    Validates email address using MyPasswordResetForm, sends password reset
    email, and redirects to confirmation page. Implements Post/Redirect/Get
    pattern to maintain form state between submissions.
    """
    if request.method == 'POST':
        form = MyPasswordResetForm(request.POST)
        if form.is_valid():
            form.save(
                request=request,  # Pass the request object
                use_https=request.is_secure(),
            )
            return HttpResponseRedirect(reverse("password_reset_done"))
        else:
            request.session['password_reset_form_data'] = request.POST
            request.session['password_reset_form_errors'] = form.errors
            return HttpResponseRedirect(reverse("password_reset"))
    
    form_data = request.session.pop('password_reset_form_data', None)
    form_errors = request.session.pop('password_reset_form_errors', None)

    if form_data:
        form = MyPasswordResetForm(form_data)
        if form_errors:
            form._errors = form_errors
    else:
        form = MyPasswordResetForm()

    return render(
        request, 'registration/password_reset_form.html', {'form': form}
    )


User = get_user_model()

def password_reset_confirm(request, uidb64, token):
    """
    Finalize password reset process with token validation.
    
    Decodes user ID from URL, validates reset token, and processes password
    reset confirmation form. Uses MyPasswordResetConfirmForm for validation
    and implements Post/Redirect/Get pattern.
    """
    try:
        # Decode the uidb64 to get the user id
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)  # Get the user from database
    except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
        user = None
        print(f"Error decoding uidb64: {e}")

    # Check if the user exists and the token is valid
    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            form = MyPasswordResetConfirmForm(user, request.POST)
            if form.is_valid():
                form.save()
                return redirect(reverse('password_reset_complete'))
            else:
                request.session[
                    'password_reset_confirm_form_data'
                ] = request.POST
                request.session[
                    'password_reset_confirm_form_errors'
                ] = form.errors
                return redirect(
                    reverse('password_reset_confirm', args=[uidb64, token])
                )
        else:
            form_data = request.session.pop(
                'password_reset_confirm_form_data', None
            )
            form_errors = request.session.pop(
                'password_reset_confirm_form_errors', None
            )
            if form_data:
                form = MyPasswordResetConfirmForm(user, form_data)
                if form_errors:
                    form._errors = form_errors
            else:
                form = MyPasswordResetConfirmForm(user)
    else:
        # Provide a default form when user is None
        form = MyPasswordResetConfirmForm(user=None) 

    return render(
        request, 'registration/password_reset_confirm.html', {'form': form}
    )
