"""
Custom Django forms for user authentication and password management.

Contains extended versions of Django's built-in auth forms with 
additional validation, security features, and HTML5 attributes for 
client-side validation. Includes login, registration, password change, 
and password reset forms.
"""

from django.contrib.auth.forms import (
    AuthenticationForm, UserCreationForm, PasswordChangeForm,
    PasswordResetForm, SetPasswordForm
)
from django import forms
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.core.validators import RegexValidator

User = get_user_model()

# Shared password validation rules
PASSWORD_REGEX = r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}$'
PASSWORD_MESSAGE = (
    "Password must contain 8-20 characters, at least 1 uppercase, "
    "1 lowercase, 1 digit, and 1 special symbol (@$!%*?&)."
)

class LoginForm(AuthenticationForm):
    """
    Custom login form with case-insensitive username and remember me 
    functionality. Extends Django's default AuthenticationForm with additional 
    fields and styling.
    """
    username = forms.CharField(max_length=64)
    password = forms.CharField(widget=forms.PasswordInput)
    remember_me = forms.BooleanField(required=False)

    def clean_username(self):
        username = self.cleaned_data.get('username')
        try:
            # Perform case-insensitive lookup
            user = User.objects.get(username__iexact=username)
        except User.DoesNotExist:
            # Return original username if not found (authentication will fail)
            return username
        else:
            # Return the actual username from database
            return user.username

class SignUpForm(UserCreationForm):
    """
    User registration form with enhanced validation for username format,
    email uniqueness, and password complexity. Requires:
    - Unique username meeting format requirements
    - Unique email address
    - Strong password matching complexity rules
    """
    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')

    def __init__(self, *args, **kwargs):
        """Sets up custom regex validators for username and password 
        fields.
        """
        super().__init__(*args, **kwargs)
        # Add regex validators to fields
        self.fields['password1'].validators.insert(0,
            RegexValidator(regex=PASSWORD_REGEX, message=PASSWORD_MESSAGE)
        )
        self.fields['username'].validators.insert(0,
            RegexValidator(
                regex=r'^(?!.*[-_]{2})[A-Za-z0-9](?!.*[-_]$)[A-Za-z0-9-_]{2,14}[A-Za-z0-9]$',
                message="Username must be 4-16 characters with specific format rules."
            )
        )

    def clean_username(self):
        """Validates username availability and checks against reserved 
        names.
        """
        username = self.cleaned_data.get('username').strip()
        if username.lower() in ['admin', 'root', 'administrator']:
            raise ValidationError("Reserved username. Choose another.")
        if User.objects.filter(username__iexact=username).exists():
            raise ValidationError("Username already exists.")
        return username
        
    def clean_email(self):
        """Ensures email address is not already registered."""
        email = self.cleaned_data.get('email')
        if User.objects.filter(email__iexact=email).exists():
            raise ValidationError("Email address already in use.")
        return email


class MyPasswordChangeForm(PasswordChangeForm):
    """
    Password change form with enhanced security validation. Adds regex 
    pattern validation for new passwords while maintaining Django's 
    default behavior.
    """
    def __init__(self, *args, **kwargs):
        """Adds password complexity validation to the new password 
        field.
        """
        super().__init__(*args, **kwargs)
        self.fields['new_password1'].validators.insert(0,
            RegexValidator(regex=PASSWORD_REGEX, message=PASSWORD_MESSAGE)
        )


class MyPasswordResetForm(PasswordResetForm):
    """
    Custom password reset request form with styled email input field.
    Includes accessibility attributes and bootstrap classes.
    """
    email = forms.EmailField( 
        max_length=254, 
        widget=forms.EmailInput(attrs={ 
            'class': 'form-control w-auto', 
            'required': 'required',
            'id': 'inputEmail',
            'aria-describedby': 'emailHelpInline'
        }) 
    )


class MyPasswordResetConfirmForm(SetPasswordForm):
    """
    Password reset confirmation form with HTML5 validation attributes.
    Implements client-side validation patterns while maintaining 
    server-side checks.
    """
    def __init__(self, *args, **kwargs):
        """Configures password input fields with validation attributes.
        """
        super().__init__(*args, **kwargs)
        
        self.fields['new_password1'].widget.attrs.update({
            'class': 'form-control',
            'minlength': '8',
            'maxlength': '20',
            'title': PASSWORD_MESSAGE,
            'pattern': PASSWORD_REGEX
        })
        
        self.fields['new_password2'].widget.attrs.update({
            'class': 'form-control',
            'minlength': '8',
            'maxlength': '20',
            'title': 'Re-enter your new password'
        })
        
        self.fields['new_password1'].validators.insert(0,
            RegexValidator(regex=PASSWORD_REGEX, message=PASSWORD_MESSAGE)
        )
