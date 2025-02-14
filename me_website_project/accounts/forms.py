from django.contrib.auth.forms import (
    AuthenticationForm, UserCreationForm, PasswordChangeForm,
    PasswordResetForm, SetPasswordForm
)
from django import forms
from django.contrib.auth.models import User
# from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.core.validators import RegexValidator

# Centralized regex and message for password validation
PASSWORD_REGEX = r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}$'
PASSWORD_MESSAGE = (
    "Password must contain 8-20 characters, at least 1 uppercase, "
    "1 lowercase, 1 digit, and 1 special symbol (@$!%*?&)."
)

class LoginForm(AuthenticationForm):
    username = forms.CharField(max_length=64)
    password = forms.CharField(widget=forms.PasswordInput)
    remember_me = forms.BooleanField(required=False)


class SignUpForm(UserCreationForm):
    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Password validation will run first
        self.fields['password1'].validators.insert(0,
            RegexValidator(
                regex=PASSWORD_REGEX,
                message=PASSWORD_MESSAGE
            )
        )

        # Username validation will run first
        self.fields['username'].validators.insert(0,
            RegexValidator(
                regex=r'^(?!.*[-_]{2})[A-Za-z0-9](?!.*[-_]$)[A-Za-z0-9-_]{2,14}[A-Za-z0-9]$',               
                message=(
                    "Username must be 4-16 characters long, "
                    "start and end with an alphanumeric character, "
                    "and only contain alphanumeric characters, "
                    "hyphens, and underscores."
                )
            )
        )


    def clean_username(self):
        username = self.cleaned_data.get('username').strip()
        reserved = ['admin', 'root', 'administrator']
        if username.lower() in reserved:
            raise ValidationError("Reserved username. Choose another.")
        # Optional: Case-insensitive uniqueness check
        if User.objects.filter(username__iexact=username).exists():
            raise ValidationError("Username already exists.")
        return username
        

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email__iexact=email).exists():
            raise ValidationError(
                "A user with this email address already exists."
            )
        return email


class MyPasswordChangeForm(PasswordChangeForm):
    '''Form for changing the password with custom validation'''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add regex validation for the new password to run first
        self.fields['new_password1'].validators.insert(0,
            RegexValidator(
                regex=PASSWORD_REGEX,
                message=PASSWORD_MESSAGE
            )
        )
    

class MyPasswordResetForm(PasswordResetForm): 
    '''Form to enter the email for the password reset link'''
    email = forms.EmailField( 
        max_length=254, 
        widget=forms.EmailInput(attrs={ 
            'class': 'form-control w-auto', 
            'required': 'required',
            'id': 'inputEmail',
            'aria-describedby': 'emailHelpInline'
            }
        ) 
    )
    

class MyPasswordResetConfirmForm(SetPasswordForm):
    '''Form to set new password with enhanced validation'''
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Update widget attributes for new_password1
        self.fields['new_password1'].widget.attrs.update({
            'class': 'form-control',
            'id': 'inputNewPassword',
            'minlength': '8',
            'maxlength': '20',
            'title': PASSWORD_MESSAGE,
            'aria-describedby': 'newPasswordHelpInline',
            'pattern': PASSWORD_REGEX
        })
        
        # Update widget attributes for new_password2
        self.fields['new_password2'].widget.attrs.update({
            'class': 'form-control',
            'id': 'inputConfirmPassword',
            'minlength': '8',
            'maxlength': '20',
            'title': 'Re-enter your new password',
            'aria-describedby': 'newConfirmPasswordHelpInline',
        })
        
        # Add server-side validation for new_password1 to run first
        self.fields['new_password1'].validators.insert(0,
            RegexValidator(
                regex=PASSWORD_REGEX,
                message=PASSWORD_MESSAGE
            )
        )

    