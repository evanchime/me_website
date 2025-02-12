from django.contrib.auth.forms import (
    AuthenticationForm, UserCreationForm, PasswordChangeForm,
    PasswordResetForm, SetPasswordForm
)
from django import forms
from django.contrib.auth.models import User
# from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

class LoginForm(AuthenticationForm):
    username = forms.CharField(max_length=64)
    password = forms.CharField(widget=forms.PasswordInput)
    remember_me = forms.BooleanField(required=False)


class SignUpForm(UserCreationForm):
    '''Form for signing up new users'''
    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')


    def clean_password1(self):
        '''Check if password meets the requirements'''
        password = self.cleaned_data.get('password1')

        if not any(c.isdigit() for c in password):
            raise forms.ValidationError(
                "Password must contain at least one digit."
            )
        if not any(c.islower() for c in password):
            raise forms.ValidationError(
                "Password must contain at least one lowercase letter."
            )
        if not any(c.isupper() for c in password):
            raise forms.ValidationError(
                "Password must contain at least one uppercase letter."
            )
        if not any(c in "@$!%*?&" for c in password):
            raise forms.ValidationError(
                "Password must contain at least "
                "one special character (@$!%*?&)."
            )

        return password
        

    def clean_password2(self):
        '''Check if the passwords match'''
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')

        if password1 and password2 and password1 != password2:
            raise ValidationError(_
                ("The passwords don't match. Please try again"), 
                code='password_mismatch'
            )

        return password2
    
    
    def clean_email(self):
        '''Check if the email is already in use'''
        email = self.cleaned_data.get('email')
        # Check if the email is already in use
        if User.objects.filter(email=email).exists():
            raise ValidationError(_
                ("A user with this email address already exists."), 
                code='email_in_use'
            )
        return email


class MyPasswordChangeForm(PasswordChangeForm):
    '''Form for changing the password'''
    old_password = forms.CharField(widget=forms.PasswordInput())
    new_password1 = forms.CharField(widget=forms.PasswordInput())
    new_password2 = forms.CharField(widget=forms.PasswordInput())

    # Check passwords match
    def clean_new_password2(self):
        password1 = self.cleaned_data.get('new_password1')
        password2 = self.cleaned_data.get('new_password2')

        if password1 and password2 and password1 != password2:
            raise ValidationError(_
                ("The passwords don't match. Please try again"), 
                code='password_mismatch'
            )

        return password2


    # Check old password is correct
    def clean_old_password(self):
        old_password = self.cleaned_data.get('old_password')
        # Check if the old password is correct
        if not self.user.check_password(old_password):
            raise ValidationError(_
                (
                    "Your old password was entered incorrectly. " 
                    "Please enter it again."
                ), 
                code='password_incorrect'
            )
        return old_password
    

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
    '''Form to enter the new password'''
    new_password1 = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                'class': 'form-control',
                'required': 'required',
                'id': 'inputNewPassword',
                'minlength': 8,
                'maxlength': 20,
                'title': ( 
                    'Only alphanumeric characters (letters and numbers) ' 
                    'are allowed' 
                ),
                'aria-describedby': 'newPasswordHelpInline',
                'pattern': (
                    "(?=.*\d)(?=.*[a-z])(?=.*[A-Z])"
                    "(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}"
                )
            }
        ),
    )
    new_password2 = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                'class': 'form-control',
                'required': 'required',
                'id': 'inputConfirmPassword',
                'minlength': 8,
                'maxlength': 20,
                'title': 'Re-enter your new password',
                'aria-describedby': 'newConfirmPasswordHelpInline',
                'pattern': (
                    "(?=.*\d)(?=.*[a-z])(?=.*[A-Z])"
                    "(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}"
                )
            }
        ),
    )

    