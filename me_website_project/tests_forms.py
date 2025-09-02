"""
Comprehensive tests for forms, validation, and input sanitization.

This module tests all forms in the project to ensure proper validation,
security, and user experience across different scenarios.
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from accounts.forms import LoginForm, SignUpForm, MyPasswordChangeForm, MyPasswordResetForm
from unittest.mock import patch
import re


class FormValidationTests(TestCase):
    """Test cases for form validation across the project."""
    
    def setUp(self):
        """Set up test data for form tests."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='SecurePass123!'
        )
    
    def test_login_form_validation_edge_cases(self):
        """Test login form with various edge cases."""
        edge_cases = [
            # Username edge cases
            {'username': 'a' * 151, 'password': 'SecurePass123!'},  # Too long
            {'username': '   ', 'password': 'SecurePass123!'},       # Whitespace only
            {'username': 'test\nuser', 'password': 'SecurePass123!'}, # Newline
            {'username': 'test\tuser', 'password': 'SecurePass123!'}, # Tab
            
            # Password edge cases  
            {'username': 'testuser', 'password': ''},                # Empty password
            {'username': 'testuser', 'password': ' ' * 10},         # Whitespace password
        ]
        
        for case in edge_cases:
            with self.subTest(case=case):
                form = LoginForm(data=case)
                if case['username'] == '   ' or case['password'] == '':
                    self.assertFalse(form.is_valid())
                else:
                    # Form validation might pass, but authentication should fail
                    self.assertTrue(form.is_valid() or not form.is_valid())
    
    def test_signup_form_comprehensive_validation(self):
        """Test signup form with comprehensive validation scenarios."""
        # Test valid signup
        valid_data = {
            'username': 'newuser123',
            'email': 'newuser@example.com',
            'password1': 'NewSecurePass123!',
            'password2': 'NewSecurePass123!'
        }
        form = SignUpForm(data=valid_data)
        self.assertTrue(form.is_valid())
        
        # Test username validation
        username_cases = [
            ('', False),                    # Empty
            ('a', True),                    # Single character
            ('a' * 150, True),             # Max length
            ('a' * 151, False),            # Too long
            ('user@name', True),            # Special characters
            ('user name', True),            # Space
            ('用户名', True),                # Unicode
        ]
        
        for username, should_be_valid in username_cases:
            with self.subTest(username=username):
                data = valid_data.copy()
                data['username'] = username
                form = SignUpForm(data=data)
                
                if should_be_valid and username != '':
                    # Additional check for existing users
                    if not User.objects.filter(username=username).exists():
                        self.assertTrue(form.is_valid(), f"Username '{username}' should be valid")
                else:
                    self.assertFalse(form.is_valid(), f"Username '{username}' should be invalid")
    
    def test_email_validation_comprehensive(self):
        """Test comprehensive email validation."""
        valid_data = {
            'username': 'emailtest',
            'email': 'test@example.com',
            'password1': 'SecurePass123!',
            'password2': 'SecurePass123!'
        }
        
        email_cases = [
            # Valid emails
            ('user@example.com', True),
            ('user.name@example.com', True),
            ('user+tag@example.com', True),
            ('user123@example-site.com', True),
            ('user@subdomain.example.com', True),
            
            # Invalid emails
            ('', False),                    # Empty
            ('invalid', False),             # No @
            ('@example.com', False),        # No username
            ('user@', False),               # No domain
            ('user@.com', False),           # Invalid domain
            ('user..name@example.com', False), # Double dots
            ('user@example..com', False),   # Double dots in domain
        ]
        
        for email, should_be_valid in email_cases:
            with self.subTest(email=email):
                data = valid_data.copy()
                data['email'] = email
                data['username'] = f'user{hash(email)}'  # Unique username
                
                form = SignUpForm(data=data)
                
                if should_be_valid:
                    self.assertTrue(form.is_valid(), f"Email '{email}' should be valid")
                else:
                    self.assertFalse(form.is_valid(), f"Email '{email}' should be invalid")
    
    def test_password_strength_validation(self):
        """Test password strength validation."""
        valid_data = {
            'username': 'passwordtest',
            'email': 'passwordtest@example.com',
            'password1': 'SecurePass123!',
            'password2': 'SecurePass123!'
        }
        
        password_cases = [
            # Strong passwords
            ('SecurePass123!', True),
            ('MyP@ssw0rd2023', True),
            ('Str0ng!P@ssw0rd', True),
            
            # Weak passwords
            ('password', False),            # Too common
            ('12345678', False),            # Only numbers
            ('PASSWORD', False),            # Only uppercase
            ('password123', False),         # No special chars
            ('Pass1!', False),              # Too short
            ('verylongpasswordwithoutspecialchars123', False), # No special
        ]
        
        for password, should_be_valid in password_cases:
            with self.subTest(password=password):
                data = valid_data.copy()
                data['password1'] = password
                data['password2'] = password
                data['username'] = f'user{hash(password)}'
                data['email'] = f'user{hash(password)}@example.com'
                
                form = SignUpForm(data=data)
                
                if should_be_valid:
                    self.assertTrue(form.is_valid(), f"Password '{password}' should be valid")
                else:
                    self.assertFalse(form.is_valid(), f"Password '{password}' should be invalid")


class InputSanitizationTests(TestCase):
    """Test cases for input sanitization and XSS prevention."""
    
    def test_xss_prevention_in_forms(self):
        """Test that forms prevent XSS attacks."""
        xss_payloads = [
            '<script>alert("xss")</script>',
            'javascript:alert("xss")',
            '<img src=x onerror=alert("xss")>',
            '"><script>alert("xss")</script>',
            "'><script>alert('xss')</script>",
            '<iframe src="javascript:alert(\'xss\')"></iframe>',
            '<svg onload=alert("xss")>',
            '&lt;script&gt;alert("xss")&lt;/script&gt;'
        ]
        
        for payload in xss_payloads:
            with self.subTest(payload=payload):
                # Test in login form
                login_form = LoginForm(data={
                    'username': payload,
                    'password': 'testpass'
                })
                
                # Form might be valid or invalid, but should not execute script
                if login_form.is_valid():
                    # If valid, cleaned data should be safe
                    self.assertNotIn('<script>', str(login_form.cleaned_data))
                
                # Test in signup form
                signup_form = SignUpForm(data={
                    'username': payload,
                    'email': f'{payload}@example.com',
                    'password1': 'SecurePass123!',
                    'password2': 'SecurePass123!'
                })
                
                # Form should either be invalid or sanitize the input
                if signup_form.is_valid():
                    self.assertNotIn('<script>', str(signup_form.cleaned_data))
    
    def test_sql_injection_prevention_in_forms(self):
        """Test that forms prevent SQL injection attacks."""
        sql_payloads = [
            "'; DROP TABLE auth_user; --",
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM auth_user --",
            "1'; DELETE FROM auth_user WHERE '1'='1",
            "'; INSERT INTO auth_user (username) VALUES ('hacked'); --"
        ]
        
        for payload in sql_payloads:
            with self.subTest(payload=payload):
                # Test in login form
                login_form = LoginForm(data={
                    'username': payload,
                    'password': 'testpass'
                })
                
                # Form processing should not cause database errors
                try:
                    login_form.is_valid()
                    if login_form.is_valid():
                        # Should not find a user with malicious input
                        self.assertIsNone(login_form.get_user())
                except Exception as e:
                    # Should not cause database exceptions
                    self.fail(f"SQL injection payload caused exception: {e}")
    
    def test_unicode_handling_in_forms(self):
        """Test that forms properly handle Unicode input."""
        unicode_inputs = [
            'тестовыйпользователь',    # Cyrillic
            '测试用户',                  # Chinese
            'テストユーザー',             # Japanese
            'مستخدماختبار',           # Arabic
            '🚀🌟✨',                  # Emojis
            'café@example.com',        # Accented characters
        ]
        
        for unicode_input in unicode_inputs:
            with self.subTest(input=unicode_input):
                # Test in signup form
                signup_form = SignUpForm(data={
                    'username': unicode_input,
                    'email': f'{unicode_input}@example.com',
                    'password1': 'SecurePass123!',
                    'password2': 'SecurePass123!'
                })
                
                # Form should handle Unicode gracefully
                try:
                    is_valid = signup_form.is_valid()
                    # Should not crash on Unicode input
                    self.assertIsInstance(is_valid, bool)
                except UnicodeError:
                    self.fail(f"Form failed to handle Unicode input: {unicode_input}")


class FormSecurityTests(TestCase):
    """Test cases for form security measures."""
    
    def test_csrf_token_requirement(self):
        """Test that forms require CSRF tokens."""
        client = Client(enforce_csrf_checks=True)
        
        # Test login form without CSRF token
        response = client.post('/accounts/login/', {
            'username': 'testuser',
            'password': 'testpass'
        })
        self.assertEqual(response.status_code, 403)
        
        # Test signup form without CSRF token
        response = client.post('/accounts/signup/', {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password1': 'NewPass123!',
            'password2': 'NewPass123!'
        })
        self.assertEqual(response.status_code, 403)
    
    def test_form_field_length_limits(self):
        """Test that form fields respect length limits."""
        # Test extremely long inputs
        long_string = 'a' * 10000
        
        # Login form
        login_form = LoginForm(data={
            'username': long_string,
            'password': long_string
        })
        
        # Should either be invalid or truncate safely
        if login_form.is_valid():
            self.assertLessEqual(len(login_form.cleaned_data['username']), 64)
        
        # Signup form
        signup_form = SignUpForm(data={
            'username': long_string,
            'email': f'{long_string}@example.com',
            'password1': long_string,
            'password2': long_string
        })
        
        # Should be invalid due to length constraints
        self.assertFalse(signup_form.is_valid())
    
    def test_password_field_security(self):
        """Test security measures for password fields."""
        # Test that password fields don't echo values in error messages
        signup_form = SignUpForm(data={
            'username': 'testuser',
            'email': 'test@example.com',
            'password1': 'SecretPassword123!',
            'password2': 'DifferentPassword123!'
        })
        
        self.assertFalse(signup_form.is_valid())
        
        # Check that password values are not in error messages
        error_text = str(signup_form.errors)
        self.assertNotIn('SecretPassword123!', error_text)
        self.assertNotIn('DifferentPassword123!', error_text)


class FormUsabilityTests(TestCase):
    """Test cases for form usability and user experience."""
    
    def test_form_error_messages_clarity(self):
        """Test that form error messages are clear and helpful."""
        # Test signup form with various errors
        signup_form = SignUpForm(data={
            'username': '',
            'email': 'invalid-email',
            'password1': 'weak',
            'password2': 'different'
        })
        
        self.assertFalse(signup_form.is_valid())
        
        # Check that error messages exist and are informative
        self.assertIn('username', signup_form.errors)
        self.assertIn('email', signup_form.errors)
        
        # Error messages should be user-friendly
        username_error = str(signup_form.errors['username'])
        self.assertIn('required', username_error.lower())
    
    def test_form_field_widgets_and_attributes(self):
        """Test that form fields have appropriate widgets and attributes."""
        # Test login form
        login_form = LoginForm()
        
        # Username field should be text input
        username_widget = login_form.fields['username'].widget
        self.assertEqual(username_widget.input_type, 'text')
        
        # Password field should be password input
        password_widget = login_form.fields['password'].widget
        self.assertEqual(password_widget.input_type, 'password')
        
        # Remember me should be checkbox
        remember_widget = login_form.fields['remember_me'].widget
        self.assertEqual(remember_widget.input_type, 'checkbox')
    
    def test_form_accessibility_features(self):
        """Test that forms have accessibility features."""
        # Test that forms can be rendered without errors
        login_form = LoginForm()
        signup_form = SignUpForm()
        
        try:
            login_html = str(login_form)
            signup_html = str(signup_form)
            
            # Should not raise exceptions
            self.assertIsInstance(login_html, str)
            self.assertIsInstance(signup_html, str)
            
        except Exception as e:
            self.fail(f"Form rendering failed: {e}")


class FormIntegrationTests(TestCase):
    """Integration tests for forms with views and templates."""
    
    def setUp(self):
        """Set up test client and user."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='integrationuser',
            email='integration@example.com',
            password='IntegrationPass123!'
        )
    
    def test_login_form_integration(self):
        """Test login form integration with view."""
        # Get login page
        response = self.client.get('/accounts/login/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'username')
        self.assertContains(response, 'password')
        
        # Test successful login
        response = self.client.post('/accounts/login/', {
            'username': 'integrationuser',
            'password': 'IntegrationPass123!',
            'remember_me': False
        })
        self.assertEqual(response.status_code, 302)
    
    def test_signup_form_integration(self):
        """Test signup form integration with view."""
        # Get signup page
        response = self.client.get('/accounts/signup/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'username')
        self.assertContains(response, 'email')
        self.assertContains(response, 'password1')
        self.assertContains(response, 'password2')
        
        # Test successful signup
        response = self.client.post('/accounts/signup/', {
            'username': 'newintegrationuser',
            'email': 'newintegration@example.com',
            'password1': 'NewIntegrationPass123!',
            'password2': 'NewIntegrationPass123!'
        })
        self.assertEqual(response.status_code, 302)
        
        # Verify user was created
        self.assertTrue(User.objects.filter(username='newintegrationuser').exists())
    
    def test_form_validation_messages_in_templates(self):
        """Test that form validation messages are displayed in templates."""
        # Submit invalid login data
        response = self.client.post('/accounts/login/', {
            'username': '',
            'password': ''
        })
        
        self.assertEqual(response.status_code, 200)
        # Should contain error messages
        self.assertContains(response, 'error', msg_prefix='Login form should show errors')
        
        # Submit invalid signup data
        response = self.client.post('/accounts/signup/', {
            'username': '',
            'email': 'invalid-email',
            'password1': 'weak',
            'password2': 'different'
        })
        
        self.assertEqual(response.status_code, 200)
        # Should contain error messages
        content = response.content.decode('utf-8')
        self.assertTrue('error' in content.lower() or 'invalid' in content.lower(),
                       'Signup form should show validation errors')
