from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from .forms import LoginForm, SignUpForm, MyPasswordChangeForm, MyPasswordResetForm, MyPasswordResetConfirmForm
from unittest.mock import patch, MagicMock
import re


User = get_user_model()


class LoginFormTests(TestCase):
    """Test cases for the custom LoginForm."""
    
    def setUp(self):
        """Set up test user for form tests."""
        self.user = User.objects.create_user(
            username='TestUser',
            password='TestPass123!',
            email='test@example.com'
        )
    
    def test_valid_login_form(self):
        """Test valid login form submission."""
        form_data = {
            'username': 'TestUser',
            'password': 'TestPass123!',
            'remember_me': True
        }
        form = LoginForm(data=form_data)
        self.assertTrue(form.is_valid())
    
    def test_case_insensitive_username(self):
        """Test that username lookup is case insensitive."""
        form_data = {
            'username': 'testuser',  # lowercase
            'password': 'TestPass123!',
            'remember_me': False
        }
        form = LoginForm(data=form_data)
        self.assertTrue(form.is_valid())
        # Should return the actual username from database
        self.assertEqual(form.cleaned_data['username'], 'TestUser')
    
    def test_username_with_whitespace(self):
        """Test that username whitespace is stripped."""
        form_data = {
            'username': '  TestUser  ',
            'password': 'TestPass123!',
            'remember_me': False
        }
        form = LoginForm(data=form_data)
        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['username'], 'TestUser')
    
    def test_nonexistent_username(self):
        """Test form with nonexistent username."""
        form_data = {
            'username': 'nonexistent',
            'password': 'TestPass123!',
            'remember_me': False
        }
        form = LoginForm(data=form_data)
        # Form should be valid but authentication will fail
        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['username'], 'nonexistent')
    
    def test_empty_username(self):
        """Test form with empty username."""
        form_data = {
            'username': '',
            'password': 'TestPass123!',
            'remember_me': False
        }
        form = LoginForm(data=form_data)
        self.assertFalse(form.is_valid())
    
    def test_empty_password(self):
        """Test form with empty password."""
        form_data = {
            'username': 'TestUser',
            'password': '',
            'remember_me': False
        }
        form = LoginForm(data=form_data)
        self.assertFalse(form.is_valid())
    
    def test_remember_me_optional(self):
        """Test that remember_me field is optional."""
        form_data = {
            'username': 'TestUser',
            'password': 'TestPass123!'
        }
        form = LoginForm(data=form_data)
        self.assertTrue(form.is_valid())
        self.assertFalse(form.cleaned_data['remember_me'])


class SignUpFormTests(TestCase):
    """Test cases for the custom SignUpForm."""
    
    def test_valid_signup_form(self):
        """Test valid signup form submission."""
        form_data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password1': 'NewPass123!',
            'password2': 'NewPass123!'
        }
        form = SignUpForm(data=form_data)
        self.assertTrue(form.is_valid())
    
    def test_password_mismatch(self):
        """Test signup form with password mismatch."""
        form_data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password1': 'NewPass123!',
            'password2': 'DifferentPass123!'
        }
        form = SignUpForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn('password2', form.errors)
    
    def test_weak_password(self):
        """Test signup form with weak password."""
        form_data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password1': 'weak',
            'password2': 'weak'
        }
        form = SignUpForm(data=form_data)
        self.assertFalse(form.is_valid())
    
    def test_invalid_email(self):
        """Test signup form with invalid email."""
        form_data = {
            'username': 'newuser',
            'email': 'invalid-email',
            'password1': 'NewPass123!',
            'password2': 'NewPass123!'
        }
        form = SignUpForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn('email', form.errors)
    
    def test_duplicate_username(self):
        """Test signup form with duplicate username."""
        User.objects.create_user(username='existinguser', password='pass')
        form_data = {
            'username': 'existinguser',
            'email': 'new@example.com',
            'password1': 'NewPass123!',
            'password2': 'NewPass123!'
        }
        form = SignUpForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn('username', form.errors)
    
    def test_duplicate_email(self):
        """Test signup form with duplicate email."""
        User.objects.create_user(
            username='existing', 
            email='existing@example.com', 
            password='pass'
        )
        form_data = {
            'username': 'newuser',
            'email': 'existing@example.com',
            'password1': 'NewPass123!',
            'password2': 'NewPass123!'
        }
        form = SignUpForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn('email', form.errors)


class LoginViewTests(TestCase):
    """Test cases for the login view."""
    
    def setUp(self):
        """Set up test client and user."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='TestPass123!',
            email='test@example.com'
        )
        self.login_url = reverse('login')
    
    def test_login_get_request(self):
        """Test GET request to login page."""
        response = self.client.get(self.login_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'login')
        self.assertIsInstance(response.context['form'], LoginForm)
    
    def test_valid_login_post(self):
        """Test valid login POST request."""
        response = self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'TestPass123!',
            'remember_me': False
        })
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('home'))
    
    def test_invalid_login_post(self):
        """Test invalid login POST request."""
        response = self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'wrongpassword',
            'remember_me': False
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'error')
    
    def test_remember_me_session_expiry(self):
        """Test that remember me sets correct session expiry."""
        # Test with remember_me = True
        response = self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'TestPass123!',
            'remember_me': True
        })
        self.assertEqual(self.client.session.get_expiry_age(), 1209600)  # 14 days
        
        # Logout and test with remember_me = False
        self.client.logout()
        response = self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'TestPass123!',
            'remember_me': False
        })
        self.assertEqual(self.client.session.get_expiry_age(), 0)  # Session cookie
    
    def test_blog_redirect_after_login(self):
        """Test redirect to blog after login when session flag is set."""
        session = self.client.session
        session['blog_index'] = 'yes'
        session.save()
        
        response = self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'TestPass123!',
            'remember_me': False
        })
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('blog_index'))
    
    def test_already_authenticated_redirect(self):
        """Test that already authenticated users are redirected."""
        self.client.login(username='testuser', password='TestPass123!')
        response = self.client.get(self.login_url)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('home'))


class SignupViewTests(TestCase):
    """Test cases for the signup view."""
    
    def setUp(self):
        """Set up test client."""
        self.client = Client()
        self.signup_url = reverse('signup')
    
    def test_signup_get_request(self):
        """Test GET request to signup page."""
        response = self.client.get(self.signup_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'signup')
        self.assertIsInstance(response.context['form'], SignUpForm)
    
    def test_valid_signup_post(self):
        """Test valid signup POST request."""
        response = self.client.post(self.signup_url, {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password1': 'NewPass123!',
            'password2': 'NewPass123!'
        })
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('login'))
        self.assertTrue(User.objects.filter(username='newuser').exists())
    
    def test_invalid_signup_post(self):
        """Test invalid signup POST request."""
        response = self.client.post(self.signup_url, {
            'username': 'newuser',
            'email': 'invalid-email',
            'password1': 'weak',
            'password2': 'different'
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username='newuser').exists())
    
    def test_already_authenticated_signup_redirect(self):
        """Test that authenticated users are redirected from signup."""
        user = User.objects.create_user(username='testuser', password='pass')
        self.client.login(username='testuser', password='pass')
        response = self.client.get(self.signup_url)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('home'))


class PasswordChangeViewTests(TestCase):
    """Test cases for password change view."""
    
    def setUp(self):
        """Set up test client and user."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='OldPass123!',
            email='test@example.com'
        )
        self.password_change_url = reverse('password_change')
    
    def test_password_change_requires_login(self):
        """Test that password change requires authentication."""
        response = self.client.get(self.password_change_url)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, f'/accounts/login/?next={self.password_change_url}')
    
    def test_password_change_get_request(self):
        """Test GET request to password change page."""
        self.client.login(username='testuser', password='OldPass123!')
        response = self.client.get(self.password_change_url)
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.context['form'], MyPasswordChangeForm)
    
    def test_valid_password_change(self):
        """Test valid password change."""
        self.client.login(username='testuser', password='OldPass123!')
        response = self.client.post(self.password_change_url, {
            'old_password': 'OldPass123!',
            'new_password1': 'NewPass123!',
            'new_password2': 'NewPass123!'
        })
        self.assertEqual(response.status_code, 302)
        
        # Verify password was changed
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('NewPass123!'))
    
    def test_invalid_old_password(self):
        """Test password change with invalid old password."""
        self.client.login(username='testuser', password='OldPass123!')
        response = self.client.post(self.password_change_url, {
            'old_password': 'WrongOldPass',
            'new_password1': 'NewPass123!',
            'new_password2': 'NewPass123!'
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'error')


class PasswordResetTests(TestCase):
    """Test cases for password reset functionality."""
    
    def setUp(self):
        """Set up test client and user."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='TestPass123!',
            email='test@example.com'
        )
        self.password_reset_url = reverse('password_reset')
    
    def test_password_reset_get_request(self):
        """Test GET request to password reset page."""
        response = self.client.get(self.password_reset_url)
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.context['form'], MyPasswordResetForm)
    
    @patch('accounts.views.send_mail')
    def test_valid_password_reset_request(self, mock_send_mail):
        """Test valid password reset request."""
        response = self.client.post(self.password_reset_url, {
            'email': 'test@example.com'
        })
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('password_reset_done'))
        mock_send_mail.assert_called_once()
    
    def test_password_reset_nonexistent_email(self):
        """Test password reset with nonexistent email."""
        response = self.client.post(self.password_reset_url, {
            'email': 'nonexistent@example.com'
        })
        # Should still redirect to prevent email enumeration
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('password_reset_done'))
    
    def test_password_reset_confirm_valid_token(self):
        """Test password reset confirm with valid token."""
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = default_token_generator.make_token(self.user)
        
        response = self.client.get(
            reverse('password_reset_confirm', args=[uidb64, token])
        )
        self.assertEqual(response.status_code, 200)
    
    def test_password_reset_confirm_invalid_token(self):
        """Test password reset confirm with invalid token."""
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        
        response = self.client.get(
            reverse('password_reset_confirm', args=[uidb64, 'invalid-token'])
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'invalid')


class AccountsURLTests(TestCase):
    """Test cases for accounts app URL configuration."""
    
    def test_login_url_resolves(self):
        """Test that login URL resolves correctly."""
        from django.urls import resolve
        resolver = resolve('/accounts/login/')
        self.assertEqual(resolver.func.__name__, 'login')
        self.assertEqual(resolver.url_name, 'login')
    
    def test_signup_url_resolves(self):
        """Test that signup URL resolves correctly."""
        from django.urls import resolve
        resolver = resolve('/accounts/signup/')
        self.assertEqual(resolver.func.__name__, 'signup')
        self.assertEqual(resolver.url_name, 'signup')
    
    def test_password_change_url_resolves(self):
        """Test that password change URL resolves correctly."""
        from django.urls import resolve
        resolver = resolve('/accounts/password_change/')
        self.assertEqual(resolver.func.__name__, 'password_change')
        self.assertEqual(resolver.url_name, 'password_change')


class AccountsIntegrationTests(TestCase):
    """Integration tests for accounts app."""
    
    def setUp(self):
        """Set up test data for integration tests."""
        self.client = Client()
    
    def test_complete_user_registration_flow(self):
        """Test the complete user registration and login flow."""
        # Step 1: Register new user
        response = self.client.post(reverse('signup'), {
            'username': 'integrationuser',
            'email': 'integration@example.com',
            'password1': 'IntegrationPass123!',
            'password2': 'IntegrationPass123!'
        })
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('login'))
        
        # Verify user was created
        user = User.objects.get(username='integrationuser')
        self.assertEqual(user.email, 'integration@example.com')
        
        # Step 2: Login with new user
        response = self.client.post(reverse('login'), {
            'username': 'integrationuser',
            'password': 'IntegrationPass123!',
            'remember_me': False
        })
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('home'))
        
        # Step 3: Access protected page
        response = self.client.get(reverse('blog_index'))
        self.assertEqual(response.status_code, 200)
    
    def test_authentication_required_workflow(self):
        """Test workflow for accessing protected resources."""
        # Try to access protected resource without authentication
        response = self.client.get(reverse('blog_index'))
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('login'))
        
        # Check that session variable is set
        session = self.client.session
        self.assertEqual(session.get('blog_index'), 'yes')
        
        # Login
        user = User.objects.create_user(
            username='protecteduser',
            password='ProtectedPass123!'
        )
        response = self.client.post(reverse('login'), {
            'username': 'protecteduser',
            'password': 'ProtectedPass123!',
            'remember_me': False
        })
        
        # Should redirect to originally requested page
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('blog_index'))
    
    def test_logout_workflow(self):
        """Test the logout workflow."""
        # Create and login user
        user = User.objects.create_user(
            username='logoutuser',
            password='LogoutPass123!'
        )
        self.client.login(username='logoutuser', password='LogoutPass123!')
        
        # Verify user is authenticated
        response = self.client.get(reverse('blog_index'))
        self.assertEqual(response.status_code, 200)
        
        # Logout
        response = self.client.post(reverse('logout'))
        self.assertEqual(response.status_code, 302)
        
        # Verify user is no longer authenticated
        response = self.client.get(reverse('blog_index'))
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('login'))


class SecurityTests(TestCase):
    """Security-related tests for accounts app."""
    
    def setUp(self):
        """Set up test data for security tests."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='securityuser',
            password='SecurityPass123!',
            email='security@example.com'
        )
    
    def test_password_strength_validation(self):
        """Test that weak passwords are rejected."""
        weak_passwords = [
            'password',  # Too common
            '12345678',  # Only digits
            'PASSWORD',  # Only uppercase
            'password1',  # No special chars
            'Pass1!',  # Too short
        ]
        
        for weak_password in weak_passwords:
            form_data = {
                'username': f'user{weak_password}',
                'email': f'{weak_password}@example.com',
                'password1': weak_password,
                'password2': weak_password
            }
            form = SignUpForm(data=form_data)
            self.assertFalse(form.is_valid(), f"Password '{weak_password}' should be invalid")
    
    def test_login_rate_limiting_behavior(self):
        """Test login behavior with multiple failed attempts."""
        # Multiple failed login attempts
        for i in range(5):
            response = self.client.post(reverse('login'), {
                'username': 'securityuser',
                'password': 'wrongpassword',
                'remember_me': False
            })
            self.assertEqual(response.status_code, 200)
        
        # Account should still be accessible with correct password
        response = self.client.post(reverse('login'), {
            'username': 'securityuser',
            'password': 'SecurityPass123!',
            'remember_me': False
        })
        self.assertEqual(response.status_code, 302)
    
    def test_csrf_protection(self):
        """Test that CSRF protection is enabled."""
        # Attempt POST without CSRF token
        response = self.client.post(reverse('login'), {
            'username': 'securityuser',
            'password': 'SecurityPass123!',
            'remember_me': False
        }, enforce_csrf_checks=True)
        self.assertEqual(response.status_code, 403)
    
    def test_sql_injection_protection(self):
        """Test protection against SQL injection attacks."""
        malicious_inputs = [
            "'; DROP TABLE auth_user; --",
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM auth_user --"
        ]
        
        for malicious_input in malicious_inputs:
            form_data = {
                'username': malicious_input,
                'password': 'anypassword'
            }
            response = self.client.post(reverse('login'), form_data)
            # Should not crash or return unexpected results
            self.assertIn(response.status_code, [200, 302])
    
    def test_xss_protection(self):
        """Test protection against XSS attacks."""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "';alert(String.fromCharCode(88,83,83))//'"
        ]
        
        for payload in xss_payloads:
            form_data = {
                'username': payload,
                'email': f'{payload}@example.com',
                'password1': 'TestPass123!',
                'password2': 'TestPass123!'
            }
            response = self.client.post(reverse('signup'), form_data)
            # Response should not contain unescaped script tags
            content = response.content.decode('utf-8')
            self.assertNotIn('<script>', content)
            self.assertNotIn('javascript:', content)
