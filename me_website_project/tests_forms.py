"""
Comprehensive tests for forms, validation, and input sanitization.

This module tests all forms in the project to ensure proper validation,
security, and user experience across different scenarios.
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse  
from django.utils.html import escape 
from django.core.exceptions import ValidationError
from accounts.forms import (
    LoginForm, 
    SignUpForm, 
    MyPasswordChangeForm, 
    MyPasswordResetForm
)
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
        """  
        Test login form with various edge cases, accounting for the 
        custom max_length on the username field.  
        """  
        # Test cases as tuples: (form_data, expected_is_valid_result)  
        test_cases = [  
            # --- Username edge cases ---

            # Username too long (65 chars). Should now be INVALID.
            ({'username': 'a' * 65, 'password': 'SecurePass123!'}, False),

            # Username exactly at max_length (64 chars). Should be VALID.
            ({'username': 'a' * 64, 'password': 'SecurePass123!'}, True),

            # Username of only whitespace. Should be INVALID 
            # (required field).
            ({'username': '   ', 'password': 'SecurePass123!'}, False),

            # Username with newline. Should be VALID for a CharField.
            ({'username': 'test\nuser', 'password': 'SecurePass123!'}, True),

            # Username with tab. Should be VALID for a CharField.
            ({'username': 'test\tuser', 'password': 'SecurePass123!'}, True),

            # --- Password edge cases ---

            # Empty password. Should be INVALID (required field).
            ({'username': 'testuser', 'password': ''}, False),

            # Whitespace-only password. Should be VALID for the form 
            # field itself. Authentication would fail later in the view.
            ({'username': 'testuser', 'password': ' ' * 10}, True),  
        ]  
    
        for i, (form_data, expected_result) in enumerate(test_cases):  
            with self.subTest(
                case_index=i, 
                expected=expected_result, 
                username_len=len(form_data['username'])
            ):  
                form = LoginForm(data=form_data)  
    
                if expected_result:  
                    self.assertTrue(
                        form.is_valid(),
                        msg=f"Form should be VALID for case: {form_data}"
                    )  
                else:  
                    self.assertFalse(form.is_valid(),
                        msg=f"Form should be INVALID for case: {form_data}"
                    )  
                    # Check that the 'username' field has the error.
                    if 'username' in form_data:
                        # Verify if the username exceeds maximum length
                        if len(form_data['username']) > 64:
                            self.assertIn('username', form.errors)


    def test_signup_form_rejects_existing_username(self):  
        """Test that the signup form is invalid if the username already 
        exists.
        """
        # Create a user first to ensure it exists in the database.
        User.objects.create_user(username='existinguser', password='password123')

        # Try to sign up with the same username.
        data = {
            'username': 'existinguser', # This username now exists  
            'email': 'test@example.com',  
            'password1': 'ValidPass123!',  
            'password2': 'ValidPass123!',  
        }  
        form = SignUpForm(data=data)  
    
        # The form should be invalid.  
        self.assertFalse(form.is_valid())  
        # And the error should be on the 'username' field.  
        self.assertIn('username', form.errors)  
        self.assertIn('Username already exists', form.errors['username']) 

    def test_signup_form_valid_data(self):  
        """Test that the signup form is valid with correct data."""  
        valid_data = {  
            'username': 'newuser123',  
            'email': 'newuser@example.com',  
            'password1': 'NewSecurePass123!',  
            'password2': 'NewSecurePass123!'  
        }  
        form = SignUpForm(data=valid_data)  
        self.assertTrue(form.is_valid(), form.errors.as_text())

    def test_signup_form_username_validation(self):  
        """
        Test the validation rules for the username field 
        (length, characters).
        """  
        # (input_username, expected_is_valid)  
        username_cases = [  
            # Boundary and Length  
            ('', False),                    # Empty is invalid  
            ('a', True),                     # Single character is valid  
            ('a' * 150, True),              # Max length is valid  
            ('a' * 151, False),             # Too long is invalid  
            
            # Character Set  
            ('user.name', True),            # Dot is valid  
            ('user_name', True),            # Underscore is valid  
            ('user@name', True),            # @ symbol is valid  
            ('user-name', True),            # Hyphen is valid  
            ('user+name', True),            # Plus is valid  
            ('user name', False),           # Space is INVALID  
            ('user!', False),              # Exclamation mark is INVALID  
            ('用户名', True),                 # Unicode letters are valid  
        ]  
    
        for username, expected_validity in username_cases:  
            with self.subTest(username=username, expected=expected_validity):  
                data = {  
                    'username': username,  
                    'email': 'test@example.com',  
                    'password1': 'ValidPass123!',  
                    'password2': 'ValidPass123!',  
                }  
                form = SignUpForm(data=data)  
                self.assertEqual(form.is_valid(), expected_validity)
    
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
                data['username'] = f'user{hash(email)}' # Unique username
                
                form = SignUpForm(data=data)
                
                if should_be_valid:
                    self.assertTrue(
                        form.is_valid(), f"Email '{email}' should be valid")
                else:
                    self.assertFalse(
                        form.is_valid(), 
                        f"Email '{email}' should be invalid"
                    )
    
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
            (
                'verylongpasswordwithoutspecialchars123', 
                False
            ), # No special
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
                    self.assertTrue(
                        form.is_valid(), 
                        f"Password '{password}' should be valid"
                    )
                else:
                    self.assertFalse(
                        form.is_valid(), 
                        f"Password '{password}' should be invalid"
                    )


class InputSanitizationTests(TestCase):
    """Test cases for input sanitization and XSS prevention."""
    
    def setUp(self):  
        """Set up the client and any necessary users or URLs."""  
        self.client = Client()  
        # You might need to create a user for some form submissions  
        # self.user = User.objects.create_user(...)  
        self.signup_url = reverse('signup')  
        self.login_url = reverse('login')  
  
    def test_views_prevent_xss_on_form_error(self):  
        """  
        Test that both login and signup views correctly escape XSS 
        payloads when re-rendering a form due to a validation error.  
        """  
        xss_payloads = [  
            '<script>alert("xss")</script>',  
            'javascript:alert("xss")',  
            '<img src=x onerror=alert("xss")>',  
            '"><script>alert("xss")</script>',  
            "'><script>alert('xss')</script>",  
            '<iframe src="javascript:alert(\'xss\')"></iframe>',  
            '<svg onload=alert("xss")>',  
            # This one is already escaped, so it's a good control case.  
            '&lt;script&gt;alert("xss")&lt;/script&gt;'  
        ]  
  
        # A dictionary mapping a form's name to its URL and the field 
        # we'll inject into.  
        forms_to_test = {  
            'signup': {  
                'url': self.signup_url,  
                'field_to_inject': 'username'  
            },  
            'login': {  
                'url': self.login_url,  
                'field_to_inject': 'username'  
            }  
        }  
  
        for form_name, form_details in forms_to_test.items():  
            for payload in xss_payloads:  
                with self.subTest(form=form_name, payload=payload):  
                    # We need to construct form data that is guaranteed 
                    # to be invalid, forcing the form to re-render with 
                    # the payload. For both forms, providing a 
                    # non-existent password or mismatched passwords is 
                    # a reliable way to trigger a validation error.  
                    if form_name == 'signup':  
                        form_data = {  
                            'username': 'dummy_user_for_xss_test',  
                            'email': 'dummy@example.com',  
                            'password1': 'ValidPass123!',  
                            'password2': 'DIFFERENT_PASS_456!'  
                        }  
                    else: # login form  
                        form_data = {  
                            'username': 'dummy_user_for_xss_test',  
                            'password': 'wrongpassword' 
                        }  
                      
                    # Now, inject the payload into the target field  
                    form_data[form_details['field_to_inject']] = payload  
  
                    response = self.client.post(form_details['url'], form_data)  
  
                    # The page should re-render with a 200 OK status due
                    # to the error.  
                    self.assertEqual(
                        response.status_code, 200,
                        "View should re-render the form on validation error."
                    )

                    # The raw, unescaped payload should NOT be in the 
                    # response content. We make an exception for our 
                    # pre-escaped control case.  
                    if payload.startswith('&lt;'):  
                        self.assertIn(
                            payload, response.content.decode(),
                            "Pre-escaped payload should be present as is."
                        )
                    else:  
                        self.assertNotIn(
                            payload, response.content.decode(),
                            "Raw XSS payload should NOT be in the response."
                        )

                    # The HTML-escaped version of the payload SHOULD be 
                    # in the response. Django's template engine will 
                    # escape the payload when it renders it inside the 
                    # <input value="..."> attribute. The escape() 
                    # function mimics this behavior.
                    self.assertIn(
                        escape(payload), response.content.decode(),
                        "HTML-escaped version of the payload SHOULD be in the "
                        "response."
                    )

    def test_login_view_prevents_sql_injection(self):
        """
        Test that the login view correctly handles SQL injection payloads,
        preventing crashes and unauthorized access.
        """
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
                # A user trying to log in with the malicious payload.
                response = self.client.post(self.login_url, {
                    'username': payload,
                    'password': 'anypassword'
                })

                # The login MUST fail. A failed login should re-render
                # the login page with a 200 OK status. It should NOT
                # crash (500) or succeed (302 redirect).
                self.assertEqual(
                    response.status_code, 200,
                    "View should not crash or redirect on a malicious login "
                    "attempt."
                )

                # The user should NOT be authenticated. The most reliable 
                # way to check this is to see if the user's ID is in the 
                # session.
                self.assertNotIn(
                    '_auth_user_id', self.client.session,
                    "User should NOT be logged in after a malicious attempt."
                )

    def test_signup_form_handles_unicode_correctly(self):
        """
        Test that the SignUpForm correctly validates various Unicode
        inputs for the username and email fields.
        """
        unicode_username_cases = [
            ('тестовыйпользователь', True),    # Cyrillic
            ('测试用户',                  True),    # Chinese
            ('テストユーザー',             True),    # Japanese
            ('مستخدماختبار',           True),    # Arabic
            # Emojis (often valid depending on DB collation)
            ('🚀🌟✨',                  True),    
        ]

        for username, expected_validity in unicode_username_cases:
            with self.subTest(username=username):
                data = {
                    'username': username,
                    'email': 'test@example.com', 
                    'password1': 'SecurePass123!',
                    'password2': 'SecurePass123!'
                }
                form = SignUpForm(data=data)
                self.assertEqual(
                    form.is_valid(), 
                    expected_validity,
                    f"Username '{username}' failed validation. "
                    f"Errors: {form.errors.as_text()}"
                )

        # A separate, focused test for email is cleaner
        unicode_email_cases = [
            ('café@example.com', True),
            # Internationalized Domain Name (IDN)
            ('test@bücher.com', True),
            # Emojis are typically not valid in the local-part 
            ('🚀@example.com', False), 
        ]

        for email, expected_validity in unicode_email_cases:
            with self.subTest(email=email):
                data = {
                    'username': f'user{hash(email)}',
                    'email': email,
                    'password1': 'SecurePass123!',
                    'password2': 'SecurePass123!'
                }
                form = SignUpForm(data=data)
                self.assertEqual(
                    form.is_valid(), 
                    expected_validity,
                    f"Email '{email}' failed validation. "
                    f"Errors: {form.errors.as_text()}"
                )


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
    
    def test_form_fields_reject_oversized_inputs(self):
        """
        Test that form fields correctly reject inputs that exceed their
        defined max_length, preventing data truncation issues and 
        ensuring data integrity.
        """
        # Use a length that is guaranteed to be longer than any 
        # reasonable field limit.
        long_string = 'a' * 10000

        # --- Test Login Form ---
        with self.subTest(form="LoginForm"):
            login_form = LoginForm(data={
                'username': long_string,
                # Password length isn't usually checked on a login form
                'password': 'any_password'
            })

            # The form MUST be invalid because the username exceeds its 
            # max_length (64).
            self.assertFalse(login_form.is_valid())

            # Verify the error is on the correct field.
            self.assertIn('username', login_form.errors)
            self.assertNotIn('password', login_form.errors)


        # --- Test Signup Form ---
        with self.subTest(form="SignUpForm"):
            # We only need to make one field too long to invalidate the 
            # form. This makes the test more focused.
            signup_form = SignUpForm(data={
                'username': long_string, # Will invalidate the form
                'email': 'test@example.com',
                'password1': 'SecurePass123!',
                'password2': 'SecurePass123!'
            })

            # The form MUST be invalid due to the username's length 
            # constraint.
            self.assertFalse(signup_form.is_valid())

            # Verify the error is specifically on the username field.
            self.assertIn('username', signup_form.errors)
    
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
        """
        Test that form fields have appropriate widgets and attributes.
        """
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
    
    def test_form_fields_have_associated_labels(self):
        """
        Test that each form field is rendered with a corresponding <label>
        tag to ensure basic accessibility.
        """
        # We can test multiple forms in one go
        forms_to_test = {
            'login': LoginForm(),
            'signup': SignUpForm(),
        }

        for form_name, form in forms_to_test.items():
            with self.subTest(form=form_name):
                # Render the form to HTML by calling as_p()
                form_html = form.as_p()

                # Iterate through each field in the form
                for field_name, field in form.fields.items():
                    # Get the auto-generated ID for the input field.
                    # Django automatically creates an ID like "id_username".
                    field_id = field.widget.attrs.get('id') or f'id_{field_name}'

                    # Construct the expected <label> tag for this field.
                    # It should look like: <label for="id_username">
                    expected_label_html = f'<label for="{field_id}"'

                    # Assert that this <label> tag exists in the rendered 
                    # HTML. This proves the link between the label and 
                    # the input exists.
                    self.assertIn(
                        expected_label_html, 
                        form_html,
                        f"Form '{form_name}' is missing a linked label for "
                        f"field '{field_name}'."
                    )

    def test_password_fields_have_autocomplete_attributes(self):
        """
        Test that password fields have correct autocomplete attributes
        to help password managers and improve accessibility.
        """
        signup_form = SignUpForm()
        
        # For a new password on a signup form
        new_pass_attrs = signup_form.fields['password1'].widget.attrs
        self.assertEqual(new_pass_attrs.get('autocomplete'), 'new-password')

        # For a password on a login form
        login_form = LoginForm()
        current_pass_attrs = login_form.fields['password'].widget.attrs
        self.assertEqual(
            current_pass_attrs.get('autocomplete'), 
            'current-password'
        )


class FormAuthenticationIntegrationTests(TestCase):  
  
    def setUp(self):  
        """Set up the client and a user for login tests."""  
        self.client = Client()  
        self.login_url = reverse('login')  
        self.signup_url = reverse('signup')  
        self.home_url = reverse('home')  
  
        # Create a user that our login test can use to authenticate.  
        self.test_user_username = 'integrationuser'  
        self.test_user_password = 'IntegrationPass123!'  
        self.user = User.objects.create_user(  
            username=self.test_user_username,  
            password=self.test_user_password  
        )  
  
    def test_login_form_integration(self):  
        """  
        Test the complete login user journey, from viewing the page to a  
        successful, authenticated session.  
        """  
        # Test viewing the login page
        response = self.client.get(self.login_url)  
        self.assertEqual(response.status_code, 200)  
        self.assertTemplateUsed(response, 'accounts/login.html') 
        self.assertContains(response, 'username')  
        self.assertContains(response, 'password')  

        # Test a successful login POST request
        response = self.client.post(self.login_url, {
            'username': self.test_user_username,
            'password': self.test_user_password,
            'remember_me': False
        })

        # Assert that the response is a redirect to the correct page.  
        # This checks for a 302 status code and the 'Location' header.  
        self.assertRedirects(response, self.home_url)  
  
        # Part 3: Verify the final session state
        # Assert that the user is now authenticated. The presence of the  
        # '_auth_user_id' key in the session is the definitive check.  
        self.assertIn('_auth_user_id', self.client.session)  
        self.assertEqual(
            int(self.client.session['_auth_user_id']), self.user.id
        )  
  
    def test_signup_form_integration(self):  
        """  
        Test the complete user signup journey, from viewing the page to  
        creating a user in the database and starting an authenticated 
        session.  
        """  
        # Test viewing the signup page  
        response = self.client.get(self.signup_url)  
        self.assertEqual(response.status_code, 200)  
        self.assertTemplateUsed(response, 'accounts/signup.html')  
        self.assertContains(response, 'username')  
        self.assertContains(response, 'email')  
  
        # Test a successful signup POST request
        new_user_data = {  
            'username': 'newintegrationuser',  
            'email': 'newintegration@example.com',  
            'password1': 'NewIntegrationPass123!',  
            'password2': 'NewIntegrationPass123!'  
        }  
        response = self.client.post(self.signup_url, new_user_data)

        # Assert that the signup redirects to the correct success page.
        self.assertRedirects(response, self.home_url)

        # Verify the database state
        # Assert that user with this username now exists in the database.
        self.assertTrue(
            User.objects.filter(username=new_user_data['username']).exists()
        )

        # Verify the final session state
        # Assert that the new user is automatically logged in.
        new_user = User.objects.get(username=new_user_data['username'])
        self.assertIn('_auth_user_id', self.client.session)
        self.assertEqual(
            int(self.client.session['_auth_user_id']), new_user.id
        )  
  

class FormErrorRenderingTests(TestCase):

    def setUp(self):
        self.client = Client()
        self.login_url = reverse('login')
        self.signup_url = reverse('signup')

    def test_validation_errors_are_displayed_in_templates(self):
        """
        Test that when a form is submitted with invalid data, the view
        re-renders the page and includes user-friendly error messages.
        """
        # Test Login Form
        with self.subTest(form="Login"):
            # Submit invalid data (empty fields)
            response = self.client.post(self.login_url, {
                'username': '',
                'password': ''
            })

            # Assert the page re-rendered successfully
            self.assertEqual(response.status_code, 200)

            # Assert that the response contains Django's default error 
            # list class.
            self.assertContains(
                response, 
                'errorlist',
                msg_prefix="Login form should display a list of errors"
            )

            # You can also check for specific error text
            self.assertContains(response, 'This field is required.')


        # Test Signup Form
        with self.subTest(form="Signup"):
            # Submit data with multiple types of errors
            response = self.client.post(self.signup_url, {
                'username': '',
                'email': 'invalid-email',
                'password1': 'weak',
                'password2': 'different'
            })

            # Assert the page re-rendered successfully
            self.assertEqual(response.status_code, 200)

            # Assert that the response contains the error list wrapper
            self.assertContains(
                response, 'errorlist',
                msg_prefix="Signup form should display a list of errors"
            )

            # Check for specific error message to be even more confident
            self.assertContains(response, 'Enter a valid email address.')

