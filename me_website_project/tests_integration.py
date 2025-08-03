"""
Comprehensive integration and system-wide tests for the me_website project.

This module contains tests that span multiple apps and test the overall
functionality of the Django project including URL routing, settings,
middleware, database connections, and cross-app interactions.
"""

from django.test import TestCase, Client, TransactionTestCase
from django.urls import reverse, resolve
from django.contrib.auth.models import User
from django.core.management import call_command
from django.core.exceptions import ImproperlyConfigured
from django.db import connection, transaction
from django.conf import settings
from django.template.loader import get_template
from django.template import TemplateDoesNotExist
from features.models import Post, Question, Choice
from unittest.mock import patch, MagicMock
import tempfile
import os
import threading
import time


class ProjectURLTests(TestCase):
    """Test cases for project-wide URL configuration."""
    
    def test_all_main_urls_resolve(self):
        """Test that all main URLs resolve correctly."""
        main_urls = [
            ('/', 'home'),
            ('/about/', 'about'),
            ('/projects/', 'projects'),
            ('/skills/', 'skills'),
            ('/experience/', 'experience'),
            ('/education/', 'education'),
            ('/contact/', 'contact'),
            ('/accounts/login/', 'login'),
            ('/accounts/signup/', 'signup'),
            ('/features/blog/', 'blog_index'),
            ('/features/polls/', 'polls_index'),
            ('/admin/', None),  # Admin doesn't have a name
            ('/ht/', 'health_check')
        ]
        
        for url, expected_name in main_urls:
            with self.subTest(url=url):
                resolver = resolve(url)
                if expected_name:
                    self.assertEqual(resolver.url_name, expected_name)
    
    def test_reverse_all_named_urls(self):
        """Test that all named URLs can be reversed."""
        named_urls = [
            'home', 'about', 'projects', 'skills', 'experience', 
            'education', 'contact', 'login', 'signup', 'logout',
            'password_change', 'password_reset', 'blog_index', 
            'polls_index', 'health_check'
        ]
        
        for url_name in named_urls:
            with self.subTest(url_name=url_name):
                try:
                    reverse(url_name)
                except Exception as e:
                    self.fail(f"Could not reverse URL '{url_name}': {e}")
    
    def test_url_patterns_no_conflicts(self):
        """Test that URL patterns don't conflict with each other."""
        from django.urls import get_resolver
        resolver = get_resolver()
        
        # Get all URL patterns
        url_patterns = []
        for pattern in resolver.url_patterns:
            url_patterns.append(str(pattern.pattern))
        
        # Check for obvious conflicts
        self.assertNotIn('', url_patterns[1:])  # Only root should be empty
        
        # Check that admin URLs don't conflict with app URLs
        admin_patterns = [p for p in url_patterns if 'admin' in str(p)]
        app_patterns = [p for p in url_patterns if 'admin' not in str(p)]
        
        self.assertTrue(len(admin_patterns) > 0)
        self.assertTrue(len(app_patterns) > 0)


class ProjectSettingsTests(TestCase):
    """Test cases for Django settings configuration."""
    
    def test_required_settings_exist(self):
        """Test that all required settings are properly configured."""
        required_settings = [
            'SECRET_KEY', 'DEBUG', 'ALLOWED_HOSTS', 'INSTALLED_APPS',
            'MIDDLEWARE', 'ROOT_URLCONF', 'TEMPLATES', 'DATABASES'
        ]
        
        for setting_name in required_settings:
            with self.subTest(setting=setting_name):
                self.assertTrue(hasattr(settings, setting_name))
                setting_value = getattr(settings, setting_name)
                self.assertIsNotNone(setting_value)
    
    def test_installed_apps_configuration(self):
        """Test that all required apps are installed."""
        required_apps = [
            'django.contrib.admin',
            'django.contrib.auth',
            'django.contrib.contenttypes',
            'django.contrib.sessions',
            'django.contrib.messages',
            'django.contrib.staticfiles',
            'accounts',
            'about',
            'projects',
            'skills',
            'experience',
            'education',
            'contact',
            'features'
        ]
        
        for app in required_apps:
            with self.subTest(app=app):
                self.assertIn(app, settings.INSTALLED_APPS)
    
    def test_middleware_configuration(self):
        """Test that required middleware is configured."""
        required_middleware = [
            'django.middleware.security.SecurityMiddleware',
            'django.contrib.sessions.middleware.SessionMiddleware',
            'django.middleware.common.CommonMiddleware',
            'django.middleware.csrf.CsrfViewMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware',
            'django.contrib.messages.middleware.MessageMiddleware',
            'django.middleware.clickjacking.XFrameOptionsMiddleware'
        ]
        
        for middleware in required_middleware:
            with self.subTest(middleware=middleware):
                self.assertIn(middleware, settings.MIDDLEWARE)
    
    def test_database_configuration(self):
        """Test that database is properly configured."""
        self.assertIn('default', settings.DATABASES)
        db_config = settings.DATABASES['default']
        self.assertIn('ENGINE', db_config)
        self.assertIn('NAME', db_config)
    
    def test_template_configuration(self):
        """Test that templates are properly configured."""
        self.assertTrue(len(settings.TEMPLATES) > 0)
        template_config = settings.TEMPLATES[0]
        self.assertEqual(template_config['BACKEND'], 'django.template.backends.django.DjangoTemplates')
        self.assertIn('DIRS', template_config)
        self.assertTrue(template_config['APP_DIRS'])


class DatabaseTests(TransactionTestCase):
    """Test cases for database operations and integrity."""
    
    def test_database_connection(self):
        """Test that database connection is working."""
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            self.assertEqual(result[0], 1)
    
    def test_database_migrations_applied(self):
        """Test that all migrations have been applied."""
        from django.db.migrations.executor import MigrationExecutor
        executor = MigrationExecutor(connection)
        plan = executor.migration_plan(executor.loader.graph.leaf_nodes())
        self.assertEqual(len(plan), 0, "Unapplied migrations found")
    
    def test_model_creation_and_relationships(self):
        """Test that models can be created and relationships work."""
        # Test creating a question and choices
        question = Question.objects.create(
            question_text="Test question?",
            pub_date=timezone.now()
        )
        
        choice1 = Choice.objects.create(
            question=question,
            choice_text="Choice 1",
            votes=0
        )
        
        choice2 = Choice.objects.create(
            question=question,
            choice_text="Choice 2", 
            votes=5
        )
        
        # Test relationships
        self.assertEqual(question.choice_set.count(), 2)
        self.assertIn(choice1, question.choice_set.all())
        self.assertIn(choice2, question.choice_set.all())
        
        # Test cascade delete
        question.delete()
        self.assertFalse(Choice.objects.filter(id=choice1.id).exists())
        self.assertFalse(Choice.objects.filter(id=choice2.id).exists())
    
    def test_database_transaction_rollback(self):
        """Test that database transactions work correctly."""
        initial_count = Question.objects.count()
        
        try:
            with transaction.atomic():
                Question.objects.create(
                    question_text="Test question",
                    pub_date=timezone.now()
                )
                # Force an error to trigger rollback
                raise Exception("Forced error")
        except Exception:
            pass
        
        # Count should be unchanged due to rollback
        self.assertEqual(Question.objects.count(), initial_count)


class TemplateTests(TestCase):
    """Test cases for template rendering and existence."""
    
    def test_all_required_templates_exist(self):
        """Test that all required templates exist."""
        required_templates = [
            'home.html',
            'about.html', 
            'contact.html',
            'education.html',
            'experience.html',
            'projects.html',
            'skills.html',
            'features/blog/blog.html',
            'features/blog/post.html',
            'features/polls/poll.html',
            'features/polls/detail.html',
            'features/polls/results.html',
            'registration/login.html',
            'registration/signup.html'
        ]
        
        for template_name in required_templates:
            with self.subTest(template=template_name):
                try:
                    template = get_template(template_name)
                    self.assertIsNotNone(template)
                except TemplateDoesNotExist:
                    self.fail(f"Template '{template_name}' does not exist")
    
    def test_base_template_inheritance(self):
        """Test that templates properly inherit from base template."""
        client = Client()
        
        template_urls = [
            reverse('home'),
            reverse('about'),
            reverse('contact'),
            reverse('projects'),
            reverse('skills'),
            reverse('experience'),
            reverse('education')
        ]
        
        for url in template_urls:
            with self.subTest(url=url):
                response = client.get(url)
                self.assertEqual(response.status_code, 200)
                content = response.content.decode('utf-8')
                # Check for common base template elements
                self.assertIn('<html', content.lower())
                self.assertIn('<head', content.lower())
                self.assertIn('<body', content.lower())


class SecurityTests(TestCase):
    """Test cases for security configurations."""
    
    def test_csrf_protection_enabled(self):
        """Test that CSRF protection is enabled."""
        self.assertIn('django.middleware.csrf.CsrfViewMiddleware', settings.MIDDLEWARE)
    
    def test_clickjacking_protection_enabled(self):
        """Test that clickjacking protection is enabled."""
        self.assertIn('django.middleware.clickjacking.XFrameOptionsMiddleware', settings.MIDDLEWARE)
    
    def test_security_headers(self):
        """Test that security headers are properly set."""
        client = Client()
        response = client.get(reverse('home'))
        
        # Test that response doesn't expose sensitive headers
        self.assertNotIn('X-Powered-By', response)
        self.assertNotIn('Server', response)
    
    def test_admin_requires_authentication(self):
        """Test that admin interface requires authentication."""
        client = Client()
        response = client.get('/admin/')
        self.assertEqual(response.status_code, 302)  # Redirect to login
    
    def test_password_validation(self):
        """Test that password validation is working."""
        from django.contrib.auth.password_validation import validate_password
        from django.core.exceptions import ValidationError
        
        weak_passwords = ['password', '123456', 'qwerty']
        
        for password in weak_passwords:
            with self.subTest(password=password):
                with self.assertRaises(ValidationError):
                    validate_password(password)


class PerformanceTests(TestCase):
    """Test cases for performance and optimization."""
    
    def test_page_load_times(self):
        """Test that pages load within acceptable time limits."""
        client = Client()
        
        urls_to_test = [
            reverse('home'),
            reverse('about'),
            reverse('contact'),
            reverse('projects'),
            reverse('skills'),
            reverse('experience'),
            reverse('education')
        ]
        
        for url in urls_to_test:
            with self.subTest(url=url):
                start_time = time.time()
                response = client.get(url)
                end_time = time.time()
                
                self.assertEqual(response.status_code, 200)
                load_time = end_time - start_time
                self.assertLess(load_time, 2.0, f"Page {url} took {load_time:.2f}s to load")
    
    def test_database_query_efficiency(self):
        """Test that database queries are efficient."""
        from django.test.utils import override_settings
        from django.db import connection
        
        # Create test data
        for i in range(10):
            question = Question.objects.create(
                question_text=f"Question {i}",
                pub_date=timezone.now()
            )
            for j in range(3):
                Choice.objects.create(
                    question=question,
                    choice_text=f"Choice {j}",
                    votes=j
                )
        
        # Test query count for retrieving questions with choices
        with self.assertNumQueries(2):  # Should be 2 queries max with prefetch_related
            questions = Question.objects.prefetch_related('choice_set').all()
            for question in questions:
                list(question.choice_set.all())  # Force evaluation
    
    def test_static_files_accessibility(self):
        """Test that static files are accessible."""
        from django.contrib.staticfiles import finders
        
        # Test that static files finder works
        static_file = finders.find('docs/assets/css/carousel.css')
        if static_file:  # Only test if file exists
            self.assertTrue(os.path.exists(static_file))


class ConcurrencyTests(TransactionTestCase):
    """Test cases for concurrent access and thread safety."""
    
    def test_concurrent_user_creation(self):
        """Test that concurrent user creation doesn't cause conflicts."""
        results = []
        errors = []
        
        def create_user(username):
            try:
                user = User.objects.create_user(
                    username=username,
                    password='testpass123'
                )
                results.append(user.id)
            except Exception as e:
                errors.append(str(e))
        
        # Create multiple threads to create users concurrently
        threads = []
        for i in range(10):
            thread = threading.Thread(target=create_user, args=[f'user{i}'])
            threads.append(thread)
        
        # Start all threads
        for thread in threads:
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # All users should be created successfully
        self.assertEqual(len(errors), 0, f"Errors occurred: {errors}")
        self.assertEqual(len(results), 10)
        self.assertEqual(len(set(results)), 10)  # All IDs should be unique
    
    def test_concurrent_voting(self):
        """Test that concurrent voting doesn't cause race conditions."""
        question = Question.objects.create(
            question_text="Concurrent test question?",
            pub_date=timezone.now()
        )
        choice = Choice.objects.create(
            question=question,
            choice_text="Test choice",
            votes=0
        )
        
        def vote():
            choice_obj = Choice.objects.get(id=choice.id)
            choice_obj.votes += 1
            choice_obj.save()
        
        # Create multiple threads to vote concurrently
        threads = []
        for i in range(10):
            thread = threading.Thread(target=vote)
            threads.append(thread)
        
        # Start all threads
        for thread in threads:
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Check final vote count
        choice.refresh_from_db()
        self.assertEqual(choice.votes, 10)


class ErrorHandlingTests(TestCase):
    """Test cases for error handling and edge cases."""
    
    def test_404_error_handling(self):
        """Test that 404 errors are handled gracefully."""
        client = Client()
        response = client.get('/nonexistent-page/')
        self.assertEqual(response.status_code, 404)
    
    def test_500_error_handling(self):
        """Test that 500 errors are handled gracefully."""
        # This would require creating a view that intentionally raises an exception
        # and testing with DEBUG=False
        pass
    
    def test_invalid_form_data_handling(self):
        """Test that invalid form data is handled properly."""
        client = Client()
        
        # Test login with invalid data
        response = client.post(reverse('login'), {
            'username': '',
            'password': ''
        })
        self.assertEqual(response.status_code, 200)  # Should return form with errors
        
        # Test signup with invalid data
        response = client.post(reverse('signup'), {
            'username': '',
            'email': 'invalid-email',
            'password1': 'weak',
            'password2': 'different'
        })
        self.assertEqual(response.status_code, 200)  # Should return form with errors
    
    def test_sql_injection_protection(self):
        """Test that the application is protected against SQL injection."""
        client = Client()
        
        # Attempt SQL injection through URL parameters
        malicious_params = [
            "'; DROP TABLE auth_user; --",
            "' OR '1'='1",
            "1' UNION SELECT * FROM auth_user --"
        ]
        
        for param in malicious_params:
            with self.subTest(param=param):
                response = client.get(f'/about/?id={param}')
                self.assertEqual(response.status_code, 200)
                # Application should not crash


class HealthCheckTests(TestCase):
    """Test cases for the health check endpoint."""
    
    @patch.dict(os.environ, {'HEALTH_CHECK_SECRET': 'test-secret'})
    def test_health_check_with_valid_secret(self):
        """Test health check with valid secret."""
        client = Client()
        response = client.get(
            reverse('health_check'),
            HTTP_X_HEALTH_CHECK_SECRET='test-secret'
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')
    
    @patch.dict(os.environ, {'HEALTH_CHECK_SECRET': 'test-secret'})
    def test_health_check_with_invalid_secret(self):
        """Test health check with invalid secret."""
        client = Client()
        response = client.get(
            reverse('health_check'),
            HTTP_X_HEALTH_CHECK_SECRET='wrong-secret'
        )
        self.assertEqual(response.status_code, 403)
    
    @patch.dict(os.environ, {'HEALTH_CHECK_SECRET': 'test-secret'})
    def test_health_check_without_secret(self):
        """Test health check without secret header."""
        client = Client()
        response = client.get(reverse('health_check'))
        self.assertEqual(response.status_code, 403)


# Import timezone for the tests that need it
from django.utils import timezone
