"""
Comprehensive tests for the health check endpoint functionality.

This module tests the health check endpoint which is critical for
monitoring the application's health in production environments.
"""

from django.test import TestCase, Client
from django.urls import reverse
from django.db import connection, OperationalError
from unittest.mock import patch, MagicMock
from django.core.exceptions import ImproperlyConfigured
from hmac import compare_digest
from me_website_project.config_checks import get_health_check_secret
import json
import os


class HealthCheckEndpointTests(TestCase):
    """Test cases for the health check endpoint."""
    
    def setUp(self):
        """Set up test client."""
        self.client = Client()
        self.health_check_url = reverse('health_check')
    
    @patch.dict(os.environ, {'HEALTH_CHECK_SECRET': 'test-secret-key'})
    def test_health_check_success(self):
        """Test successful health check with valid secret."""
        response = self.client.get(
            self.health_check_url,
            HTTP_X_HEALTH_CHECK_SECRET='test-secret-key'
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')
        
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'healthy')
        self.assertTrue(data['services']['database'])  # Fixed: services.database not database
        self.assertIn('version', data)
    
    @patch.dict(os.environ, {'HEALTH_CHECK_SECRET': 'test-health-check-secret'})
    def test_health_check_invalid_secret(self):
        """Test health check with invalid secret."""
        response = self.client.get(
            self.health_check_url,
            HTTP_X_HEALTH_CHECK_SECRET='wrong-secret'
        )
        
        # Accept either 401 or 403 as both are valid for unauthorized access
        self.assertIn(response.status_code, [401, 403])
    
    @patch.dict(os.environ, {'HEALTH_CHECK_SECRET': 'test-health-check-secret'})
    def test_health_check_missing_secret(self):
        """Test health check without secret header."""
        response = self.client.get(self.health_check_url)
        
        # Accept either 401 or 403 as both are valid for unauthorized access
        self.assertIn(response.status_code, [401, 403])
    
    @patch.dict(os.environ, {'HEALTH_CHECK_SECRET': 'test-secret-key'})
    def test_health_check_post_method_not_allowed(self):
        """Test that POST method is not allowed."""
        response = self.client.post(
            self.health_check_url,
            HTTP_X_HEALTH_CHECK_SECRET='test-secret-key'
        )
        
        self.assertEqual(response.status_code, 405)
    
    @patch.dict(os.environ, {'HEALTH_CHECK_SECRET': 'test-secret-key'})
    @patch('me_website_project.views.check_database')
    def test_health_check_database_failure(self, mock_check_db):
        """Test health check when database check fails."""
        mock_check_db.return_value = False
        
        response = self.client.get(
            self.health_check_url,
            HTTP_X_HEALTH_CHECK_SECRET='test-secret-key'
        )
        
        self.assertEqual(response.status_code, 503)
        
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'unhealthy')
        self.assertFalse(data['database'])
    
    @patch.dict(os.environ, {'HEALTH_CHECK_SECRET': 'test-secret-key'})
    def test_health_check_csrf_exempt(self):
        """Test that health check is exempt from CSRF protection."""
        # This test ensures the endpoint can be called without CSRF token
        response = self.client.get(
            self.health_check_url,
            HTTP_X_HEALTH_CHECK_SECRET='test-secret-key',
            enforce_csrf_checks=True
        )
        
        # Should succeed even with CSRF checks enforced
        self.assertEqual(response.status_code, 200)
    
    @patch.dict(os.environ, {'HEALTH_CHECK_SECRET': 'test-secret-key'})
    def test_health_check_response_format(self):
        """Test that health check response has correct format."""
        response = self.client.get(
            self.health_check_url,
            HTTP_X_HEALTH_CHECK_SECRET='test-secret-key'
        )
        
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.content)
        
        # Check required fields
        required_fields = ['status', 'database', 'timestamp']
        for field in required_fields:
            self.assertIn(field, data)
        
        # Check data types
        self.assertIsInstance(data['status'], str)
        self.assertIsInstance(data['database'], bool)
        self.assertIsInstance(data['timestamp'], str)
        
        # Check status values
        self.assertIn(data['status'], ['healthy', 'unhealthy'])
    
    @patch.dict(os.environ, {'HEALTH_CHECK_SECRET': 'test-secret-key'})
    def test_health_check_includes_version_if_available(self):
        """Test that health check includes version if APP_VERSION is set."""
        with patch('django.conf.settings.APP_VERSION', '1.0.0'):
            response = self.client.get(
                self.health_check_url,
                HTTP_X_HEALTH_CHECK_SECRET='test-secret-key'
            )
            
            self.assertEqual(response.status_code, 200)
            
            data = json.loads(response.content)
            self.assertIn('version', data)
            self.assertEqual(data['version'], '1.0.0')

    @patch.dict(os.environ, {'HEALTH_CHECK_SECRET': 'test-secret-key'})
    def test_health_check_omits_version_if_unavailable(self):
        """
        Test that health check omits version if APP_VERSION is not set.
        """
        response = self.client.get(
            self.health_check_url,
            HTTP_X_HEALTH_CHECK_SECRET='test-secret-key'
        )
        
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.content)
        # The 'version' key should NOT be in the response.
        self.assertNotIn('version', data)


class HealthCheckDatabaseTests(TestCase):
    """Test cases for the database check functionality."""
    
    def test_check_database_function_success(self):
        """Test that check_database function works correctly."""
        from me_website_project.views import check_database
        
        result = check_database()
        self.assertTrue(result)
    
    @patch('me_website_project.views.connection')
    def test_check_database_function_failure(self, mock_connection):
        """
        Test that check_database function returns False when the database
        connection fails.
        """
        from me_website_project.views import check_database

        # Configure the mock to simulate a database error.
        # We make the mock's cursor raise an OperationalError when used.
        mock_connection.cursor.side_effect = OperationalError(
            "Database is down!"
        )

        # Call the function.
        result = check_database()

        # The function should catch the exception and return False.
        self.assertFalse(result)
    
    @patch('me_website_project.views.connection')
    def test_check_database_logs_errors(self, mock_connection):
        """
        Test that when a database connection fails, the error is logged
        before the function returns False.
        """
        from me_website_project.views import check_database

        # Simulate the database failure. Make the act of getting a 
        # cursor raise the specific, correct exception.
        error_message = "Database connection failed!"
        mock_connection.cursor.side_effect = OperationalError(error_message)

        # Intercept the logger and call the function. Use a nested patch 
        # to capture calls to the logger.
        with patch('me_website_project.views.logger') as mock_logger:
            result = check_database()

            # Assert the function returned the correct failure value.
            self.assertFalse(result)

            # Assert that the logger's 'error' method was called exactly 
            # once.
            mock_logger.error.assert_called_once()

            # Assert that the logger was called with a message 
            # containing the exception text. This proves you are
            # logging useful information.
            call_args, call_kwargs = mock_logger.error.call_args
            self.assertIn("Database health check failed", call_args[0])
            self.assertIn(error_message, call_args[0])


class HealthCheckSecurityTests(TestCase):
    """Test cases for health check security measures."""
    
    def test_get_health_check_secret_raises_error_if_missing(self):
        """
        Test that get_health_check_secret raises ImproperlyConfigured
        if the environment variable is not set.
        """
        # Ensure the environment variable is not set
        with patch.dict(os.environ, {}, clear=True):
            # Use assertRaises as a context manager to verify that the 
            # expected exception is raised.
            with self.assertRaises(ImproperlyConfigured) as cm:
                get_health_check_secret()

            # Check the exception message
            self.assertIn("environment variable is not set", str(cm.exception))

    def test_get_health_check_secret_returns_value_if_present(self):
        """
        Test that get_health_check_secret returns the correct value
        when the environment variable is set.
        """
        # Set the environment variable
        secret = 'my-test-secret'
        with patch.dict(os.environ, {'HEALTH_CHECK_SECRET': secret}):
            retrieved_secret = get_health_check_secret()
            self.assertEqual(retrieved_secret, secret)
    
    @patch.dict(os.environ, {'HEALTH_CHECK_SECRET': 'test-secret'})
    def test_health_check_secret_case_sensitive(self):
        """Test that health check secret is case sensitive."""
        response = self.client.get(
            reverse('health_check'),
            HTTP_X_HEALTH_CHECK_SECRET='TEST-SECRET'  # Different case
        )
        
        self.assertEqual(response.status_code, 403)
    
    @patch.dict(os.environ, {'HEALTH_CHECK_SECRET': 'test-secret'})
    def test_health_check_secret_requires_exact_match(self):
        """
        Test that health check secret requires an exact, case-sensitive 
        match.
        """
        
        test_cases = {
            "superset": "test-secret-extra", # More than the secret
            "subset": "test",               # Less than the secret
            "case_mismatch": "TEST-SECRET", # Wrong case
            "empty": "",                    # Empty string
        }

        for name, payload in test_cases.items():
            with self.subTest(case=name):
                response = self.client.get(
                    reverse('health_check'),
                    HTTP_X_HEALTH_CHECK_SECRET=payload
                )
                self.assertEqual(
                    response.status_code, 
                    403,
                    f"Failed on case '{name}' with payload '{payload}'"
                )

    @patch.dict(os.environ, {'HEALTH_CHECK_SECRET': 'test-secret'})
    @patch('me_website_project.views.compare_digest')
    def test_health_check_uses_secure_comparison(self, mock_compare_digest):
        """
        Test that the view uses a constant-time comparison function to
        prevent timing attacks.
        """
        # Configure the mock to return True so the request succeeds
        mock_compare_digest.return_value = True
        
        # Make the request
        response = self.client.get(
            reverse('health_check'),
            HTTP_X_HEALTH_CHECK_SECRET='any-secret'
        )
        
        self.assertEqual(response.status_code, 200)
        
        # Was compare_digest called?
        mock_compare_digest.assert_called_once()
        
        # Check what it was called with
        args, kwargs = mock_compare_digest.call_args
        provided_secret = args[0]
        expected_secret = args[1]
        
        self.assertEqual(provided_secret, 'any-secret')
        self.assertEqual(expected_secret, 'test-secret')


class HealthCheckIntegrationTests(TestCase):
    """Integration tests for health check functionality."""
    
    @patch.dict(os.environ, {'HEALTH_CHECK_SECRET': 'integration-test-secret'})
    def test_health_check_end_to_end(self):
        """Test complete health check flow."""
        response = self.client.get(
            reverse('health_check'),
            HTTP_X_HEALTH_CHECK_SECRET='integration-test-secret'
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')
        
        data = json.loads(response.content)
        
        # Verify response structure
        self.assertIn('status', data)
        self.assertIn('database', data)
        self.assertIn('timestamp', data)
        
        # Verify values
        self.assertEqual(data['status'], 'healthy')
        self.assertTrue(data['database'])
        
        # Verify timestamp format (ISO 8601)
        from datetime import datetime
        try:
            datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
        except ValueError:
            self.fail("Timestamp is not in valid ISO 8601 format")
    
    @patch.dict(os.environ, {'HEALTH_CHECK_SECRET': 'load-test-secret'})
    def test_health_check_load_test(self):
        """Test health check under load."""
        import threading
        import time
        
        results = []
        errors = []
        
        def make_request():
            try:
                response = self.client.get(
                    reverse('health_check'),
                    HTTP_X_HEALTH_CHECK_SECRET='load-test-secret'
                )
                results.append(response.status_code)
            except Exception as e:
                errors.append(str(e))
        
        # Create multiple threads to simulate load
        threads = []
        for i in range(20):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
        
        # Start all threads
        start_time = time.time()
        for thread in threads:
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        end_time = time.time()
        
        # All requests should succeed
        self.assertEqual(len(errors), 0, f"Errors occurred: {errors}")
        self.assertEqual(len(results), 20)
        self.assertTrue(all(status == 200 for status in results))
        
        # All requests should complete within reasonable time
        total_time = end_time - start_time
        self.assertLess(total_time, 5.0, f"Load test took too long: {total_time:.2f}s")
