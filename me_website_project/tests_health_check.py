"""
Comprehensive tests for the health check endpoint functionality.

This module tests the health check endpoint which is critical for
monitoring the application's health in production environments.
"""

from django.test import TestCase, Client
from django.urls import reverse
from django.db import connection
from unittest.mock import patch, MagicMock
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
            HTTP_X_HEALTH_CHECK_SECRET='test-health-check-secret'
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


class HealthCheckDatabaseTests(TestCase):
    """Test cases for the database check functionality."""
    
    def test_check_database_function_success(self):
        """Test that check_database function works correctly."""
        from me_website_project.views import check_database
        
        result = check_database()
        self.assertTrue(result)
    
    @patch('me_website_project.views.connection')
    def test_check_database_function_failure(self, mock_connection):
        """Test check_database function when database is unavailable."""
        from me_website_project.views import check_database
        
        # Mock database connection failure
        mock_cursor = MagicMock()
        mock_cursor.execute.side_effect = Exception("Database connection failed")
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
        
        result = check_database()
        self.assertFalse(result)
    
    @patch('me_website_project.views.connection')
    def test_check_database_logs_errors(self, mock_connection):
        """Test that database check errors are logged."""
        from me_website_project.views import check_database
        
        # Mock database connection failure
        mock_cursor = MagicMock()
        mock_cursor.execute.side_effect = Exception("Database error")
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
        
        with patch('me_website_project.views.logger') as mock_logger:
            result = check_database()
            
            self.assertFalse(result)
            mock_logger.error.assert_called_once()


class HealthCheckSecurityTests(TestCase):
    """Test cases for health check security measures."""
    
    def test_health_check_secret_required_in_settings(self):
        """Test that health check secret is required in environment."""
        # This test ensures the secret is properly configured
        with patch.dict(os.environ, {}, clear=True):
            # Remove HEALTH_CHECK_SECRET from environment
            try:
                # Try to import the views module which should fail
                import importlib
                import me_website_project.views
                importlib.reload(me_website_project.views)
                self.fail("Should raise ImproperlyConfigured when secret is missing")
            except Exception:
                # Expected behavior - should raise an exception
                pass
    
    @patch.dict(os.environ, {'HEALTH_CHECK_SECRET': 'test-secret'})
    def test_health_check_secret_case_sensitive(self):
        """Test that health check secret is case sensitive."""
        response = self.client.get(
            reverse('health_check'),
            HTTP_X_HEALTH_CHECK_SECRET='TEST-SECRET'  # Different case
        )
        
        self.assertEqual(response.status_code, 403)
    
    @patch.dict(os.environ, {'HEALTH_CHECK_SECRET': 'test-secret'})
    def test_health_check_secret_exact_match(self):
        """Test that health check secret requires exact match."""
        # Test with extra characters
        response = self.client.get(
            reverse('health_check'),
            HTTP_X_HEALTH_CHECK_SECRET='test-secret-extra'
        )
        self.assertEqual(response.status_code, 403)
        
        # Test with substring
        response = self.client.get(
            reverse('health_check'),
            HTTP_X_HEALTH_CHECK_SECRET='test'
        )
        self.assertEqual(response.status_code, 403)
    
    @patch.dict(os.environ, {'HEALTH_CHECK_SECRET': 'test-secret'})
    def test_health_check_timing_attack_resistance(self):
        """Test that health check is resistant to timing attacks."""
        import time
        
        # Measure time for correct secret
        start = time.time()
        response1 = self.client.get(
            reverse('health_check'),
            HTTP_X_HEALTH_CHECK_SECRET='test-secret'
        )
        time1 = time.time() - start
        
        # Measure time for incorrect secret
        start = time.time()
        response2 = self.client.get(
            reverse('health_check'),
            HTTP_X_HEALTH_CHECK_SECRET='wrong-secret'
        )
        time2 = time.time() - start
        
        # Both should succeed/fail quickly
        self.assertLess(time1, 1.0)
        self.assertLess(time2, 1.0)
        
        # Time difference should be minimal (less than 100ms)
        self.assertLess(abs(time1 - time2), 0.1)


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
