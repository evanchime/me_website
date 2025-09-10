from django.test import TestCase, RequestFactory
from django.http import HttpResponse
from unittest.mock import patch, MagicMock
import logging
from .views import (
    bad_request, permission_denied, page_not_found, server_error
)

# Disable logging during tests to keep the test output clean
logging.disable(logging.CRITICAL)

class ErrorHandlerViewTests(TestCase):
    """
    Test cases for custom error handler views (400, 403, 404, 500).
    """

    def setUp(self):
        """
        Set up a RequestFactory instance to generate mock requests for 
        each test.
        """
        self.factory = RequestFactory()

    @patch('core.views.render')
    def test_bad_request_view(self, mock_render):
        """
        Test the bad_request (400) view.
        """
        # Mock the render function to return a simple HttpResponse
        mock_render.return_value = HttpResponse(status=400)
        
        # Create a mock request
        request = self.factory.get('/test-path')
        
        # Create a mock exception
        exception = ValueError("A test validation error occurred.")
        
        # Call the view function with the request and exception
        response = bad_request(request, exception)
        
        # Test that the status code is 400
        self.assertEqual(response.status_code, 400)
        
        # Test that render was called correctly
        mock_render.assert_called_once_with(
            request, 'errors/400.html', status=400
        )

    @patch('core.views.render')
    def test_permission_denied_view(self, mock_render):
        """
        Test the permission_denied (403) view.
        """
        # Mock the render function to return a simple HttpResponse
        mock_render.return_value = HttpResponse(status=403)

        # Create a mock request
        request = self.factory.get('/forbidden-resource')

        # Create a mock exception
        exception = Exception("User does not have permission.")
        
        # Call the view function with the request and exception
        response = permission_denied(request, exception)
        
        # Test that the status code is 403
        self.assertEqual(response.status_code, 403)
        
        # Test that render was called correctly
        mock_render.assert_called_once_with(
            request, 'errors/403.html', status=403
        )

    @patch('core.views.render')
    def test_page_not_found_view(self, mock_render):
        """
        Test the page_not_found (404) view.
        """
        # Configure the mock 'render' to return a generic response.
        mock_render.return_value = HttpResponse(status=404)

        # Create a mock request object.
        request = self.factory.get('/non-existent-url')

        # Create a mock exception
        exception = Exception("Page not found at this location.")

        # Call the view function directly.
        response = page_not_found(request, exception)
        
        # Test that the status code is 404
        self.assertEqual(response.status_code, 404)

        # Test that render was called correctly
        mock_render.assert_called_once_with(
            request, 'errors/404.html', status=404
        )


    @patch('core.views.render') 
    def test_server_error_view(self, mock_render):
        """
        Test that the server_error (500) view correctly renders the 
        500.html template with a 500 status code.
        """
        # Configure the mock 'render' to return a generic response.
        mock_render.return_value = HttpResponse(status=500)

        # Create a mock request object.
        request = self.factory.get('/path-that-caused-error')

        # Call the view function directly.
        response = server_error(request)

        # Test that the status code is 500
        self.assertEqual(response.status_code, 500)
        
        # Test that render was called correctly
        mock_render.assert_called_once_with(
            request, 'errors/500.html', status=500
        )


    @patch('core.views.logger')
    def test_logging_with_exception(self, mock_logger):
        """
        Test that views log a warning when an exception is provided.
        """
        exception = Exception("Detailed error message.")
        
        # Test 400 logging
        bad_request(self.factory.get('/'), exception)
        mock_logger.warning.assert_called_with(
            f"400 Bad Request: {str(exception)}"
        )

        # Test 403 logging
        permission_denied(self.factory.get('/'), exception)
        mock_logger.warning.assert_called_with(
            f"403 Forbidden: {str(exception)}"
        )
        
        # Test 404 logging
        request_404 = self.factory.get('/not-found')
        page_not_found(request_404, exception)
        mock_logger.warning.assert_called_with(
            f"404 Not Found: {request_404.path} - {str(exception)}"
        )

    @patch('core.views.logger')
    def test_no_logging_without_exception(self, mock_logger):
        """
        Test that views do not attempt to log when no exception is 
        provided.
        """
        # Call views with exception=None (the default)
        bad_request(self.factory.get('/'))
        permission_denied(self.factory.get('/'))
        page_not_found(self.factory.get('/'))
        
        # Assert logger.warning was never called for these executions
        mock_logger.warning.assert_not_called()

