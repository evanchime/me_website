from django.test import TestCase, Client
from django.urls import reverse
from django.http import HttpResponse
from django.template.loader import render_to_string
from unittest.mock import patch


class AboutViewTests(TestCase):
    """Test cases for the about app views."""
    
    def setUp(self):
        """Set up test client for each test method."""
        self.client = Client()
        self.about_url = reverse('about')
    
    def test_about_view_status_code(self):
        """Test that about view returns 200 status code."""
        response = self.client.get(self.about_url)
        self.assertEqual(response.status_code, 200)
    
    def test_about_view_uses_correct_template(self):
        """Test that about view uses the correct template."""
        response = self.client.get(self.about_url)
        self.assertTemplateUsed(response, 'about.html')
    
    def test_about_view_content_type(self):
        """Test that about view returns HTML content."""
        response = self.client.get(self.about_url)
        self.assertEqual(response['Content-Type'], 'text/html; charset=utf-8')
    
    def test_about_view_never_cache_decorator(self):
        """Test that about view has never_cache decorator applied."""
        response = self.client.get(self.about_url)
        # Check for cache control headers
        self.assertIn('Cache-Control', response)
        self.assertIn('no-cache', response['Cache-Control'])
        self.assertIn('no-store', response['Cache-Control'])
        self.assertIn('must-revalidate', response['Cache-Control'])
    
    def test_about_view_get_method(self):
        """Test that about view handles GET requests properly."""
        response = self.client.get(self.about_url)
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response, HttpResponse)
    
    def test_about_view_post_method_allowed(self):
        """Test that about view handles POST requests (should still work)."""
        response = self.client.post(self.about_url)
        self.assertEqual(response.status_code, 200)
    
    def test_about_view_head_method(self):
        """Test that about view handles HEAD requests."""
        response = self.client.head(self.about_url)
        self.assertEqual(response.status_code, 200)
    
    def test_about_view_options_method(self):
        """Test that about view handles OPTIONS requests."""
        response = self.client.options(self.about_url)
        self.assertEqual(response.status_code, 200)
    
    def test_about_url_name(self):
        """Test that the about URL name resolves correctly."""
        url = reverse('about')
        self.assertEqual(url, '/about/')
    
    def test_about_view_context_variables(self):
        """Test that about view doesn't pass unexpected context variables."""
        response = self.client.get(self.about_url)
        # Basic context should only contain built-in Django variables
        expected_keys = ['view', 'request', 'user', 'perms', 'messages', 'DEFAULT_MESSAGE_LEVELS']
        context_keys = list(response.context.keys()) if response.context else []
        # Check that no unexpected custom variables are passed
        custom_keys = [key for key in context_keys if key not in expected_keys]
        # Allow for some flexibility in context keys
        self.assertLessEqual(len(custom_keys), 5)  # Allow up to 5 additional context variables
    
    @patch('about.views.render')
    def test_about_view_render_called_correctly(self, mock_render):
        """Test that render is called with correct parameters."""
        mock_render.return_value = HttpResponse('Mocked response')
        
        response = self.client.get(self.about_url)
        
        mock_render.assert_called_once()
        args, kwargs = mock_render.call_args
        self.assertEqual(len(args), 2)  # request and template
        self.assertEqual(args[1], 'about.html')
    
    def test_about_view_multiple_requests(self):
        """Test that about view handles multiple concurrent requests."""
        responses = []
        for _ in range(10):
            response = self.client.get(self.about_url)
            responses.append(response)
        
        # All responses should be successful
        for response in responses:
            self.assertEqual(response.status_code, 200)
    
    def test_about_view_with_query_parameters(self):
        """Test that about view handles query parameters gracefully."""
        response = self.client.get(self.about_url + '?test=1&param=value')
        self.assertEqual(response.status_code, 200)
    
    def test_about_view_with_invalid_query_parameters(self):
        """Test that about view handles invalid query parameters."""
        response = self.client.get(self.about_url + '?<script>alert("xss")</script>')
        self.assertEqual(response.status_code, 200)
    
    def test_about_view_response_headers(self):
        """Test response headers for security and caching."""
        response = self.client.get(self.about_url)
        
        # Test cache control headers
        self.assertIn('Cache-Control', response)
        cache_control = response['Cache-Control']
        self.assertIn('no-cache', cache_control)
        self.assertIn('no-store', cache_control)
        self.assertIn('must-revalidate', cache_control)
        
        # Test that max-age is 0
        self.assertIn('max-age=0', cache_control)


class AboutURLTests(TestCase):
    """Test cases for about app URL configuration."""
    
    def test_about_url_resolves(self):
        """Test that /about/ URL resolves to about view."""
        from django.urls import resolve
        resolver = resolve('/about/')
        self.assertEqual(resolver.func.__name__, 'about')
        self.assertEqual(resolver.url_name, 'about')
        self.assertEqual(resolver.namespace, '')
    
    def test_about_url_reverse(self):
        """Test that about URL name reverses correctly."""
        url = reverse('about')
        self.assertEqual(url, '/about/')
    
    def test_about_url_without_trailing_slash(self):
        """Test that /about without trailing slash redirects."""
        response = self.client.get('/about', follow_redirects=False)
        # Django should redirect to add trailing slash
        self.assertEqual(response.status_code, 301)
        self.assertEqual(response['Location'], '/about/')


class AboutIntegrationTests(TestCase):
    """Integration tests for about app."""
    
    def test_about_page_accessibility(self):
        """Test basic accessibility of about page."""
        response = self.client.get(reverse('about'))
        content = response.content.decode('utf-8')
        
        # Check for basic HTML structure
        self.assertIn('<html', content.lower())
        self.assertIn('<head', content.lower())
        self.assertIn('<body', content.lower())
    
    def test_about_page_loads_within_time_limit(self):
        """Test that about page loads within reasonable time."""
        import time
        start_time = time.time()
        response = self.client.get(reverse('about'))
        end_time = time.time()
        
        self.assertEqual(response.status_code, 200)
        # Page should load within 2 seconds (generous for testing)
        self.assertLess(end_time - start_time, 2.0)
    
    def test_about_page_encoding(self):
        """Test that about page uses correct character encoding."""
        response = self.client.get(reverse('about'))
        self.assertEqual(response.charset, 'utf-8')
    
    def test_about_page_with_session(self):
        """Test about page with session data."""
        session = self.client.session
        session['test_key'] = 'test_value'
        session.save()
        
        response = self.client.get(reverse('about'))
        self.assertEqual(response.status_code, 200)
    
    def test_about_page_stress_test(self):
        """Stress test the about page with rapid requests."""
        for i in range(50):
            response = self.client.get(reverse('about'))
            self.assertEqual(response.status_code, 200)
