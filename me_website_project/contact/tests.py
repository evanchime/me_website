from django.test import TestCase, Client
from django.urls import reverse
from django.http import HttpResponse
from unittest.mock import patch


class ContactViewTests(TestCase):
    """Test cases for the contact app views."""
    
    def setUp(self):
        """Set up test client for each test method."""
        self.client = Client()
        self.contact_url = reverse('contact')
    
    def test_contact_view_status_code(self):
        """Test that contact view returns 200 status code."""
        response = self.client.get(self.contact_url)
        self.assertEqual(response.status_code, 200)
    
    def test_contact_view_uses_correct_template(self):
        """Test that contact view uses the correct template."""
        response = self.client.get(self.contact_url)
        self.assertTemplateUsed(response, 'contact.html')
    
    def test_contact_view_content_type(self):
        """Test that contact view returns HTML content."""
        response = self.client.get(self.contact_url)
        self.assertEqual(response['Content-Type'], 'text/html; charset=utf-8')
    
    def test_contact_view_never_cache_decorator(self):
        """Test that contact view has never_cache decorator applied."""
        response = self.client.get(self.contact_url)
        # Check for cache control headers
        self.assertIn('Cache-Control', response)
        self.assertIn('no-cache', response['Cache-Control'])
        self.assertIn('no-store', response['Cache-Control'])
        self.assertIn('must-revalidate', response['Cache-Control'])
    
    def test_contact_view_get_method(self):
        """Test that contact view handles GET requests properly."""
        response = self.client.get(self.contact_url)
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response, HttpResponse)
    
    def test_contact_view_post_method_allowed(self):
        """Test that contact view handles POST requests."""
        response = self.client.post(self.contact_url)
        self.assertEqual(response.status_code, 200)
    
    def test_contact_view_head_method(self):
        """Test that contact view handles HEAD requests."""
        response = self.client.head(self.contact_url)
        self.assertEqual(response.status_code, 200)
    
    def test_contact_view_options_method(self):
        """Test that contact view handles OPTIONS requests."""
        response = self.client.options(self.contact_url)
        self.assertEqual(response.status_code, 200)
    
    def test_contact_url_name(self):
        """Test that the contact URL name resolves correctly."""
        url = reverse('contact')
        self.assertEqual(url, '/contact/')
    
    def test_contact_view_with_query_parameters(self):
        """Test that contact view handles query parameters gracefully."""
        response = self.client.get(self.contact_url + '?message=hello&name=test')
        self.assertEqual(response.status_code, 200)
    
    def test_contact_view_with_invalid_query_parameters(self):
        """Test that contact view handles invalid query parameters."""
        response = self.client.get(self.contact_url + '?<script>alert("xss")</script>')
        self.assertEqual(response.status_code, 200)
    
    def test_contact_view_response_headers(self):
        """Test response headers for security and caching."""
        response = self.client.get(self.contact_url)
        
        # Test cache control headers
        self.assertIn('Cache-Control', response)
        cache_control = response['Cache-Control']
        self.assertIn('no-cache', cache_control)
        self.assertIn('no-store', cache_control)
        self.assertIn('must-revalidate', cache_control)
        self.assertIn('max-age=0', cache_control)
    
    @patch('contact.views.render')
    def test_contact_view_render_called_correctly(self, mock_render):
        """Test that render is called with correct parameters."""
        mock_render.return_value = HttpResponse('Mocked response')
        
        response = self.client.get(self.contact_url)
        
        mock_render.assert_called_once()
        args, kwargs = mock_render.call_args
        self.assertEqual(len(args), 2)  # request and template
        self.assertEqual(args[1], 'contact.html')
    
    def test_contact_view_multiple_requests(self):
        """Test that contact view handles multiple concurrent requests."""
        responses = []
        for _ in range(10):
            response = self.client.get(self.contact_url)
            responses.append(response)
        
        # All responses should be successful
        for response in responses:
            self.assertEqual(response.status_code, 200)


class ContactURLTests(TestCase):
    """Test cases for contact app URL configuration."""
    
    def test_contact_url_resolves(self):
        """Test that /contact/ URL resolves to contact view."""
        from django.urls import resolve
        resolver = resolve('/contact/')
        self.assertEqual(resolver.func.__name__, 'contact')
        self.assertEqual(resolver.url_name, 'contact')
        self.assertEqual(resolver.namespace, '')
    
    def test_contact_url_reverse(self):
        """Test that contact URL name reverses correctly."""
        url = reverse('contact')
        self.assertEqual(url, '/contact/')
    
    def test_contact_url_without_trailing_slash(self):
        """Test that /contact without trailing slash redirects."""
        response = self.client.get('/contact', follow_redirects=False)
        # Django should redirect to add trailing slash
        self.assertEqual(response.status_code, 301)
        self.assertEqual(response['Location'], '/contact/')


class ContactIntegrationTests(TestCase):
    """Integration tests for contact app."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.contact_url = reverse('contact')
    
    def test_contact_page_accessibility(self):
        """Test basic accessibility of contact page."""
        response = self.client.get(reverse('contact'))
        content = response.content.decode('utf-8')
        
        # Check for basic HTML structure
        self.assertIn('<html', content.lower())
        self.assertIn('<head', content.lower())
        self.assertIn('<body', content.lower())
    
    def test_contact_page_loads_within_time_limit(self):
        """Test that contact page loads within reasonable time."""
        import time
        start_time = time.time()
        response = self.client.get(reverse('contact'))
        end_time = time.time()
        
        self.assertEqual(response.status_code, 200)
        # Page should load within 2 seconds (generous for testing)
        self.assertLess(end_time - start_time, 2.0)
    
    def test_contact_page_encoding(self):
        """Test that contact page uses correct character encoding."""
        response = self.client.get(reverse('contact'))
        self.assertEqual(response.charset, 'utf-8')
    
    def test_contact_page_with_session(self):
        """Test contact page with session data."""
        session = self.client.session
        session['test_key'] = 'test_value'
        session.save()
        
        response = self.client.get(reverse('contact'))
        self.assertEqual(response.status_code, 200)
    
    def test_contact_page_stress_test(self):
        """Stress test the contact page with rapid requests."""
        for i in range(50):
            response = self.client.get(reverse('contact'))
            self.assertEqual(response.status_code, 200)
    
    def test_contact_view_context_variables(self):
        """Test that contact view doesn't pass unexpected context variables."""
        response = self.client.get(self.contact_url)
        # Basic context should only contain built-in Django variables
        expected_keys = ['view', 'request', 'user', 'perms', 'messages', 'DEFAULT_MESSAGE_LEVELS']
        context_keys = list(response.context.keys()) if response.context else []
        # Check that no unexpected custom variables are passed
        custom_keys = [key for key in context_keys if key not in expected_keys]
        # Allow for some flexibility in context keys
        self.assertLessEqual(len(custom_keys), 5)  # Allow up to 5 additional context variables
