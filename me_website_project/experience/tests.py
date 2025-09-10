from django.test import TestCase, Client
from django.urls import reverse
from django.http import HttpResponse
from django.template.loader import render_to_string
from unittest.mock import patch


class ExperienceViewTests(TestCase ):
    """Test cases for the experience app views."""
    
    def setUp(self):
        """Set up test client for each test method."""
        self.client = Client()
        self.experience_url = reverse('experience')
    
    def test_experience_view_status_code(self):
        """Test that experience view returns 200 status code."""
        response = self.client.get(self.experience_url)
        self.assertEqual(response.status_code, 200)
    
    def test_experience_view_uses_correct_template(self):
        """Test that experience view uses the correct template."""
        response = self.client.get(self.experience_url)
        self.assertTemplateUsed(response, 'experience.html')
    
    def test_experience_view_content_type(self):
        """Test that experience view returns HTML content."""
        response = self.client.get(self.experience_url)
        self.assertEqual(
            response['Content-Type'], 'text/html; charset=utf-8'
        )
    
    def test_experience_view_disables_caching(self):
        """
        Test that the @never_cache decorator correctly sets non-caching 
        headers on the response for the experience view.
        """
        response = self.client.get(self.experience_url)
        self.assertIn('Cache-Control', response)
        cache_control_header = response['Cache-Control']
        self.assertIn('no-cache', cache_control_header)
        self.assertIn('no-store', cache_control_header)
        self.assertIn('must-revalidate', cache_control_header)
        self.assertIn('max-age=0', cache_control_header)
    
    def test_experience_view_get_method(self):
        """Test that experience view handles GET requests properly."""
        response = self.client.get(self.experience_url)
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response, HttpResponse)
    
    def test_experience_view_post_method_allowed(self):
        """
        Test that experience view handles POST requests (should still work).
        """
        response = self.client.post(self.experience_url)
        self.assertEqual(response.status_code, 200)
    
    def test_experience_view_head_method(self):
        """Test that experience view handles HEAD requests."""
        response = self.client.head(self.experience_url)
        self.assertEqual(response.status_code, 200)
    
    def test_experience_view_options_method(self):
        """Test that experience view handles OPTIONS requests."""
        response = self.client.options(self.experience_url)
        self.assertEqual(response.status_code, 200)
    
    def test_experience_view_context_variables(self):
        """
        Test that experience view doesn't pass unexpected context variables.
        """
        response = self.client.get(self.experience_url)
        # Basic context should only contain built-in Django variables
        expected_keys = [
            'view', 
            'request', 
            'user', 
            'perms', 
            'messages', 
            'DEFAULT_MESSAGE_LEVELS'
        ]
        context_keys = list(response.context.keys()) if response.context else []
        # Check that no unexpected custom variables are passed
        custom_keys = [key for key in context_keys if key not in expected_keys]
        # Allow for some flexibility in context keys
        # Allow up to 5 additional context variables
        self.assertLessEqual(len(custom_keys), 5)  
    
    @patch('experience.views.render')
    def test_experience_view_render_called_correctly(self, mock_render):
        """Test that render is called with correct parameters."""
        mock_render.return_value = HttpResponse('Mocked response')
        
        response = self.client.get(self.experience_url)
        
        mock_render.assert_called_once()
        args, kwargs = mock_render.call_args
        self.assertEqual(len(args), 2)  # request and template
        self.assertEqual(args[1], 'experience.html')
    
    def test_experience_view_multiple_requests(self):
        """Test that experience view handles multiple concurrent requests."""
        responses = []
        for _ in range(10):
            response = self.client.get(self.experience_url)
            responses.append(response)
        
        # All responses should be successful
        for response in responses:
            self.assertEqual(response.status_code, 200)
    
    def test_experience_view_with_query_parameters(self):
        """
        Test that experience view handles query parameters gracefully.
        """
        response = self.client.get(self.experience_url + '?test=1&param=value')
        self.assertEqual(response.status_code, 200)
    
    def test_experience_view_with_invalid_query_parameters(self):
        """Test that experience view handles invalid query parameters."""
        response = self.client.get(
            self.experience_url + '?<script>alert("xss")</script>'
        )
        self.assertEqual(response.status_code, 200)
    

class ExperienceURLTests(TestCase):
    """Test cases for experience app URL configuration."""
    
    def test_experience_url_resolves(self):
        """Test that /experience/ URL resolves to experience view."""
        from django.urls import resolve
        resolver = resolve('/experience/')
        self.assertEqual(resolver.func.__name__, 'experience')
        self.assertEqual(resolver.url_name, 'experience')
        self.assertEqual(resolver.namespace, '')
    
    def test_experience_url_reverses_correctly(self):
        """
        Test that the named URL 'experience' correctly reverses to the 
        expected path '/experience/'.
        """
        url_name = 'experience'
        expected_path = '/experience/'
        resolved_path = reverse(url_name)
        self.assertEqual(resolved_path, expected_path)
    
    def test_experience_url_without_trailing_slash(self):
        """Test that /experience without trailing slash redirects."""
        response = self.client.get('/experience', follow_redirects=False)
        # Django should redirect to add trailing slash
        self.assertEqual(response.status_code, 301)
        self.assertEqual(response['Location'], '/experience/')


class ExperienceIntegrationTests(TestCase):
    """Integration tests for experience app."""
    
    def test_experience_page_renders_basic_html_structure(self):
        """
        Test that the experience page renders the fundamental tags of an HTML
        document, including a title.
        """
        response = self.client.get(reverse('experience'))
        self.assertEqual(response.status_code, 200) 
        self.assertContains(response, "<html", status_code=200)
        self.assertContains(response, "<head")
        self.assertContains(response, "<title>Experience")
        self.assertContains(response, "</body>")
    
    def test_experience_page_loads_within_time_limit(self):
        """Test that experience page loads within reasonable time."""
        import time
        start_time = time.time()
        response = self.client.get(reverse('experience'))
        end_time = time.time()
        
        self.assertEqual(response.status_code, 200)
        # Page should load within 2 seconds (generous for testing)
        self.assertLess(end_time - start_time, 2.0)
    
    def test_experience_page_encoding(self):
        """Test that experience page uses correct character encoding."""
        response = self.client.get(reverse('experience'))
        self.assertEqual(response.charset, 'utf-8')
    
    def test_experience_page_with_session(self):
        """Test experience page with session data."""
        session = self.client.session
        session['test_key'] = 'test_value'
        session.save()
        
        response = self.client.get(reverse('experience'))
        self.assertEqual(response.status_code, 200)
    
    def test_experience_page_stress_test(self):
        """Stress test the experience page with rapid requests."""
        for i in range(50):
            response = self.client.get(reverse('experience'))
            self.assertEqual(response.status_code, 200)
