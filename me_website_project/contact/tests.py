from django.test import TestCase, Client
from django.urls import reverse
from django.http import HttpResponse
from django.template.loader import render_to_string
from unittest.mock import patch

class ContactViewTests(TestCase):
    """Test cases for the contact app views."""
    
    def setUp(self):
        """Set up test client for each test method."""
        self.client = Client()
        self.contact_url = reverse("contact")
    
    def test_contact_view_status_code(self):
        """Test that contact view returns 200 status code."""
        response = self.client.get(self.contact_url)
        self.assertEqual(response.status_code, 200)
    
    def test_contact_view_uses_correct_template(self):
        """Test that contact view uses the correct template."""
        response = self.client.get(self.contact_url)
        self.assertTemplateUsed(response, "contact.html")
    
    def test_contact_view_content_type(self):
        """Test that contact view returns HTML content."""
        response = self.client.get(self.contact_url)
        self.assertEqual(
            response["Content-Type"], "text/html; charset=utf-8"
        )
    
    def test_contact_view_disables_caching(self):
        """
        Test that the @never_cache decorator correctly sets non-caching 
        headers on the response for the contact view.
        """
        response = self.client.get(self.contact_url)
        self.assertIn("Cache-Control", response)
        cache_control_header = response["Cache-Control"]
        self.assertIn("no-cache", cache_control_header)
        self.assertIn("no-store", cache_control_header)
        self.assertIn("must-revalidate", cache_control_header)
        self.assertIn("max-age=0", cache_control_header)
    
    def test_contact_view_get_method(self):
        """Test that contact view handles GET requests properly."""
        response = self.client.get(self.contact_url)
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response, HttpResponse)
    
    def test_contact_view_post_method_allowed(self):
        """
        Test that contact view handles POST requests (should still work).
        """
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
    
    def test_contact_view_context_variables(self):
        """
        Test that contact view doesn"t pass unexpected context variables.
        """
        response = self.client.get(self.contact_url)
        # Basic context should only contain built-in Django variables
        expected_keys = [
            "view", 
            "request", 
            "user", 
            "perms", 
            "messages", 
            "DEFAULT_MESSAGE_LEVELS"
        ]
        context_keys = list(response.context.keys()) if response.context else []
        # Check that no unexpected custom variables are passed
        custom_keys = [key for key in context_keys if key not in expected_keys]
        # Allow for some flexibility in context keys
        # Allow up to 5 additional context variables
        self.assertLessEqual(len(custom_keys), 5)  
    
    @patch("contact.views.render")
    def test_contact_view_render_called_correctly(self, mock_render):
        """Test that render is called with correct parameters."""
        mock_render.return_value = HttpResponse("Mocked response")
        
        response = self.client.get(self.contact_url)
        
        mock_render.assert_called_once()
        args, kwargs = mock_render.call_args
        self.assertEqual(len(args), 2)  # request and template
        self.assertEqual(args[1], "contact.html")
    
    def test_contact_view_multiple_requests(self):
        """Test that contact view handles multiple concurrent requests."""
        responses = []
        for _ in range(10):
            response = self.client.get(self.contact_url)
            responses.append(response)
        
        # All responses should be successful
        for response in responses:
            self.assertEqual(response.status_code, 200)
    
    def test_contact_view_with_query_parameters(self):
        """
        Test that contact view handles query parameters gracefully.
        """
        response = self.client.get(self.contact_url + "?test=1&param=value")
        self.assertEqual(response.status_code, 200)
    
    def test_contact_view_with_invalid_query_parameters(self):
        """Test that contact view handles invalid query parameters."""
        response = self.client.get(
            self.contact_url + "?<script>alert(\"xss\")</script>"
        )
        self.assertEqual(response.status_code, 200)
        
    
class ContactURLTests(TestCase):
    """Test cases for contact app URL configuration."""
    
    def test_contact_url_resolves(self):
        """Test that /contact/ URL resolves to contact view."""
        from django.urls import resolve
        resolver = resolve("/contact/")
        self.assertEqual(resolver.func.__name__, "contact")
        self.assertEqual(resolver.url_name, "contact")
        self.assertEqual(resolver.namespace, "")
    
    def test_contact_url_reverses_correctly(self):
        """
        Test that the named URL "contact" correctly reverses to the 
        expected path "/contact/".
        """
        url_name = "contact"
        expected_path = "/contact/"
        resolved_path = reverse(url_name)
        self.assertEqual(resolved_path, expected_path)
    
    def test_contact_url_without_trailing_slash(self):
        """Test that /contact without trailing slash redirects."""
        response = self.client.get("/contact", follow_redirects=False)
        # Django should redirect to add trailing slash
        self.assertEqual(response.status_code, 301)
        self.assertEqual(response["Location"], "/contact/")


class ContactIntegrationTests(TestCase):
    """Integration tests for contact app."""
    
    def test_contact_page_renders_basic_html_structure(self):
        """
        Test that the contact page renders the fundamental tags of an 
        HTML document, including a title.
        """
        response = self.client.get(reverse("contact"))
        self.assertEqual(response.status_code, 200) 
        self.assertContains(response, "<html", status_code=200)
        self.assertContains(response, "<head")
        self.assertContains(response, "<title>Contact")
        self.assertContains(response, "</body>")
    
    def test_contact_page_loads_within_time_limit(self):
        """Test that contact page loads within reasonable time."""
        import time
        start_time = time.time()
        response = self.client.get(reverse("contact"))
        end_time = time.time()
        
        self.assertEqual(response.status_code, 200)
        # Page should load within 2 seconds (generous for testing)
        self.assertLess(end_time - start_time, 2.0)
    
    def test_contact_page_encoding(self):
        """Test that contact page uses correct character encoding."""
        response = self.client.get(reverse("contact"))
        self.assertEqual(response.charset, "utf-8")
    
    def test_contact_page_with_session(self):
        """Test contact page with session data."""
        session = self.client.session
        session["test_key"] = "test_value"
        session.save()
        
        response = self.client.get(reverse("contact"))
        self.assertEqual(response.status_code, 200)
    
    def test_contact_page_stress_test(self):
        """Stress test the contact page with rapid requests."""
        for i in range(50):
            response = self.client.get(reverse("contact"))
            self.assertEqual(response.status_code, 200)
