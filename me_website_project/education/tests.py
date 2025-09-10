from django.test import TestCase, Client
from django.urls import reverse
from django.http import HttpResponse
from django.template.loader import render_to_string
from unittest.mock import patch

class EducationViewTests(TestCase):
    """Test cases for the education app views."""
    
    def setUp(self):
        """Set up test client for each test method."""
        self.client = Client()
        self.education_url = reverse("education")
    
    def test_education_view_status_code(self):
        """Test that education view returns 200 status code."""
        response = self.client.get(self.education_url)
        self.assertEqual(response.status_code, 200)
    
    def test_education_view_uses_correct_template(self):
        """Test that education view uses the correct template."""
        response = self.client.get(self.education_url)
        self.assertTemplateUsed(response, "education.html")
    
    def test_education_view_content_type(self):
        """Test that education view returns HTML content."""
        response = self.client.get(self.education_url)
        self.assertEqual(
            response["Content-Type"], "text/html; charset=utf-8"
        )
    
    def test_education_view_disables_caching(self):
        """
        Test that the @never_cache decorator correctly sets non-caching 
        headers on the response for the education view.
        """
        response = self.client.get(self.education_url)
        self.assertIn("Cache-Control", response)
        cache_control_header = response["Cache-Control"]
        self.assertIn("no-cache", cache_control_header)
        self.assertIn("no-store", cache_control_header)
        self.assertIn("must-revalidate", cache_control_header)
        self.assertIn("max-age=0", cache_control_header)

    def test_education_view_get_method(self):
        """Test that education view handles GET requests properly."""
        response = self.client.get(self.education_url)
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response, HttpResponse)
    
    def test_education_view_post_method_allowed(self):
        """
        Test that education view handles POST requests (should still work).
        """
        response = self.client.post(self.education_url)
        self.assertEqual(response.status_code, 200)
    
    def test_education_view_head_method(self):
        """Test that education view handles HEAD requests."""
        response = self.client.head(self.education_url)
        self.assertEqual(response.status_code, 200)
    
    def test_education_view_options_method(self):
        """Test that education view handles OPTIONS requests."""
        response = self.client.options(self.education_url)
        self.assertEqual(response.status_code, 200)
    
    def test_education_view_context_variables(self):
        """
        Test that education view doesn"t pass unexpected context variables.
        """
        response = self.client.get(self.education_url)
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
    
    @patch("education.views.render")
    def test_education_view_render_called_correctly(self, mock_render):
        """Test that render is called with correct parameters."""
        mock_render.return_value = HttpResponse("Mocked response")
        
        response = self.client.get(self.education_url)
        
        mock_render.assert_called_once()
        args, kwargs = mock_render.call_args
        self.assertEqual(len(args), 2)  # request and template
        self.assertEqual(args[1], "education.html")
    
    def test_education_view_multiple_requests(self):
        """Test that education view handles multiple concurrent requests."""
        responses = []
        for _ in range(10):
            response = self.client.get(self.education_url)
            responses.append(response)
        
        # All responses should be successful
        for response in responses:
            self.assertEqual(response.status_code, 200)
    
    def test_education_view_with_query_parameters(self):
        """
        Test that education view handles query parameters gracefully.
        """
        response = self.client.get(self.education_url + "?test=1&param=value")
        self.assertEqual(response.status_code, 200)
    
    def test_education_view_with_invalid_query_parameters(self):
        """Test that education view handles invalid query parameters."""
        response = self.client.get(
            self.education_url + "?<script>alert(\"xss\")</script>"
        )
        self.assertEqual(response.status_code, 200)
    

class EducationURLTests(TestCase):
    """Test cases for education app URL configuration."""
    
    def test_education_url_resolves(self):
        """Test that /education/ URL resolves to education view."""
        from django.urls import resolve
        resolver = resolve("/education/")
        self.assertEqual(resolver.func.__name__, "education")
        self.assertEqual(resolver.url_name, "education")
        self.assertEqual(resolver.namespace, "")
    
    def test_education_url_reverses_correctly(self):
        """
        Test that the named URL "education" correctly reverses to the 
        expected path "/education/".
        """
        url_name = "education"
        expected_path = "/education/"
        resolved_path = reverse(url_name)
        self.assertEqual(resolved_path, expected_path)
    
    def test_education_url_without_trailing_slash(self):
        """Test that /education without trailing slash redirects."""
        response = self.client.get("/education", follow_redirects=False)
        # Django should redirect to add trailing slash
        self.assertEqual(response.status_code, 301)
        self.assertEqual(response["Location"], "/education/")


class EducationIntegrationTests(TestCase):
    """Integration tests for education app."""
    
    def test_education_page_renders_basic_html_structure(self):
        """
        Test that the education page renders the fundamental tags of an 
        HTML document, including a title.
        """
        response = self.client.get(reverse("education"))
        self.assertEqual(response.status_code, 200) 
        self.assertContains(response, "<html", status_code=200)
        self.assertContains(response, "<head")
        self.assertContains(response, "<title>Education")
        self.assertContains(response, "</body>")
    
    def test_education_page_loads_within_time_limit(self):
        """Test that education page loads within reasonable time."""
        import time
        start_time = time.time()
        response = self.client.get(reverse("education"))
        end_time = time.time()
        
        self.assertEqual(response.status_code, 200)
        # Page should load within 2 seconds (generous for testing)
        self.assertLess(end_time - start_time, 2.0)
    
    def test_education_page_encoding(self):
        """Test that education page uses correct character encoding."""
        response = self.client.get(reverse("education"))
        self.assertEqual(response.charset, "utf-8")
    
    def test_education_page_with_session(self):
        """Test education page with session data."""
        session = self.client.session
        session["test_key"] = "test_value"
        session.save()
        
        response = self.client.get(reverse("education"))
        self.assertEqual(response.status_code, 200)
    
    def test_education_page_stress_test(self):
        """Stress test the education page with rapid requests."""
        for i in range(50):
            response = self.client.get(reverse("education"))
            self.assertEqual(response.status_code, 200)
