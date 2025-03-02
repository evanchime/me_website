from health_check.views import MainView
from django.http import JsonResponse
import environ

class SecureHealthCheckView(MainView):
    """
    A secure health check view that validates requests using a secret 
    token.

    This view extends the `MainView` from `django-health-check` and adds 
    an additional layer of security by requiring a valid 
    `X-Health-Check-Secret` header to access the health check endpoint.

    Attributes:
        None

    Methods:
        get(request, *args, **kwargs): Processes GET requests and 
        validates the secret token.
    """

    def get(self, request, *args, **kwargs):
        """
        Handle GET requests to the health check endpoint.

        Args:
            request (HttpRequest): The incoming HTTP request.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            JsonResponse: If the secret token is invalid, returns a 401 
            Unauthorized response.
            HttpResponse: If the secret token is valid, returns the 
            standard health check response.

        """
        env = environ.Env()
        expected_secret = env.str("HEALTH_CHECK_SECRET")
        provided_secret = request.headers.get("X-Health-Check-Secret")

        if expected_secret and provided_secret != expected_secret:
            return JsonResponse({"status": "unauthorized"}, status=401)
        
        return super().get(request, *args, **kwargs)