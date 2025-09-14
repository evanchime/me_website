"""
Health Check Endpoint Module.

This module provides a comprehensive health check endpoint for this 
Django application. It checks the application's ability to connect to 
the database. A secret header must be provided to access the endpoint 
securely.

Environment Variables:
    HEALTH_CHECK_SECRET: The secret token required for authentication.

Settings:
    APP_VERSION: (Optional) The application version to return in the 
    health check response.
"""

from django.http import JsonResponse
from django.views.decorators.http import require_GET
from django.views.decorators.csrf import csrf_exempt
from django.db import connection, OperationalError
from hmac import compare_digest
from django.conf import settings
from .config_checks import get_health_check_secret
import logging

logger = logging.getLogger(__name__)

# Cache the secret at module level for efficiency.
EXPECTED_HEALTH_CHECK_SECRET = get_health_check_secret()

def check_database():
    """
    Test database connectivity.

    This function attempts to open a database cursor and execute a 
    simple query. It returns True if the query executes successfully, 
    otherwise logs the error and returns False.

    Returns:
        bool: True if the database is reachable, False on error.
    """
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        return True
    except OperationalError as e:
        logger.error("Database check failed: %s", e)
        return False


@csrf_exempt
@require_GET
def health_check(request):
    """
    Comprehensive health check endpoint.

    This view function handles GET requests to the health check endpoint. 
    It validates the secret header, then runs a health check for 
    database. Based on the results, it returns a JSON response with the 
    overall health status, individual service statuses, and the 
    application version.
    
    The response status code is:
        - 200 (OK): If the check passes.
        - 503 (Service Unavailable): If the check fails.
        - 401 (Unauthorized): If the provided secret is missing or 
        incorrect.

    Args:
        request (HttpRequest): The incoming HTTP request containing the 
        secret header 'X-Health-Check-Secret'.

    Returns:
        JsonResponse: A JSON response containing the overall health 
        status, status of the database, and optionally the application 
        version.
    """
    try:
        # Validate the secret header.
        provided_secret = request.headers.get("X-Health-Check-Secret")
        logger.debug(
            f"Health check secret validation - Provided: '{provided_secret}', "
            "Expected: '{EXPECTED_HEALTH_CHECK_SECRET}'"
        )
        if not compare_digest(
            provided_secret or "", EXPECTED_HEALTH_CHECK_SECRET or ""
        ):
            return JsonResponse({"error": "Unauthorized"}, status=401)

        # Run health check.
        checks = {
            "database": check_database(),
        }

        # Determine overall status.
        status_code = 200 if all(checks.values()) else 503
        status = "healthy" if status_code == 200 else "unhealthy"

        return JsonResponse(
            {
                "status": status,
                "services": checks,
                "version": getattr(settings, "APP_VERSION", "unknown"),
            },
            status=status_code,
        )
    except Exception as e:
        logger.exception("Health check failed")
        return JsonResponse(
            {
                "status": "error", 
                "details": "Internal Server Error. Please try again later."
            },
            status=503
        )
