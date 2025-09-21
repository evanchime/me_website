"""
Configuration Validation and Retrieval for the Project.

This module centralizes the logic for reading and validating critical
configuration settings from environment variables. It is designed to be
imported at application startup to ensure that the environment is
correctly configured before the server begins handling requests.

The primary goal is to provide a single source of truth for configuration
checks and to raise a clear 
:exc:`~django.core.exceptions.ImproperlyConfigured` exception if a 
required setting is missing. This "fail-fast" approach prevents the 
application from running in a misconfigured state.

Functions:
    get_health_check_secret(): Retrieves the mandatory secret key for the
                               health check endpoint.

Example:
    In a settings or views file, you can ensure the secret is loaded at
    startup::

        from .config_checks import get_health_check_secret

        HEALTH_CHECK_SECRET = get_health_check_secret()

"""
import environ
from django.core.exceptions import ImproperlyConfigured

env = environ.Env()

def get_health_check_secret():
    """Retrieves the health check secret from environment variables.

    This function reads the ``HEALTH_CHECK_SECRET`` from the environment.
    If the variable is not set or is empty, it immediately raises an
    exception to halt application startup, preventing the health check
    endpoint from being exposed without a secret.

    :raises django.core.exceptions.ImproperlyConfigured: If the
        ``HEALTH_CHECK_SECRET`` environment variable is not set.
    :return: The value of the health check secret.
    :rtype: str
    """
    EXPECTED_HEALTH_CHECK_SECRET = env.str("HEALTH_CHECK_SECRET", default=None)
    if EXPECTED_HEALTH_CHECK_SECRET is None:
        raise ImproperlyConfigured(
            "HEALTH_CHECK_SECRET environment variable is not set"
        )
    return EXPECTED_HEALTH_CHECK_SECRET