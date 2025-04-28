from django.shortcuts import render
import logging

logger = logging.getLogger(__name__)

def bad_request(request, exception=None):
    if exception:
        logger.warning(f"400 Bad Request: {str(exception)}")
    return render(request, 'errors/400.html', status=400)

def permission_denied(request, exception=None):
    if exception:
        logger.warning(f"403 Forbidden: {str(exception)}")
    return render(request, 'errors/403.html', status=403)

def page_not_found(request, exception=None):
    context = {'path': request.path}
    if exception:
        logger.warning(f"404 Not Found: {request.path} - {str(exception)}")
    return render(request, 'errors/404.html', context, status=404)

def server_error(request):  # No exception parameter for 500
    logger.error("500 Server Error")
    return render(request, 'errors/500.html', status=500)
