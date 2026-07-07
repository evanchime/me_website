from django.http import HttpResponse

class ALBHealthCheckMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # If the request is for our health check path, return 200 OK 
        if request.path == '/health/':
            return HttpResponse("OK")
        
        # Otherwise, proceed to the next middleware
        return self.get_response(request)
