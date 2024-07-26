

from django.utils.deprecation import MiddlewareMixin

class CustomHeaderMiddleware(MiddlewareMixin):
    def process_response(self, request, response):
        response['Cross-Origin-Opener-Policy'] = 'same-origin-allow-popups'
        return response
