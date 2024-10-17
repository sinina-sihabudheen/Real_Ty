import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'realty_b.settings')

from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application
from channels.auth import AuthMiddlewareStack
from notification_chat.routing import websocket_urlpatterns 


from channels.security.websocket import AllowedHostsOriginValidator



application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AllowedHostsOriginValidator(
        AuthMiddlewareStack(
            URLRouter(
                websocket_urlpatterns  
            )
        )
    ),
})
