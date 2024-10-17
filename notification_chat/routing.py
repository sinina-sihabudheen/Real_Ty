from django.urls import re_path, path
from notification_chat.consumers import ChatConsumer


websocket_urlpatterns = [
    path('ws/chat/<int:receiver_id>/', ChatConsumer.as_asgi()),

]