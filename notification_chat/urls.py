from django.urls import path, include
from .views import (
    MarkMessagesAsRead, MessageListView,
    UnreadMessagesView, 
    
)

urlpatterns = [

    path('messages/<int:seller_id>/', MessageListView.as_view(), name = 'message-list'),
    path('messages/unread/', UnreadMessagesView.as_view(), name = 'unread-messages'),
    path('messages/mark-messages-as-read/<int:sender_id>', MarkMessagesAsRead.as_view(), name = 'mark-messages-as-read'),


]


    