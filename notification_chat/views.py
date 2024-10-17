from django.shortcuts import render
from django.utils import timezone
from django.contrib.auth import authenticate
from django.conf import settings
from django.db.models import Sum, Count, Q
from django.views.generic import ListView

from rest_framework import viewsets, status, generics, serializers, permissions
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny,IsAuthenticated

from myapp.models import User, LandProperty, ResidentialProperty, SubscriptionPayment
from myapp.serializers import UserSerializer

from .models import Message
from .serializers import MessageSerializer



class MessageListView(generics.ListAPIView):
    serializer_class = MessageSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        seller_id = self.kwargs['seller_id']
        
        # Retrieve messages where the user is either the sender or the receiver
        return Message.objects.filter(
            Q(sender=user, receiver_id=seller_id) | Q(receiver=user, sender_id=seller_id)
        ).order_by('timestamp')
    

class UnreadMessagesView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        unread_messages = Message.objects.filter(receiver=user, is_read=False) \
                                         .values('sender') \
                                         .annotate(unread_count=Count('id')) \
                                         .order_by('-unread_count')
        senders = []
        for message in unread_messages:
            sender = User.objects.get(id=message['sender'])
            senders.append({
                'sender': sender.id,
                'sender_name': sender.username,
                'unread_count': message['unread_count'],
            })
        return Response(senders)
    
class MarkMessagesAsRead(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, sender_id):
        user = request.user
        messages = Message.objects.filter(sender=sender_id, receiver=user, is_read=False)
        messages.update(is_read=True)
        return Response({"detail": "Messages marked as read."}, status=status.HTTP_200_OK)

    