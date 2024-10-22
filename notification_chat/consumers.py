
import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from rest_framework_simplejwt.exceptions import InvalidToken

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        from rest_framework_simplejwt.authentication import JWTAuthentication

        query_string = self.scope['query_string'].decode()  # Decode query string
        params = {}

        # Check if the query string is not empty
        if query_string:
            for param in query_string.split('&'):
                # Split each parameter and check if it has a key and value
                key_value = param.split('=')
                if len(key_value) == 2:  # Ensure both key and value exist
                    key, value = key_value
                    params[key] = value

        token = params.get('token')

        print("TOKEN", token)

        # Initialize JWTAuthentication
        jwt_auth = JWTAuthentication()
        self.user = None

        # Validate token and get user
        try:
            validated_token = jwt_auth.get_validated_token(token)
            self.user = await database_sync_to_async(jwt_auth.get_user)(validated_token)  
            self.scope['user'] = self.user  
            print("USER", self.user)
        except InvalidToken:
            print("Invalid token. Closing connection.")
            await self.close()
            return

        # Check if the user is authenticated
        if not self.user.is_authenticated:
            print("Unauthenticated user. Closing connection.")
            await self.close()
            return

        # Proceed with room setup as before
        self.receiver_id = self.scope['url_route']['kwargs']['receiver_id']
        if self.user.id < self.receiver_id:
            self.room_group_name = f'chat_{self.user.id}_{self.receiver_id}'
        else:
            self.room_group_name = f'chat_{self.receiver_id}_{self.user.id}'

        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()
        print("Connection accepted.")


    async def disconnect(self, close_code):
        if hasattr(self, 'room_group_name') and self.room_group_name:
            await self.channel_layer.group_discard(
                self.room_group_name,
                self.channel_name
            )

    async def receive(self, text_data):
        from notification_chat.models import Message 

        data = json.loads(text_data)
        message = data['text']

        # Store the message in the database asynchronously
        await self.store_message(message)

        # Broadcast the message to the group
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'chat_message',
                'message': message,
                'sender': self.scope['user'].id,
            }
        )

    async def chat_message(self, event):
        message = event['message']
        sender = event['sender']

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'message': message,
            'sender': sender,
        }))

    @database_sync_to_async
    def store_message(self, message):
        from notification_chat.models import Message  # Move this import here

        sender_id = self.scope['user'].id
        receiver_id = self.receiver_id
        # Corrected instantiation of Message
        chat_message = Message(sender_id=sender_id, receiver_id=receiver_id, text=message)
        chat_message.save()
    

    async def send_unread_message_count(self):
        # Get the unread message count for the current user
        unread_count = await self.get_unread_count()
        # Send the unread count to the WebSocket
        await self.send(text_data=json.dumps({
            'unread_count': unread_count,
        }))

    @database_sync_to_async
    def get_unread_count(self):
        # Fetch unread message count from the database
        return Message.objects.filter(receiver=self.scope['user'], is_read=False).count()

    async def mark_messages_as_read(self):
        # Call the existing function to mark messages as read
        await database_sync_to_async(self.mark_as_read_in_db)()

        # After marking messages as read, send an update to the WebSocket client
        await self.send_unread_message_count()

    @database_sync_to_async
    def mark_as_read_in_db(self):
        # Mark all unread messages as read for the current chat session
        Message.objects.filter(sender=self.receiver_id, receiver=self.scope['user'], is_read=False).update(is_read=True)

class NotificationConsumer(AsyncWebsocketConsumer):
    # async def connect(self):
    #     self.group_name = f"user_{self.scope['user'].id}"

    #     # Join user group
    #     await self.channel_layer.group_add(
    #         self.group_name,
    #         self.channel_name
    #     )

    #     await self.accept()
    async def connect(self):
        from rest_framework_simplejwt.authentication import JWTAuthentication

        query_string = self.scope['query_string'].decode()  # Decode query string
        params = {}

        if query_string:
            for param in query_string.split('&'):
                key_value = param.split('=')
                if len(key_value) == 2:  # Ensure both key and value exist
                    key, value = key_value
                    params[key] = value

        token = params.get('token')

        # Initialize JWTAuthentication
        jwt_auth = JWTAuthentication()
        self.user = None

        # Validate token and get user
        try:
            validated_token = jwt_auth.get_validated_token(token)
            self.user = await database_sync_to_async(jwt_auth.get_user)(validated_token)
            self.scope['user'] = self.user
        except InvalidToken:
            print("Invalid token. Closing connection.")
            await self.close()
            return

        # Proceed with group setup
        self.group_name = f"user_{self.scope['user'].id}"

        # Join user group
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):
        # Leave user group
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )

    # Method to handle incoming notifications
    async def send_subscription_expiration_notification(self, event):
        await self.send(text_data=json.dumps({
            "message": event["message"]
        }))
