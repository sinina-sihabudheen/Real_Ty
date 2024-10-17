from django.db import models
# from myapp.models import  User
from django.utils import timezone
from datetime import timedelta


class Message(models.Model):
    sender = models.ForeignKey('myapp.User', on_delete=models.CASCADE, related_name="sent_messages")
    receiver = models.ForeignKey('myapp.User', on_delete=models.CASCADE, related_name="received_messages")
    text = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)


    def __str__(self):
        return f"Message from {self.sender} to {self.receiver} - {self.timestamp}"

    class Meta:
        ordering = ['timestamp'] 