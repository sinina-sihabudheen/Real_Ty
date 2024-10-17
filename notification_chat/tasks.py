
from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from myapp.models import Subscription

@shared_task
def send_subscription_end_notification():
    # Get today's date and the date 5 days from now
    target_date = timezone.now().date() + timedelta(days=5)

    # Query subscriptions ending in 5 days
    subscriptions = Subscription.objects.filter(ended_at=target_date)

    # Send notification to each user
    for subscription in subscriptions:
        user = subscription.seller
        # Send notification (email or other means)
        send_notification(user)

def send_notification(user):
    # Implement your notification logic here (email, SMS, etc.)
    print(f"Sending notification to {user.username}, email: {user.email}")
    from django.core.mail import send_mail
    subject = "Your Subscription is Ending Soon"
    message = f"Dear {user.username}, your subscription will expire in 5 days."
    email_from = 'noreply@realty.com'
    recipient_list = [user.email]
    send_mail(subject, message, email_from, recipient_list)


    
