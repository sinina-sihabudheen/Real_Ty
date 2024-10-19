
from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from myapp.models import Subscription

@shared_task
def send_subscription_end_notification():
    # target_date = timezone.now().date() + timedelta(days=5)

    # subscriptions = Subscription.objects.filter(ended_at=target_date)

    # for subscription in subscriptions:
    #     user = subscription.seller
    #     send_notification(user)

    today = timezone.now().date()
    five_days_from_now = today + timedelta(days=5)
    one_day_from_now = today + timedelta(days=1)

    # Query subscriptions ending in 5 days or 1 day
    subscriptions_5_days = Subscription.objects.filter(ended_at=five_days_from_now)
    subscriptions_1_day = Subscription.objects.filter(ended_at=one_day_from_now)

    # Send 5-day notifications
    for subscription in subscriptions_5_days:
        user = subscription.seller
        send_notification(user, days_left=5)

    # Send 24-hour notifications
    for subscription in subscriptions_1_day:
        user = subscription.seller
        send_notification(user, days_left=1)


def send_notification(user, days_left):
    print(f"Sending notification to {user.username}, email: {user.email}")
    # from django.core.mail import send_mail
    # subject = "Your Subscription is Ending Soon"
    # message = f"Dear {user.username}, your subscription will expire in 5 days."
    # email_from = 'noreply@realty.com'
    # recipient_list = [user.email]
    # send_mail(subject, message, email_from, recipient_list)

    # channel_layer = get_channel_layer()
    # async_to_sync(channel_layer.group_send)(
    #     f"user_{user.id}",  
    #     {
    #         'type': 'send_subscription_expiration_notification',
    #         'message': message,
    #     }
    # )
    
    # Define the email subject and message based on the time left
    if days_left == 5:
        subject = "Your Subscription is Ending in 5 Days"
        message = f"Dear {user.username}, your subscription will expire in 5 days."
    elif days_left == 1:
        subject = "Your Subscription is Ending Tomorrow"
        message = f"Dear {user.username}, your subscription will expire in 24 hours."

    email_from = 'noreply@realty.com'
    recipient_list = [user.email]

    # Send the email notification
    send_mail(subject, message, email_from, recipient_list)

    # Send WebSocket notification
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f"user_{user.id}",  # User-specific group
        {
            'type': 'send_subscription_expiration_notification',
            'message': message,
        }
    )


    
