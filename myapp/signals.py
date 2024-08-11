from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Subscription, Seller, SubscriptionPayment

@receiver(post_save, sender=Subscription)
def update_seller_subscription_status(sender, instance, **kwargs):
    if instance.payment_plan == 'premium':
        instance.seller.subscription_status = 'premium'
    else:
        instance.seller.subscription_status = 'free'
    instance.seller.save()

@receiver(post_save, sender=SubscriptionPayment)
def update_seller_subscription_payment_status(sender, instance, **kwargs):
    # Check if the payment status is paid and the subscription is premium
    if instance.payment_status == 'paid' and instance.subscription.payment_plan == 'premium':
        instance.user.subscription_status = 'premium'
    else:
        instance.user.subscription_status = 'free'
    instance.user.save()
