import stripe
from django.conf import settings
from django.utils import timezone
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from myapp.models import Subscription, SubscriptionPayment, Seller

stripe.api_key = settings.STRIPE_SECRET_KEY

@api_view(['POST'])
def create_subscription(request):
    try:
        user = request.user
        payment_method_id = request.data.get('payment_method_id')
        subscription_type = request.data.get('subscription_type')
        payment_plan = request.data.get('payment_plan')
        
        # Create Stripe customer
        customer = stripe.Customer.create(
            email=user.email,
            payment_method=payment_method_id,
            invoice_settings={'default_payment_method': payment_method_id},
        )
        
        # Define price based on subscription type and payment plan
        price_id = 'price_123456'  # Replace with your actual Stripe price ID
        
        # Create Stripe subscription
        stripe_subscription = stripe.Subscription.create(
            customer=customer.id,
            items=[{'price': price_id}],
            expand=['latest_invoice.payment_intent'],
        )
        
        # Calculate expiry date based on subscription type
        if subscription_type == 'monthly':
            expiry_date = timezone.now() + timezone.timedelta(days=30)
        elif subscription_type == 'yearly':
            expiry_date = timezone.now() + timezone.timedelta(days=365)
        
        # Create subscription in the database
        subscription = Subscription.objects.create(
            seller=user,
            subscription_type=subscription_type,
            payment_plan=payment_plan,
            ended_at=expiry_date,
        )
        
        # Create subscription payment record
        SubscriptionPayment.objects.create(
            subscription=subscription,
            user=user,
            amount=stripe_subscription.latest_invoice.payment_intent.amount_received / 100,
            payment_date=timezone.now(),
            expiry_date=expiry_date,
            payment_status='paid',
            transaction_id=stripe_subscription.id,
        )
        
        return Response(status=status.HTTP_200_OK, data=stripe_subscription)
    except Exception as e:
        return Response(status=status.HTTP_400_BAD_REQUEST, data={'error': str(e)})

@api_view(['POST'])
def cancel_subscription(request):
    try:
        user = request.user
        subscription = Subscription.objects.get(seller=user, is_active=True)
        
        # Cancel Stripe subscription
        stripe.Subscription.delete(subscription.stripe_subscription_id)
        
        # Update subscription status in the database
        subscription.is_active = False
        subscription.save()
        
        return Response(status=status.HTTP_200_OK, data={'message': 'Subscription cancelled'})
    except Subscription.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND, data={'error': 'Subscription not found'})
    except Exception as e:
        return Response(status=status.HTTP_400_BAD_REQUEST, data={'error': str(e)})
