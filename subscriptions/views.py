import stripe
from django.conf import settings
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from myapp.models import Subscription, SubscriptionPayment, Seller, User, LandProperty, ResidentialProperty
from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from django.views.decorators.csrf import csrf_exempt


import logging
logger = logging.getLogger(__name__)


stripe.api_key = settings.STRIPE_SECRET_KEY

# @permission_classes([IsAuthenticated])
# @api_view(['POST'])
# def create_subscription(request):
#     user_id = request.data.get('user_id')
#     print("USERID",user_id)

#     seller = get_object_or_404(Seller, user_id=user_id)
#     print("SELLER",seller)
#     payment_method_id = request.data.get('payment_method_id')
#     subscription_type = request.data.get('subscription_type')
#     payment_plan = request.data.get('payment_plan')
    
#     try:
        
        
#         customer = stripe.Customer.create(
#             email=seller.user.email,
#             payment_method=payment_method_id,
#             invoice_settings={'default_payment_method': payment_method_id},
#         )
        
#         price_id = 'price_1PiGUIGYaADgjXW8tSAwmjcb' 

#         stripe_subscription = stripe.Subscription.create(
#             customer=customer.id,
#             items=[{'price': price_id}],
#             expand=['latest_invoice.payment_intent'],
#         )
        
#         if subscription_type == 'monthly':
#             expiry_date = timezone.now() + timezone.timedelta(days=30)
#         elif subscription_type == 'yearly':
#             expiry_date = timezone.now() + timezone.timedelta(days=365)
        
#         subscription = Subscription.objects.create(
#             seller=seller,
#             subscription_type=subscription_type,
#             payment_plan=payment_plan,
#             ended_at=expiry_date,
#             stripe_subscription_id=stripe_subscription.id,
#         )
        
#         SubscriptionPayment.objects.create(
#             subscription=subscription,
#             user=seller,
#             amount=stripe_subscription.latest_invoice.payment_intent.amount_received / 100,
#             payment_date=timezone.now(),
#             expiry_date=expiry_date,
#             payment_status='paid',
#             transaction_id=stripe_subscription.id,
#         )
        
#         return Response(status=status.HTTP_200_OK, data={'subscription_id': stripe_subscription.id})
#     except Exception as e:
#         return Response(status=status.HTTP_400_BAD_REQUEST, data={'error': str(e)})

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_subscription(request):
    user_id = request.data.get('user_id')
    subscription_type = request.data.get('subscription_type')
    payment_plan = request.data.get('payment_plan')
    print("user",user_id)
    
    seller = get_object_or_404(Seller, user_id=user_id)
    print(seller)
    
    existing_subscriptions = Subscription.objects.filter(seller=seller).order_by('-started_at')
    if existing_subscriptions.exists():
        for sub in existing_subscriptions:
            stripe.Subscription.delete(sub.stripe_subscription_id)
            sub.delete()

    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[
                {
                    'price': 'price_1PiGUIGYaADgjXW8tSAwmjcb', 
                    'quantity': 1,
                },
            ],
            mode='subscription',
            success_url='https://localhost:5173/',
            cancel_url='https://localhost:5173/cancel',
            metadata={
                'user_id': user_id,
                'subscription_type': subscription_type,
                'payment_plan': payment_plan,
            },
        )
        
        return Response(status=status.HTTP_200_OK, data={'checkout_session_id': checkout_session.id})
    except Exception as e:
        return Response(status=status.HTTP_400_BAD_REQUEST, data={'error': str(e)})

@api_view(['POST'])
def cancel_subscription(request):
    try:
        user = request.user
        subscription = get_object_or_404(Subscription, seller__user=user, ended_at__isnull=True)
        
        stripe.Subscription.delete(subscription.stripe_subscription_id)
        
        subscription.ended_at = timezone.now()
        subscription.save()
        
        return Response(status=status.HTTP_200_OK, data={'message': 'Subscription cancelled'})
    except Subscription.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND, data={'error': 'Subscription not found'})
    except Exception as e:
        return Response(status=status.HTTP_400_BAD_REQUEST, data={'error': str(e)})


@api_view(['GET'])
def check_subscription(request, user_id):
    try:
        user = get_object_or_404(User, id=user_id)
        seller = get_object_or_404(Seller, user=user)
        
        subscription = Subscription.objects.filter(seller=seller).order_by('-started_at').first()
        
        if subscription:
            current_date = timezone.now().date()
            if subscription.ended_at:
                is_subscribed = current_date <= subscription.ended_at
                days_left = (subscription.ended_at - current_date).days if is_subscribed else 0
            else:
                is_subscribed = False
                days_left = 0
        else:
            is_subscribed = False
            days_left = 0
        
        property_count = LandProperty.objects.filter(seller=seller).count() + ResidentialProperty.objects.filter(seller=seller).count()

        response = {
            'isSubscribed': is_subscribed,
            'daysLeft': days_left,
            'propertyCount': property_count,
            'subscriptionType': subscription.subscription_type if subscription else None,
            'paymentPlan': subscription.payment_plan if subscription else 'free',
        }

        return Response(response)
    except Exception as e:
        logger.error(f"Error checking subscription for user_id {user_id}: {e}")
        return Response({'detail': 'Internal Server Error'}, status=500)

@csrf_exempt
@api_view(['POST'])
def stripe_webhook(request):
    print("ENTERED INTO WEBHOOK")
    payload = request.body
    print("webhook called+++++====")
    print(payload)

    sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')
    endpoint_secret = settings.STRIPE_WEBHOOK_SECRET_KEY

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError as e:
        return Response({'error': 'Invalid payload'}, status=400)
    except stripe.error.SignatureVerificationError as e:
        return Response({'error': 'Invalid signature'}, status=400)

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user_id = session['metadata']['user_id']
        subscription_type = session['metadata']['subscription_type']
        payment_plan = session['metadata']['payment_plan']

        seller = get_object_or_404(Seller, id=user_id)
        stripe_subscription_id = session['subscription']
        expiry_date = timezone.now() + timezone.timedelta(days=30) if subscription_type == 'monthly' else timezone.now() + timezone.timedelta(days=365)
        
        subscription = Subscription.objects.create(
            seller=seller,
            subscription_type=subscription_type,
            payment_plan=payment_plan,
            ended_at=expiry_date,
            stripe_subscription_id=stripe_subscription_id,
        )
        
        SubscriptionPayment.objects.create(
            subscription=subscription,
            user=seller,
            amount=session['amount_total'] / 100,
            payment_date=timezone.now(),
            expiry_date=expiry_date,
            payment_status='paid',
            transaction_id=session['id'],
        )

    elif event['type'] == 'invoice.payment_failed':
        invoice = event['data']['object']
        payment_intent_id = invoice['payment_intent']
        subscription_payment = SubscriptionPayment.objects.filter(transaction_id=payment_intent_id).first()
        if subscription_payment:
            subscription_payment.payment_status = 'failed'
            subscription_payment.save()

    return Response(status=200)



