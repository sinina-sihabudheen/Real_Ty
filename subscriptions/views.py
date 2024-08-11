import stripe
from django.conf import settings
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from myapp.models import Subscription, SubscriptionPayment, Seller, User, LandProperty, ResidentialProperty
from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.views.decorators.csrf import csrf_exempt
import json
from django.http import JsonResponse, HttpResponse



import logging
logger = logging.getLogger(__name__)


stripe.api_key = settings.STRIPE_SECRET_KEY
endpoint_secret = settings.STRIPE_WEBHOOK_SECRET_KEY

# @permission_classes([IsAuthenticated])
@api_view(['POST'])
def create_subscription(request):
    user_id = request.data.get('user_id')
    print("USERID",user_id)
    subscription_type = request.data.get('subscription_type')
    payment_plan = request.data.get('payment_plan')

    seller = get_object_or_404(Seller, user_id=user_id)

    # Cancel and delete existing subscriptions
    existing_subscriptions = Subscription.objects.filter(seller=seller).order_by('-started_at')
    if existing_subscriptions.exists():
        for sub in existing_subscriptions:
            if sub.stripe_subscription_id:
                stripe.Subscription.delete(sub.stripe_subscription_id)
            sub.delete()

    # Define Stripe price IDs for monthly and yearly plans
    price_id = 'price_1PiGUIGYaADgjXW8tSAwmjcb' if subscription_type == 'monthly' else 'price_1PiHKhGYaADgjXW8hbcbDHEV'

    

    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[
                {
                    'price': price_id,
                    'quantity': 1,
                },
            ],
            mode='subscription',
            success_url='http://localhost:5173/success?session_id={CHECKOUT_SESSION_ID}',
            cancel_url='http://localhost:5173/cancel',
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
        
        if subscription.stripe_subscription_id:
            stripe.Subscription.delete(subscription.stripe_subscription_id)
        
        subscription.ended_at = timezone.now().date()
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

        print("SELLER:",seller)
        
        subscription = Subscription.objects.filter(seller=seller).order_by('-started_at').first()
        print("SUBSCRIPTION",subscription)
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
def stripe_webhook(request):
    payload = request.body
    sig_header = request.META['HTTP_STRIPE_SIGNATURE']
    event = None

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError:
        # Invalid payload
        return JsonResponse({'error': 'Invalid payload'}, status=400)
    except stripe.error.SignatureVerificationError:
        # Invalid signature
        return JsonResponse({'error': 'Invalid signature'}, status=400)

    # Handle the event
    event_type = event['type']
    event_data = event['data']['object']
    if event_type == 'payment_intent.succeeded':
        print("PaymentIntent was successful!")
    elif event_type == 'charge.succeeded':
        print("Charge was successful!")
    elif event_type == 'checkout.session.completed':
            print("Checkout session completed!")
          
            session_id = event_data.get('id')
            print("SESSIONIDs",session_id)
            if session_id:
                try:
                    # Retrieve the Checkout Session to get metadata
                    session = stripe.checkout.Session.retrieve(session_id)
                    metadata = session.get('metadata', {})

                    user_id = metadata.get('user_id')
                    subscription_type = metadata.get('subscription_type')
                    payment_plan = metadata.get('payment_plan')

                    if not user_id or not subscription_type or not payment_plan:
                        return JsonResponse({'error': 'Missing metadata'}, status=400)
                    
                    seller = get_object_or_404(Seller, user_id=user_id)
                    stripe_subscription_id = event_data.get('subscription')
                    expiry_date = timezone.now().date() + (timezone.timedelta(days=30) if subscription_type == 'monthly' else timezone.timedelta(days=365))

                    if payment_plan == 'premium':
                        seller.subscription_status = 'premium'
                    else:
                        seller.subscription_status = 'free'
                    seller.save()

                    
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
                        amount=event_data.get('amount_total', 0) / 100,
                        payment_date=timezone.now().date(),
                        expiry_date=expiry_date,
                        payment_status='paid',
                        transaction_id=event_data.get('id'),
                    )

                except stripe.error.StripeError as e:
                    return JsonResponse({'error': str(e)}, status=500)
    elif event_type == 'payment_method.attached':
        print("Payment method attached!")
    elif event_type == 'customer.created':
        print("Customer created!")
    elif event_type == 'customer.updated':
        print("Customer updated!")
    elif event_type == 'customer.subscription.created':
        print("Subscription created!")
    elif event_type == 'customer.subscription.updated':
        print("Subscription updated!")
        subscription_id = event_data.get('id')
        try:
            subscription = Subscription.objects.get(stripe_subscription_id=subscription_id)
            # Update the seller's subscription status if needed
            if subscription.payment_plan == 'premium':
                subscription.seller.subscription_status = 'premium'
            else:
                subscription.seller.subscription_status = 'free'
            subscription.seller.save()
        except Subscription.DoesNotExist:
            print("Subscription not found for updating seller status.")
    elif event_type == 'payment_intent.created':
        print("PaymentIntent created!")
    elif event_type == 'invoice.created':
        print("Invoice created!")
    elif event_type == 'invoice.finalized':
        print("Invoice finalized!")
    elif event_type == 'invoice.updated':
        print("Invoice updated!")
    elif event_type == 'invoice.paid':
        print("Invoice paid!")

    elif event_type == 'invoice.payment_succeeded':
        print("Invoice payment succeeded.")
    elif event_type == 'customer.subscription.deleted':
        print("Subscription deleted")
        subscription_id = event_data.get('id')
        try:
            subscription = Subscription.objects.get(stripe_subscription_id=subscription_id)
            subscription.seller.subscription_status = 'free'  # Revert to free status if subscription is deleted
            subscription.seller.save()
        except Subscription.DoesNotExist:
            print("Subscription not found for updating seller status.")      
    
    else:
        print(f'Unhandled event type {event_type}')

    return JsonResponse({'success': True})


@api_view(['GET'])
def get_session_details(request, session_id):
    try:
        session = stripe.checkout.Session.retrieve(session_id)
        return Response(session)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
