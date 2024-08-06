from django.urls import path
from . import views

urlpatterns = [
    path('create-subscription/', views.create_subscription, name='create_subscription'),
    path('cancel-subscription/', views.cancel_subscription, name='cancel_subscription'),
    path('check-subscription/<int:user_id>/', views.check_subscription, name='check_subscription'),
    path('stripe-webhook', views.stripe_webhook, name='stripe-webhook'),
    
    ]

