from django.urls import path
from . import views
from .views import get_session_details


urlpatterns = [
    path('create-subscription/', views.create_subscription, name='create-subscription'),
    path('cancel-subscription/', views.cancel_subscription, name='cancel-subscription'),
    path('check-subscription/<int:user_id>/', views.check_subscription, name='check-subscription'),
    path('stripe-webhook', views.stripe_webhook, name='stripe-webhook'),
    path('stripe/session/<str:session_id>/', get_session_details, name='get-session-details'),

    ]
