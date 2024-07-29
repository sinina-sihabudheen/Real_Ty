from django.urls import path
from . import views

urlpatterns = [
    path('create-subscription/', views.create_subscription, name='create_subscription'),
    path('cancel-subscription/', views.cancel_subscription, name='cancel_subscription'),
]
