
from django.urls import path
from .views import UserRegistrationView, OTPVerificationView, CustomLoginView, ResendOTPView

urlpatterns = [
    path('api/auth/login/', CustomLoginView.as_view(), name='custom_login'), 
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('verify-otp/', OTPVerificationView.as_view(), name='verify-otp'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),

]

