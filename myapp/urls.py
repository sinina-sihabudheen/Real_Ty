
from django.urls import path,include
from rest_framework.routers import DefaultRouter
from .views import UserRegistrationView, OTPVerificationView, CustomLoginView, ResendOTPView
from .views import RegionViewSet

router = DefaultRouter()
router.register(r'regions', RegionViewSet, basename='region')

urlpatterns = [
    path('', include(router.urls)),
    path('auth/login/', CustomLoginView.as_view(), name='custom_login'), 
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('verify-otp/', OTPVerificationView.as_view(), name='verify-otp'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    # path('regions/', RegionView.as_view(), name='regions'),

]
