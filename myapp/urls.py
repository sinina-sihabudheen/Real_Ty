
from django.urls import path,include
from rest_framework.routers import DefaultRouter
from .views import UserRegistrationView, OTPVerificationView, CustomLoginView, ResendOTPView,ForgotPasswordView
from .views import RegionViewSet,UserDetailView, UpdateUserView, ChangePasswordView, AdminLoginView, UpdateUserRole, ResetPasswordView
from .views import SellerAPIView, BuyerAPIView, UserAPIView



router = DefaultRouter()
router.register(r'regions', RegionViewSet, basename='region')

urlpatterns = [
    path('', include(router.urls)),
    path('auth/login/', CustomLoginView.as_view(), name='custom_login'), 
    path('admin-login/', AdminLoginView.as_view(), name='admin-login'),
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('verify-otp/', OTPVerificationView.as_view(), name='verify-otp'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    path('user/', UserDetailView.as_view(), name='user-detail'),   
    path('update-user/', UpdateUserView.as_view(), name='update-user'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('upadate_role/', UpdateUserRole.as_view(),name='update_role'),
    path('forgot_password/', ForgotPasswordView.as_view,name='forgot_password'),
    path('reset_password/', ResetPasswordView.as_view,name='reset_password'),
    path('users_list', UserAPIView.as_view, name='users_list'),
    path('sellers_list', SellerAPIView.as_view, name='sellers_list'),
    path('buyers_list', BuyerAPIView.as_view, name='buyers_list'),

]

