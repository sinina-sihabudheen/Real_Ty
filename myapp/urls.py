
from django.urls import path,include
from rest_framework.routers import DefaultRouter
from .views import UserRegistrationView, OTPVerificationView, CustomLoginView, ResendOTPView,ForgotPasswordView
from .views import RegionViewSet,UserDetailView, UpdateUserView, ChangePasswordView, AdminLoginView, UpdateUserRole, ResetPasswordView
from .views import UserListAPIView, UserBlockAPIView, SellerListAPIView, SellerBlockAPIView, BuyerListAPIView, BuyerBlockAPIView
from . import views


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

    path('users_list/', UserListAPIView.as_view(), name='users_list'),
    path('users/<int:pk>/block/', UserBlockAPIView.as_view(), name='block_user'),

    path('sellers_list/', SellerListAPIView.as_view(), name='sellers_list'),
    path('sellers/<int:pk>/block/', SellerBlockAPIView.as_view(), name='block_seller'),
    
    path('buyers_list/', BuyerListAPIView.as_view(), name='buyers_list'),
    path('buyers/<int:pk>/block/', BuyerBlockAPIView.as_view(), name='block_buyer'),
  
    path('api/regions/create/', views.RegionCreateAPIView.as_view(), name='region-create'),
    path('api/regions/<int:pk>/delete/', views.RegionDeleteAPIView.as_view(), name='region-delete'),
]


