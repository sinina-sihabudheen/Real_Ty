from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    GoogleLoginView, MessageListView, PremiumUserListAPIView, PropertyMessagesView, PropertySearchView, SellerProfileLandsViewSet, SellerProfileResidentsViewSet, SellerProfileView, SendMessageView, UserBlockAPIView, UnblockUserAPIView,
    UserRegistrationView, OTPVerificationView, CustomLoginView,
    ResendOTPView, ForgotPasswordView,RegionViewSet, 
    UserDetailView, UpdateUserView, ChangePasswordView, 
    AdminLoginView, ResetPasswordView, UserListAPIView, 
    RegisterLandsViewSet, RegisterResidentialsViewSet, AmenityViewSet,
    RegionCreateAPIView, RegionDeleteAPIView, SellerResidentsViewSet, 
    SellerLandsViewSet,LandPropertyDetailView,AmenityCreateAPIView, 
    AmenityDeleteAPIView,ResidentialPropertyDetailView, LandsListViewSet, 
    ResidentsListViewSet, CategoryViewSet, 
    admin_dashboard_data, CategoryCreateAPIView, CategoryDeleteAPIView, 
)


router = DefaultRouter()
router.register(r'regions', RegionViewSet, basename='region')
router.register(r'amenity', AmenityViewSet)
router.register(r'category',CategoryViewSet)
router.register(r'register-lands', RegisterLandsViewSet)
router.register(r'register-residentials', RegisterResidentialsViewSet)
router.register(r'seller-lands', SellerLandsViewSet, basename='seller-lands')
router.register(r'seller-residents', SellerResidentsViewSet, basename='seller-residents')
router.register(r'landslist', LandsListViewSet, basename='landslist')
router.register(r'residentslist', ResidentsListViewSet, basename='residentslist')

urlpatterns = [
    path('', include(router.urls)),

    path('admin-dashboard/', admin_dashboard_data, name='admin_dashboard_data'),


    path('auth/google/', GoogleLoginView.as_view(), name='google-login'),

    path('auth/login/', CustomLoginView.as_view(), name='custom_login'),
    path('admin-login/', AdminLoginView.as_view(), name='admin-login'),
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('verify-otp/', OTPVerificationView.as_view(), name='verify-otp'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    path('user/', UserDetailView.as_view(), name='user-detail'),

    path('sellerProfile/<int:userId>/', SellerProfileView.as_view(), name='seller-profile'),
    path('seller-profile-lands/<int:userId>/', SellerProfileLandsViewSet.as_view({'get': 'list'}), name='seller-profile-lands'),
    path('seller-profile-residents/<int:userId>/', SellerProfileResidentsViewSet.as_view({'get': 'list'}), name='seller-profile-residents'),

    path('update-user/', UpdateUserView.as_view(), name='update-user'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    
    path('forgot_password/', ForgotPasswordView.as_view(), name='forgot_password'),
    path('reset_password/', ResetPasswordView.as_view(), name='reset_password'),

    path('users_list/', UserListAPIView.as_view(), name='users-list'),
    path('users/<int:pk>/block/', UserBlockAPIView.as_view(), name='block-user'),
    path('users/<int:user_id>/unblock/', UnblockUserAPIView.as_view(), name='unblock-user'),


    path('regions/add/', RegionCreateAPIView.as_view(), name='region-add'),
    path('regions/<int:pk>/delete/', RegionDeleteAPIView.as_view(), name='region-delete'),


    path('categories/add/', CategoryCreateAPIView.as_view(), name='category-add'),
    path('categories/<int:pk>/delete/', CategoryDeleteAPIView.as_view(), name='category-delete'),

 
    path('amenities/add/', AmenityCreateAPIView.as_view(), name='amenity-add'),
    path('amenities/<int:pk>/delete/', AmenityDeleteAPIView.as_view(), name='amenity-delete'),

    path('lands/<int:pk>/', LandPropertyDetailView.as_view(), name='land-detail'),
    path('residentials/<int:pk>/', ResidentialPropertyDetailView.as_view(), name='residential-detail'),

    path('lands/update/<int:pk>/', LandPropertyDetailView.as_view(), name='land-update'),
    path('residentials/update/<int:pk>/', ResidentialPropertyDetailView.as_view(), name='residential-update'),

    path('lands/delete/<int:pk>/', LandPropertyDetailView.as_view(), name='land-delete'),
    path('residentials/delete/<int:pk>/', ResidentialPropertyDetailView.as_view(), name='residential-delete'),

    path('search/', PropertySearchView.as_view(), name='property_search'),
    path('premium-users/', PremiumUserListAPIView.as_view(), name='premium-users-list'),


    path('send-message/', SendMessageView.as_view(), name='send-message'),
    path('messages/<int:seller_id>/', MessageListView.as_view(), name = 'message-list'),
    path('property-messages/<int:property_id>/', PropertyMessagesView.as_view(), name='property-messages'),

]

