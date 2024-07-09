from rest_framework import viewsets, status, generics, serializers
from rest_framework.response import Response
from rest_framework.decorators import action
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from .models import User,Seller, LandProperty, ResidentialProperty, EmailDevice, Region, Buyer
from .serializers import SellerSerializer, RegionSerializer, LandPropertySerializer, ResidentialPropertySerializer, RegisterSerializer, OTPSerializer, OTPVerificationSerializer, ResendOTPSerializer
from rest_framework.views import APIView
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import authenticate
from .serializers import UserSerializer
from django.db import transaction
from rest_framework.permissions import AllowAny,IsAuthenticated
from django.conf import settings
import requests
from allauth.socialaccount.providers.facebook.views import FacebookOAuth2Adapter
from dj_rest_auth.registration.views import SocialLoginView
from django.views.decorators.csrf import csrf_exempt



User = get_user_model()

from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from dj_rest_auth.registration.views import SocialLoginView
from allauth.socialaccount.providers.oauth2.client import OAuth2Client



class GoogleLogin(SocialLoginView):

    def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            
            try:
                self.adapter_class = GoogleOAuth2Adapter
                self.client_class = OAuth2Client 
                self.callback_url = 'http://localhost:5173/auth/callback'
            except AttributeError as e:
                print(f"Error occurred during attribute assignment: {e}")

class CustomLoginView(APIView):
    permission_classes = []

    @csrf_exempt
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        password = request.data.get('password')
        print(email,password)

        if email is None or password is None:
            return Response({'error': 'Please provide both email and password'}, status=status.HTTP_400_BAD_REQUEST)

        print(f"Attempting to authenticate with email: {email}")
        
        user = authenticate(request, email=email, password=password)

        print(f"Authentication result: {user}")

        if user is None:
            print(f"Failed login attempt with email: {email}")
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        refresh = RefreshToken.for_user(user)

        if user.is_staff:
            role = 'admin'
        elif user.is_seller:
            role = 'seller'
        else:
            role = 'buyer'

        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'role': role,
        }, status=status.HTTP_200_OK)
    
class RegionViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [AllowAny]
    queryset = Region.objects.all()
    serializer_class = RegionSerializer  


class UserRegistrationView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        is_seller = serializer.validated_data.get('is_seller')
        ##
        is_buyer = not is_seller  # Determine is_buyer based on is_seller
        username = serializer.validated_data['username']
        address = serializer.validated_data['address']
        contact_number= serializer.validated_data['contact_number']


        try:
            user = User.objects.get(email=email)
            return Response({'detail': 'Email already registered'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            pass

        # user = User.objects.create_user(username=username, email=email, password=password,address=address,contact_number=contact_number)#address=address,contact_number=contact_number
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            address=address,
            contact_number=contact_number,
            is_seller=is_seller,
            is_buyer=is_buyer
        )
        if is_seller:
            
            seller_profile = Seller.objects.create(
                user=user, 
                agency_name=serializer.validated_data['agency_name']
            )
            seller_profile.regions.set(serializer.validated_data['regions'])
        else:
            Buyer.objects.create(user=user)


        device = EmailDevice.objects.create(user=user, email=email)
        device.generate_challenge()
        print(device.token)

        send_mail(
            'Your OTP Code',
            f'Your OTP code is {device.token}',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )

        print("OTP sent to email to:")
        print(email)

        return Response({
            'detail': 'OTP sent successfully',
            'email': email,
        }, status=status.HTTP_200_OK)
    
class OTPVerificationView(generics.GenericAPIView):
    serializer_class = OTPVerificationSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        token = serializer.validated_data['token']

        try:
            device = EmailDevice.objects.get(email=email, token=token, is_active=True)
        except EmailDevice.DoesNotExist:
            return Response({"message": 'Invalid OTP or email',"success":False}, status=status.HTTP_400_BAD_REQUEST)

        # Activate user account
        try:
            user = User.objects.get(email=email)
            user.is_active = True
        
            user.save()
        except User.DoesNotExist:
            return Response({"message": 'User not found', "success":False}, status=status.HTTP_404_NOT_FOUND)

        # Deactivate the device token after successful verification
        device.deactivate()
        print("OTP deactivated..", )
        return Response({
            'message': 'OTP verified successfully',
            'success':True,
            }, status=status.HTTP_200_OK)
    

class ResendOTPView(generics.GenericAPIView):
    serializer_class = ResendOTPSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

     
        EmailDevice.objects.filter(user=user, is_active=True).update(is_active=False)
       
        self.send_otp(user, email)

        return Response({"message": "OTP resent successfully",
                         'success': True }, 
                         status=status.HTTP_200_OK)

    def send_otp(self, user, email):
        device = EmailDevice.objects.create(user=user, email=email)
        device.generate_challenge()
    
        print("Resend OTP",device.token)
        send_mail(
            'Your OTP Code',
            f'Your OTP code is {device.token}',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )
        return device.token
    
class SellerViewSet(viewsets.ModelViewSet):
    queryset = Seller.objects.all()
    serializer_class = SellerSerializer

class UserDetailView(generics.RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

class LandPropertyViewSet(viewsets.ModelViewSet):
    queryset = LandProperty.objects.all()
    serializer_class = LandPropertySerializer

class ResidentialPropertyViewSet(viewsets.ModelViewSet):
    queryset = ResidentialProperty.objects.all()
    serializer_class = ResidentialPropertySerializer



