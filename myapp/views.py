from rest_framework import viewsets, status, generics, serializers
from rest_framework.response import Response
from rest_framework.decorators import action
from django.contrib.auth import get_user_model, update_session_auth_hash
from django.contrib.auth.password_validation import validate_password
from rest_framework import viewsets

from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from .models import User,Seller, LandProperty, ResidentialProperty, EmailDevice, Region, Buyer
from .serializers import SellerSerializer, RegionSerializer, UpdateUserRoleSerializer, LandPropertySerializer, ResidentialPropertySerializer, RegisterSerializer
from .serializers import OTPVerificationSerializer, ResendOTPSerializer, PasswordChangeSerializer, ForgotPasswordSerializer, ResetPasswordSerializer, BuyerSerializer
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
from django.utils.decorators import method_decorator



User = get_user_model()

from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from dj_rest_auth.registration.views import SocialLoginView
from allauth.socialaccount.providers.oauth2.client import OAuth2Client



class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter
    client_class = OAuth2Client

    def post(self, request, *args, **kwargs):
        try:
            return super().post(request, *args, **kwargs)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class AdminLoginView(APIView):
    permission_classes = []

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        password = request.data.get('password')

        if email is None or password is None:
            return Response({'error': 'Please provide both email and password'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            if not user.check_password(password) or not user.is_staff:
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        refresh = RefreshToken.for_user(user)

        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'role': 'admin',
        }, status=status.HTTP_200_OK)
    

class CustomLoginView(APIView):
    permission_classes = []

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        password = request.data.get('password')

        if email is None or password is None:
            return Response({'error': 'Please provide both email and password'}, status=status.HTTP_400_BAD_REQUEST)

        print(f"Attempting to authenticate with email: {email}, {password}")
        
        
        try:
            user = User.objects.get(email=email)

            if user.is_admin:
                return Response({'error': 'Admin cannot access the user side.'}, status=status.HTTP_401_UNAUTHORIZED)
            if not user.check_password(password):
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
            
        except User.DoesNotExist:

            print(f"Failed login attempt with email: {email}")
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        refresh = RefreshToken.for_user(user)

        if user.is_seller:
            role = 'seller'
        elif user.is_buyer:
            role = 'buyer'
        else:
            return Response({'error': 'Invalid role'}, status=status.HTTP_401_UNAUTHORIZED)


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
        is_buyer = not is_seller 
        username = serializer.validated_data['username']
        address = serializer.validated_data['address']
        contact_number= serializer.validated_data['contact_number']


        try:
            user = User.objects.get(email=email)
            return Response({'detail': 'Email already registered'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            pass

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
        
        try:
            user = User.objects.get(email=email)
            user.is_active = True
        
            user.save()
        except User.DoesNotExist:
            return Response({"message": 'User not found', "success":False}, status=status.HTTP_404_NOT_FOUND)

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

class UpdateUserView(generics.UpdateAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    def put(self, request, *args, **kwargs):
        print("FFFFFFFF")
        user = self.get_object()
        print("USER",user)
        serializer = self.get_serializer(user, data=request.data, partial=True)
        print("QQQQQQQQQ")
        if serializer.is_valid():
            serializer.save()
            print("SSSSSSS")
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ChangePasswordView(generics.UpdateAPIView):
    serializer_class = PasswordChangeSerializer
    model = User
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    def post(self, request, *args, **kwargs):
        print("OOOOO PAASSWWOORD")
        user = self.get_object()
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            if not user.check_password(serializer.data.get("current_password")):
                return Response({"current_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            user.set_password(serializer.data.get("new_password"))
            user.save()
            update_session_auth_hash(request, user)
            return Response({"detail": "Password updated successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UpdateUserRole(generics.UpdateAPIView):
    serializer_class = UpdateUserRoleSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user
    
    def put(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=True)
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ForgotPasswordView(generics.GenericAPIView):
    serializer_class = ForgotPasswordSerializer
    permission_classes = [AllowAny]

    csrf_exempt
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        device = EmailDevice.objects.create(user=user, email=email)
        device.generate_challenge()
        print("Reset password OTP",device.token)

        send_mail(
            'Your OTP Code',
            f'Your OTP code is {device.token}',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )

        print("password reset OTP sent to email to:", email)

        return Response({
            'detail': 'OTP sent successfully',
            'email': email,
        }, status=status.HTTP_200_OK)



# class ForgotPasswordView(APIView):
#     permission_classes = [AllowAny]

#     def post(self,request):
#         print("FORGOT PASSWORD",request)
#         return Response({"Password Error"})
  
class ResetPasswordView(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        otp = serializer.validated_data['otp']
        password = serializer.validated_data['password']
        confirm_password = serializer.validated_data['confirm_password']

        if password != confirm_password:
            return Response({'error': 'Passwords do not match.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            device = EmailDevice.objects.get(email=email, token=otp)
        except EmailDevice.DoesNotExist:
            return Response({'error': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.get(email=email)
        user.set_password(password)
        user.save()

        return Response({'detail': 'Password reset successfully'}, status=status.HTTP_200_OK)

##Admin side lists

class SellerAPIView(APIView):
    def get(self, request, *args, **kwargs):
        sellers = Seller.objects.all()
        serializer = SellerSerializer(sellers, many=True)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        serializer = SellerSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        seller = Seller.objects.get(pk=kwargs['pk'])
        serializer = SellerSerializer(seller, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        seller = Seller.objects.get(pk=kwargs['pk'])
        seller.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class BuyerAPIView(APIView):
    def get(self, request, *args, **kwargs):
        buyers = Buyer.objects.all()
        serializer = BuyerSerializer(buyers, many=True)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        serializer = BuyerSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        buyer = Buyer.objects.get(pk=kwargs['pk'])
        serializer = BuyerSerializer(buyer, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        buyer = Buyer.objects.get(pk=kwargs['pk'])
        buyer.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class UserAPIView(APIView):
    def get(self, request, *args, **kwargs):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        user = User.objects.get(pk=kwargs['pk'])
        serializer = UserSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        user = User.objects.get(pk=kwargs['pk'])
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)