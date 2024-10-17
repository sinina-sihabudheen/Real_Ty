from rest_framework import viewsets, status, generics, serializers, permissions
from rest_framework.response import Response
from django.contrib.auth import get_user_model, update_session_auth_hash
from rest_framework.exceptions import ValidationError
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from .models import User, LandProperty, ResidentialProperty, EmailDevice, Region, Amenity, PropertyCategory,  SubscriptionPayment
from .serializers import RegionSerializer, LandPropertySerializer, ResidentialPropertySerializer, RegisterSerializer, AmenitySerializer, UserWithSubscriptionSerializer
from .serializers import OTPVerificationSerializer, ResendOTPSerializer, PasswordChangeSerializer, ForgotPasswordSerializer, ResetPasswordSerializer
from .serializers import RegisterResidentialPropertySerializer, RegisterLandPropertySerializer,PropertyCategorySerializer
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from .serializers import UserSerializer
from rest_framework.permissions import AllowAny,IsAuthenticated, IsAdminUser
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from rest_framework.parsers import MultiPartParser, FormParser
from django.db.models import Sum, Count, Q
from django.views.generic import ListView
from rest_framework.pagination import PageNumberPagination #pagination
User = get_user_model()
from django.http import JsonResponse
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

class GoogleLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        token = request.data.get('token')
        if not token:
            return Response({'message': 'No token provided'}, status=status.HTTP_400_BAD_REQUEST)
        try:

            payload = id_token.verify_oauth2_token(token, google_requests.Request(), settings.GOOGLE_CLIENT_ID)
            if payload['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                raise ValueError('Wrong issuer.')
        except ValueError:
            return Response({'message': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

        email = payload['email']
        name = payload.get('name', '')

        user, created = User.objects.get_or_create(email=email, defaults={
            'username': name,
            'social_provider': 'google', 
        })
        
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'role' : 'user'
            }, status=status.HTTP_200_OK)
    
class AdminLoginView(APIView):
    permission_classes = []

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        password = request.data.get('password')
        
        if not email or not password:
            return Response({'message': 'Please provide both email and password'},status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            if not user.check_password(password) or not user.is_staff:
                return Response({'message': 'Invalid email or password'},status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response(
                {'message': 'User is not exist.'}, 
                status=status.HTTP_400_BAD_REQUEST)

        refresh = RefreshToken.for_user(user)

        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'role': 'admin',
        }, status=status.HTTP_200_OK)
    

class CustomLoginView(APIView):
    permission_classes = []

    def post(self, request, *args, **kwargs):

        print(f"Request data: {request.data}")
        email = request.data.get('email')
        password = request.data.get('password')
        print(f"Email: {email}, Password: {password}")

    
        if not email or not password:
            return Response({'message': 'Please provide both email and password'}, status=status.HTTP_400_BAD_REQUEST)

        print(f"Attempting to authenticate with email: {email}, {password}")

        user = authenticate(request, username=email, password=password)
        print(f"Authenticated user: {user}")

        
        if user is None:
            print("Invalid email or password")
            return Response({'message': 'Invalid email or password',"error":True}, status=status.HTTP_400_BAD_REQUEST)
        
        if user.is_admin:
            return Response({'message': 'Admin cannot access the user side.'}, status=status.HTTP_400_BAD_REQUEST)
        


        refresh = RefreshToken.for_user(user)

       
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'role': 'user',
        }, status=status.HTTP_200_OK)
    
class UserRegistrationView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as e:
            return Response({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        username = serializer.validated_data['username']
        address = serializer.validated_data['address']
        contact_number = serializer.validated_data['contact_number']
        agency_name = serializer.validated_data['agency_name']


        # Check for email existence only
        if User.objects.filter(email=email).exists():
            return Response({'message': 'Email already registered'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                address=address,
                contact_number=contact_number,   
                agency_name=agency_name, 
            )
                
        except Exception as e:
            return Response({'message': 'Error creating user'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
        try:
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
                'message': 'An OTP sent to your email successfully',
                'email': email,
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'message': 'Error sending OTP email'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
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
            return Response({'message': 'User is not found'}, status=status.HTTP_404_NOT_FOUND)

     
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
    
class SellerProfileView(generics.RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]  

    def get_object(self):
        user_id = self.kwargs.get('userId')
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            raise serializers.ValidationError({'User': 'User does not exist.'})
        

class SellerProfileLandsViewSet(viewsets.ModelViewSet):
    serializer_class = LandPropertySerializer
    permission_classes = [permissions.AllowAny]  

    def get_queryset(self):
        user_id = self.kwargs.get('userId')
        try:
            seller = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return LandProperty.objects.none() 
        return LandProperty.objects.filter(seller=seller)


class SellerProfileResidentsViewSet(viewsets.ModelViewSet):
    serializer_class = ResidentialPropertySerializer
    permission_classes = [permissions.AllowAny]  

    def get_queryset(self):
        user_id = self.kwargs.get('userId')
        try:
            seller = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return ResidentialProperty.objects.none()  
        return ResidentialProperty.objects.filter(seller=seller)
 

class RegisterLandsViewSet(viewsets.ModelViewSet):
    queryset = LandProperty.objects.all()
    serializer_class = RegisterLandPropertySerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        category_name = self.request.data.get('category')
        seller = self.request.user

        if not category_name:
            raise serializers.ValidationError({'category': 'Category is required.'})

        try:
            category = PropertyCategory.objects.get(name=category_name)
        except PropertyCategory.DoesNotExist:
            raise serializers.ValidationError({'category': 'Category does not exist.'})

        serializer.save(category=category, seller=seller)


class RegisterResidentialsViewSet(viewsets.ModelViewSet):
    queryset = ResidentialProperty.objects.all()
    serializer_class = RegisterResidentialPropertySerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        category_name = self.request.data.get('category')
        seller = self.request.user

        if not category_name:
            raise serializers.ValidationError({'category': 'Category is required.'})

        try:
            category = PropertyCategory.objects.get(name=category_name)
        except PropertyCategory.DoesNotExist:
            raise serializers.ValidationError({'category': 'Category does not exist.'})

        serializer.save(category=category, seller=seller)

class PropertySetPagination(PageNumberPagination):
    page_size = 6
    page_size_query_param = 'page_size'
   

class SellerLandsViewSet(viewsets.ModelViewSet):
    serializer_class = LandPropertySerializer
    permission_classes = [IsAuthenticated]
    pagination_class = PropertySetPagination

    def get_queryset(self):
        user = self.request.user
        try:
            seller = User.objects.get(id=user.id)
        except User.DoesNotExist:
            return LandProperty.objects.none() 
        return LandProperty.objects.filter(seller=seller)


class SellerResidentsViewSet(viewsets.ModelViewSet):
    serializer_class = ResidentialPropertySerializer
    permission_classes = [IsAuthenticated]
    pagination_class = PropertySetPagination

    def get_queryset(self):
        user = self.request.user
        try:
            seller = User.objects.get(id=user.id)
        except User.DoesNotExist:
            return ResidentialProperty.objects.none()  
        return ResidentialProperty.objects.filter(seller=seller)
    
class LandsListViewSet(viewsets.ModelViewSet):
    serializer_class = LandPropertySerializer
    permission_classes = [IsAuthenticated]
    pagiation_class = PropertySetPagination
    queryset = LandProperty.objects.all()


class ResidentsListViewSet(viewsets.ModelViewSet):
    serializer_class = ResidentialPropertySerializer
    permission_classes = [IsAuthenticated]
    pagiation_class = PropertySetPagination
    queryset = ResidentialProperty.objects.all()

class LandPropertyDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = LandProperty.objects.all()
    serializer_class = LandPropertySerializer
    permission_classes = [IsAuthenticated]

    def perform_update(self, serializer):
        video = self.request.FILES.get('video')
        if video:
            serializer.validated_data['video'] = video
        
        serializer.save()


class ResidentialPropertyDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = ResidentialProperty.objects.all()
    serializer_class = ResidentialPropertySerializer
    permission_classes = [IsAuthenticated]

    def perform_update(self, serializer):
        video = self.request.FILES.get('video')
        if video:
            serializer.validated_data['video'] = video
        
        serializer.save()

class UpdateUserView(generics.UpdateAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)


    def get_object(self):
        return self.request.user

    def put(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ChangePasswordView(generics.UpdateAPIView):
    serializer_class = PasswordChangeSerializer
    model = User
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    def post(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            if not user.check_password(serializer.data.get("current_password")):
                return Response({"current_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            user.set_password(serializer.data.get("new_password"))
            user.save()
            update_session_auth_hash(request, user)
            return Response({"message": "Password updated successfully"}, status=status.HTTP_200_OK)
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
            return Response({'message': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

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
            'message': 'OTP sent successfully',
            'email': email,
        }, status=status.HTTP_200_OK)
  
class ResetPasswordView(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer
    permission_classes = [AllowAny] 

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        otp = serializer.validated_data['otp']
        password = serializer.validated_data['password']
        confirm_password = serializer.validated_data['confirm_password']

        if password != confirm_password:
            return Response({'message': 'Passwords do not match.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            device = EmailDevice.objects.get(email=email, token=otp)
        except EmailDevice.DoesNotExist:
            return Response({'message': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.get(email=email)
        user.set_password(password)
        user.save()

        return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)

##Admin side lists

#pagination
class LargeResultsSetPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'

   

# List users
class UserListAPIView(generics.ListAPIView):
    serializer_class = UserSerializer
    pagination_class = LargeResultsSetPagination    #pagination

    def get_queryset(self):
     
        return User.objects.exclude(is_admin=True)
    


class UserBlockAPIView(APIView):
    permission_classes = [IsAdminUser]

    def patch(self, request, *args, **kwargs):
        user = User.objects.get(pk=kwargs['pk'])
        user.is_active = False 
        user.save()
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

class UnblockUserAPIView(APIView):
    permission_classes = [IsAdminUser]

    def patch(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
            user.is_active = True
            user.save()
            return Response({"detail": "User unblocked successfully."}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)
     

class RegionViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [AllowAny]
    queryset = Region.objects.all()
    serializer_class = RegionSerializer 

class RegionCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        print("Received request data:", request.data)

        serializer = RegionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RegionDeleteAPIView(APIView):    
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        try:
            region = Region.objects.get(pk=pk)
        except Region.DoesNotExist:
            return Response({'message': 'Region not found'}, status=status.HTTP_404_NOT_FOUND)

        region.delete()
        return Response({'message': 'No content'},status=status.HTTP_204_NO_CONTENT)
    

class CategoryViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [AllowAny]
    queryset = PropertyCategory.objects.all()
    serializer_class = PropertyCategorySerializer 


class CategoryCreateAPIView(APIView):
    def post(self, request):
        serializer = PropertyCategorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CategoryDeleteAPIView(APIView):
    def delete(self, request, pk):
        try:
            category = PropertyCategory.objects.get(pk=pk)
        except PropertyCategory.DoesNotExist:
            return Response({'message': 'Category not found'}, status=status.HTTP_404_NOT_FOUND)

        category.delete()
        return Response({'message': 'No content'}, status=status.HTTP_204_NO_CONTENT)



class AmenityViewSet(viewsets.ModelViewSet):
    queryset = Amenity.objects.all()
    serializer_class = AmenitySerializer


# Add a new amenity
class AmenityCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = AmenitySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Delete an amenity
class AmenityDeleteAPIView(APIView):
    def delete(self, request, pk):
        try:
            amenity = Amenity.objects.get(pk=pk)
        except Amenity.DoesNotExist:
            return Response({'message': 'Amenity not found'}, status=status.HTTP_404_NOT_FOUND)

        amenity.delete()
        return Response({'message': 'No content'}, status=status.HTTP_204_NO_CONTENT)




def admin_dashboard_data(request):   
    total_land_properties = LandProperty.objects.count()
    total_residential_properties = ResidentialProperty.objects.count()
    total_apartments = ResidentialProperty.objects.filter(property_type='Apartment').count()
    total_villas = ResidentialProperty.objects.filter(property_type='Villa').count()
    total_listings = total_land_properties + total_residential_properties

    subscription_growth = SubscriptionPayment.objects.count()
    total_revenue = SubscriptionPayment.objects.aggregate(total=Sum('amount'))['total']

    total_users = User.objects.count()
    
    return JsonResponse({
        'total_listings': total_listings,
        'total_land_properties': total_land_properties,
        'total_residential_properties': total_residential_properties,
        'total_apartments' : total_apartments,
        'total_villas' : total_villas,
        'subscription_growth': subscription_growth,
        'total_revenue': total_revenue,
        'total_users' : total_users,

    })


class PropertySearchView(ListView):
    template_name = 'property_search.html'
    context_object_name = 'results'

    def get_queryset(self):
        query = Q()

        seller_name = self.request.GET.get('seller_name')
        location = self.request.GET.get('location')
        category_name = self.request.GET.get('category_name')
        min_price = self.request.GET.get('min_price')
        max_price = self.request.GET.get('max_price')

        if seller_name:
            query &= Q(seller__username__icontains=seller_name)
        if location:
            query &= Q(location__icontains=location)
        if category_name:
            query &= Q(category__name__icontains=category_name)
        if min_price:
            query &= Q(price__gte=min_price)
        if max_price:
            query &= Q(price__lte=max_price)

        land_properties = LandProperty.objects.filter(query)
        residential_properties = ResidentialProperty.objects.filter(query)

        return list(land_properties) + list(residential_properties)
    
class PremiumUserListAPIView(generics.ListAPIView):
    serializer_class = UserWithSubscriptionSerializer
    permission_classes = [IsAdminUser]

    def get_queryset(self):
        current_date = timezone.now().date()
        queryset = User.objects.filter(
            subscription__payment_plan='premium',
            subscription__ended_at__gte=current_date
        ).distinct()
        return queryset

