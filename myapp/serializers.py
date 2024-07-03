from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.core.validators import RegexValidator
from .models import Seller, LandProperty, ResidentialProperty, EmailDevice, Region, Buyer

User = get_user_model()

class RegionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Region
        fields = '__all__'

class UserSerializer(serializers.ModelSerializer):
    profile_image = serializers.ImageField(write_only=True, required=False)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'address', 'contact_number', 'profile_image', 'is_seller', 'is_buyer']

    def update(self, instance, validated_data):
        profile_image = validated_data.pop('profile_image', None)
        instance = super().update(instance, validated_data)
        if profile_image:
            instance.profile_image = profile_image
            instance.save()
        return instance

class RegisterSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)
    is_seller = serializers.BooleanField(write_only=True, required=False)
    agency_name = serializers.CharField(write_only=True, required=False)
    regions = serializers.PrimaryKeyRelatedField(queryset=Region.objects.all(), write_only=True, many=True, required=False)
    token = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'confirm_password', 'address', 'contact_number', 'is_seller', 'agency_name', 'regions', 'token']
       
        extra_kwargs = {
            'password': {'write_only': True},
            'email': {
                'validators': [
                    RegexValidator(
                        regex=r'^[a-zA-Z0-9@.]*$', 
                        message='Email should only contain letters and "@" or "."'
                    )
                ]
            },
            'username': {
                'validators': [
                    RegexValidator(
                        regex=r'^[a-zA-Z]*$', 
                        message='Username should only contain letters'
                    )
                ]
            }
        }
    def validate_password(self, value):
            if len(value) < 8:
                raise serializers.ValidationError("Password must be at least 8 characters long.")
            if not any(char.isdigit() for char in value):
                raise serializers.ValidationError("Password must contain at least one digit.")
            if not any(char.isalpha() for char in value):
                raise serializers.ValidationError("Password must contain at least one letter.")
            return value

    def validate_contact_number(self, value):
            if not value.isdigit():
                raise serializers.ValidationError("Contact number should only contain digits.")
            if len(value) != 10:
                raise serializers.ValidationError("Contact number should be 10 digits long.")
            if value[0] not in '6789':
                raise serializers.ValidationError("Contact number should start with 6, 7, 8, or 9.")
            return value    

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use.")
        return value

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        if data.get('is_seller') and (not data.get('agency_name') or not data.get('regions')):
            raise serializers.ValidationError("Agency name and regions are required for seller registration.")
        return data

  
    def create(self, validated_data):
        validated_data.pop('confirm_password', None)
        token = validated_data.pop('token', None)
        
        user = User.objects.create_user(
            username=validated_data['email'], 
            email=validated_data['email'], 
            password=validated_data['password'],
            **{key: value for key, value in validated_data.items() if key not in ['is_seller', 'agency_name', 'regions']}
        )

        if validated_data.get('is_seller'):
            seller_profile = Seller.objects.create(
                user=user, 
                agency_name=validated_data['agency_name']
            )
            seller_profile.regions.set(validated_data['regions'])
        else:
            Buyer.objects.create(user=user)

        return {
            'validated_data': validated_data,
            'token': token
        }

class SellerSerializer(serializers.ModelSerializer):
    user = UserSerializer()
    regions = RegionSerializer(many=True)

    class Meta:
        model = Seller
        fields = ['id', 'user', 'agency_name', 'regions', 'subscription_status', 'subscription_end_date']

    def create(self, validated_data):
        regions_data = validated_data.pop('regions', [])
        user_data = validated_data.pop('user')

        user = User.objects.create_user(**user_data)
        seller = Seller.objects.create(user=user, **validated_data)

        for region_data in regions_data:
            region, _ = Region.objects.get_or_create(**region_data)
            seller.regions.add(region)

        return seller

class BuyerSerializer(serializers.ModelSerializer):
    user = UserSerializer()

    class Meta:
        model = Buyer
        fields = ['id', 'user']

class LandPropertySerializer(serializers.ModelSerializer):
    class Meta:
        model = LandProperty
        fields = '__all__'

class ResidentialPropertySerializer(serializers.ModelSerializer):
    class Meta:
        model = ResidentialProperty
        fields = '__all__'


class OTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    token = serializers.CharField(max_length=6)


class OTPVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    token = serializers.CharField(max_length=6)

    def validate(self, data):
        try:
            user = User.objects.get(email=data['email'])
            device = EmailDevice.objects.get(user=user, token=data['token'], is_active=True)
            if not device.is_valid():
                device.deactivate()
                raise serializers.ValidationError('OTP is invalid or expired')
        except (User.DoesNotExist, EmailDevice.DoesNotExist):
            raise serializers.ValidationError('Invalid OTP or email')
        return data


class ResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()