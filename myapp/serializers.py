from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.core.validators import RegexValidator
from .models import LandProperty, ResidentialProperty, EmailDevice, Region, Amenity, PropertyCategory, PropertyImage, Subscription, SubscriptionPayment
from django.contrib.auth.password_validation import validate_password


User = get_user_model()

class RegionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Region
        fields = '__all__'

class AmenitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Amenity
        fields = ['id', 'name' ]
        
class PropertyCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = PropertyCategory
        fields = ['id','name']  

class UserSerializer(serializers.ModelSerializer):
    profile_image = serializers.ImageField(required=False)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'address', 'contact_number', 'profile_image','agency_name', 'social_provider','is_active']

    def update(self, instance, validated_data):
        profile_image = validated_data.pop('profile_image', None)
        instance = super().update(instance, validated_data)
        if profile_image:
            instance.profile_image = profile_image
            instance.save()
        return instance

class RegisterSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)
    agency_name = serializers.CharField(write_only=True, required=False)
    token = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'confirm_password', 'address', 'contact_number', 'agency_name', 'token']
       
        extra_kwargs = {
            'password': {'write_only': True},
            'email': {
                'validators': [
                    RegexValidator(
                        regex=r'^[a-zA-Z0-9@.]*$', 
                        message='Email should only contain letters and "@" or "."'
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
        errors = {}
        if data['password'] != data['confirm_password']:
            errors['confirm_password'] = ["Passwords do not match."]
        if errors:
            raise serializers.ValidationError(errors)
        return data

    def create(self, validated_data):
        validated_data.pop('confirm_password', None)
        token = validated_data.pop('token', None)
        

        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'], 
            password=validated_data['password'],
            address=validated_data.get('address'),
            contact_number=validated_data.get('contact_number'),
            agency_name=validated_data['agency_name'],            
        )

        return {
            'validated_data': validated_data,
            'token': token
        }


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField()
    password = serializers.CharField()
    confirm_password = serializers.CharField()


class PropertyImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = PropertyImage
        fields = ['image', 'land_property', 'residential_property']




class RegisterLandPropertySerializer(serializers.ModelSerializer):
    images = PropertyImageSerializer(many=True, read_only=True)
    new_images = serializers.ListField(
        child=serializers.ImageField(), write_only=True, required=False
    )
    amenities = serializers.PrimaryKeyRelatedField(queryset=Amenity.objects.all(), many=True)
    category = serializers.CharField()
    seller = UserSerializer(read_only=True)

    class Meta:
        model = LandProperty
        fields = ['id', 'price', 'description', 'area', 'amenities', 'location', 'video', 'category', 'seller', 'images', 'new_images']

    def validate(self, data):
        category_name = data.get('category')
        if category_name:
            try:
                category = PropertyCategory.objects.get(name=category_name)
                data['category'] = category.id  # Use ID instead of instance
            except PropertyCategory.DoesNotExist:
                raise serializers.ValidationError({'category': 'Category does not exist.'})
        return data
    
    def create(self, validated_data):
        new_images = validated_data.pop('new_images', [])
        land_property = super().create(validated_data)

        for image in new_images:
            PropertyImage.objects.create(land_property=land_property, image=image)

        return land_property



class RegisterResidentialPropertySerializer(serializers.ModelSerializer):
    images = PropertyImageSerializer(many=True, read_only=True)
    new_images = serializers.ListField(
        child=serializers.ImageField(), write_only=True, required=False
    )
    category = serializers.CharField()  # Accept category as name (string)
    amenities = serializers.PrimaryKeyRelatedField(queryset=Amenity.objects.all(), many=True)
    seller = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = ResidentialProperty
        fields = ['seller', 'category', 'property_type', 'price', 'location', 'num_rooms', 'num_bathrooms', 'size', 'amenities', 'description', 'land_area', 'video', 'images', 'new_images']

    def validate(self, data):
        category_name = data.get('category')
        if category_name:
            try:
                category = PropertyCategory.objects.get(name=category_name)
                data['category'] = category.id  # Use ID instead of instance
            except PropertyCategory.DoesNotExist:
                raise serializers.ValidationError({'category': 'Category does not exist.'})
        return data

    def create(self, validated_data):
        new_images = validated_data.pop('new_images', [])
        residential_property = super().create(validated_data)

        for image in new_images:
            PropertyImage.objects.create(residential_property=residential_property, image=image)

        return residential_property

    
class LandPropertySerializer(serializers.ModelSerializer):
    images = PropertyImageSerializer(many=True, read_only=True)
    amenities = serializers.PrimaryKeyRelatedField(queryset=Amenity.objects.all(), many=True)

    category = serializers.CharField()  
    seller = UserSerializer(read_only=True)


    class Meta:
        model = LandProperty
        fields = ['id', 'price', 'description', 'area', 'amenities', 'location', 'video', 'category', 'seller','images']
        
    def validate_category(self, value):
        if value and not PropertyCategory.objects.filter(name=value).exists():
            raise serializers.ValidationError('Category does not exist.')
        return value
    
    def update(self, instance, validated_data):
        category_name = validated_data.pop('category', None)
        amenities_data = validated_data.pop('amenities', None)
        
        # Update other fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        # Handle many-to-many field
        if amenities_data is not None:
            instance.amenities.set(amenities_data)
        if category_name:
            category = PropertyCategory.objects.get(name=category_name)
            instance.category = category

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()
    
        return instance

class ResidentialPropertySerializer(serializers.ModelSerializer):
    images = PropertyImageSerializer(many=True, read_only=True)
    amenities = serializers.PrimaryKeyRelatedField(queryset=Amenity.objects.all(), many=True)

    category = serializers.CharField()  
    seller = UserSerializer(read_only=True)


    class Meta:
        model = ResidentialProperty
        fields = ['id', 'seller', 'category', 'property_type', 'price',
                 'location', 'num_rooms', 'num_bathrooms', 'size', 'amenities',
                 'description', 'land_area', 'video','images']

    def validate_category(self, value):
        if not PropertyCategory.objects.filter(name=value).exists():
            raise serializers.ValidationError('Category does not exist.')
        return value
    
    def update(self, instance, validated_data):
        category_name = validated_data.pop('category', None)
        amenities_data = validated_data.pop('amenities', None)
        
        # Update other fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        # Handle many-to-many field
        if amenities_data is not None:
            instance.amenities.set(amenities_data)

        if category_name:
            category = PropertyCategory.objects.get(name=category_name)
            instance.category = category

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()
        return instance
    

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

class PasswordChangeSerializer(serializers.Serializer):
    current_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def validate_new_password(self, value):
        validate_password(value)
        return value
    
    def update(self, instance, validated_data):
        instance.set_password(validated_data['new_password'])
        instance.save()
        return instance
    
class SubscriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subscription
        fields = ['subscription_type', 'payment_plan', 'started_at', 'ended_at','seller']

class UserWithSubscriptionSerializer(serializers.ModelSerializer):
    subscriptions = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'subscriptions','is_active']

    def get_subscriptions(self, user):
        # Filter subscriptions where the seller is the current user
        subscriptions = Subscription.objects.filter(seller=user)
        return SubscriptionSerializer(subscriptions, many=True).data