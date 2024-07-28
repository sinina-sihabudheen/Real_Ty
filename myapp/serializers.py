from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.core.validators import RegexValidator
from .models import Seller, LandProperty, ResidentialProperty, EmailDevice, Region, Buyer, Amenity, PropertyCategory, PropertyImage
from django.contrib.auth.password_validation import validate_password


User = get_user_model()

class RegionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Region
        fields = '__all__'

class AmenitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Amenity
        fields = '__all__'  

class UserSerializer(serializers.ModelSerializer):
    profile_image = serializers.ImageField(required=False)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'address', 'contact_number', 'profile_image', 'is_seller', 'is_buyer', 'date_of_birth']

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
        fields = ['username', 'email', 'password', 'confirm_password', 'address', 'contact_number', 'is_seller', 'is_buyer', 'agency_name', 'regions', 'token']
       
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
            # 'username': {
            #     'validators': [
            #         RegexValidator(
            #             regex=r'^[a-zA-Z]*$', 
            #             message='Username should only contain letters'
            #         )
            #     ]
            # }
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
        
        is_seller = validated_data.get('is_seller', False)
        is_buyer = not is_seller

        validated_data['is_seller'] = is_seller
        validated_data['is_buyer'] = is_buyer
        print(f"Creating user with is_seller={is_seller} and is_buyer={is_buyer}")
        
       
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'], 
            password=validated_data['password'],
            address=validated_data.get('address'),
            contact_number=validated_data.get('contact_number'),
            is_seller=is_seller,
            is_buyer=is_buyer
        )

       
        if is_seller:
            
            seller_profile = Seller.objects.create(
                user=user, 
                agency_name=validated_data['agency_name'],
                
            )
            seller_profile.regions.set(validated_data['regions'])
        else:
            
            Buyer.objects.create(
                user=user,
                
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

class PropertyImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = PropertyImage
        # fields = ['id', 'image']
        fields = ['image', 'land_property', 'residential_property']


class RegisterLandPropertySerializer(serializers.ModelSerializer):
    images = PropertyImageSerializer(many=True, read_only=True)
    new_images = serializers.ListField(
        child=serializers.ImageField(), write_only=True, required=False
    )

    amenities = serializers.PrimaryKeyRelatedField(queryset=Amenity.objects.all(), many=True)
    category = serializers.CharField()  
    seller = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = LandProperty
        fields = ['price', 'description', 'area', 'amenities', 'location', 'video', 'category', 'seller','images','new_images']
        
    def validate_category(self, value):
        if value and not PropertyCategory.objects.filter(name=value).exists():
            raise serializers.ValidationError('Category does not exist.')
        return value
    
    def create(self, validated_data):
        new_images = validated_data.pop('new_images', [])    
        if new_images:
            print("IMAGES ADDED")
        else:
            print("IMAGES NOT ADDED")

        print(f"Validated data: {validated_data}")

        land_property = super().create(validated_data)
        for image in new_images:
            print(f"Creating PropertyImage with land_property={land_property} and image={image}")

            PropertyImage.objects.create(land_property=land_property, image=image)
        return land_property

class RegisterResidentialPropertySerializer(serializers.ModelSerializer):
    images = PropertyImageSerializer(many=True, read_only=True)
    new_images = serializers.ListField(
        child=serializers.ImageField(), write_only=True, required=False
    )

    category = serializers.CharField()  
    amenities = serializers.PrimaryKeyRelatedField(queryset=Amenity.objects.all(),many=True)
    seller = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = ResidentialProperty
        fields = ['seller', 'category', 'property_type', 'price', 'location', 'num_rooms', 'num_bathrooms', 'size', 'amenities', 'description', 'land_area', 'video','images','new_images']

    def validate_category(self, value):
        if not PropertyCategory.objects.filter(name=value).exists():
            raise serializers.ValidationError('Category does not exist.')
        return value
    
    def create(self, validated_data):
        new_images = validated_data.pop('new_images', [])
        residential_property = super().create(validated_data)
        for image in new_images:
            PropertyImage.objects.create(residential_property=residential_property, image=image)
        return residential_property
    
class LandPropertySerializer(serializers.ModelSerializer):
    images = PropertyImageSerializer(many=True, read_only=True)
    # images = serializers.PrimaryKeyRelatedField(many=True, read_only=True)

    amenities = serializers.PrimaryKeyRelatedField(queryset=Amenity.objects.all(), many=True)
    category = serializers.CharField()  
    # seller = serializers.PrimaryKeyRelatedField(read_only=True)
    seller = SellerSerializer(read_only=True)


    class Meta:
        model = LandProperty
        fields = ['id', 'price', 'description', 'area', 'amenities', 'location', 'video', 'category', 'seller','images']
        
    def validate_category(self, value):
        if value and not PropertyCategory.objects.filter(name=value).exists():
            raise serializers.ValidationError('Category does not exist.')
        return value

class ResidentialPropertySerializer(serializers.ModelSerializer):
    images = PropertyImageSerializer(many=True, read_only=True)
    # images = serializers.PrimaryKeyRelatedField(many=True, read_only=True)


    category = serializers.CharField()  
    amenities = serializers.PrimaryKeyRelatedField(many=True, queryset=Amenity.objects.all())
    # seller = serializers.PrimaryKeyRelatedField(read_only=True)
    seller = SellerSerializer(read_only=True)


    class Meta:
        model = ResidentialProperty
        fields = ['id', 'seller', 'category', 'property_type', 'price',
                 'location', 'num_rooms', 'num_bathrooms', 'size', 'amenities',
                 'description', 'land_area', 'video','images']

    def validate_category(self, value):
        if not PropertyCategory.objects.filter(name=value).exists():
            raise serializers.ValidationError('Category does not exist.')
        return value

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
    
class UpdateUserRoleSerializer(serializers.ModelSerializer):
    agency_name = serializers.CharField(required=False)
    regions = serializers.ListField(
        child=serializers.IntegerField(), required=False
    )

    class Meta:
        model = User
        fields = ['is_seller', 'is_buyer', 'agency_name', 'regions']

    def update(self, instance, validated_data):
        is_seller = validated_data.get('is_seller', instance.is_seller)
        is_buyer = validated_data.get('is_buyer', instance.is_buyer)
        agency_name = validated_data.get('agency_name', None)
        regions_data = validated_data.get('regions', [])

        instance.is_seller = is_seller
        instance.is_buyer = is_buyer
        instance.save()

        if is_seller:
            seller, created = Seller.objects.get_or_create(user=instance)
            if agency_name:
                seller.agency_name = agency_name
            if regions_data:
                regions = Region.objects.filter(id__in=regions_data)
                seller.regions.set(regions)
            seller.save()

        if is_buyer:
            Buyer.objects.get_or_create(user=instance)

        return instance