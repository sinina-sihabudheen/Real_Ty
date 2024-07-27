from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractUser
import random
from datetime import timedelta

def user_profile_image_path(instance, filename):
    # return f'user_{instance.id}/profile/{filename}'
    return 'images/{filename}'.format(filename=filename)

SOCIAL_PROVIDERS={'email':'email','google':'google','facebook':'facebook'}
class User(AbstractUser):
    email = models.EmailField(unique=True)
    address = models.CharField(max_length=255, blank=True, null=True)
    contact_number = models.CharField(max_length=15, blank=True, null=True)

    profile_image = models.ImageField(upload_to=user_profile_image_path, blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    social_provider = models.CharField(max_length=50, default=SOCIAL_PROVIDERS.items(),blank=True, null=True)  
    social_id = models.CharField(max_length=255, blank=True, null=True)
    date_of_birth = models.DateField(null=True, blank=True)
    is_seller = models.BooleanField(default=False)
    is_buyer = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)

    def __str__(self):
        return self.username

class Region(models.Model):
    name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)


    def __str__(self):
        return self.name

class Seller(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='seller_profiles')
    agency_name = models.CharField(max_length=255, blank=True, null=True)
    regions = models.ManyToManyField(Region)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    subscription_status = models.CharField(max_length=50, default='free')
    subscription_end_date = models.DateTimeField(default=timezone.now() + timezone.timedelta(days=30))

    def __str__(self):
        return f'{self.user.username} - {self.agency_name or "No Agency"}'

class Buyer(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='buyer_profiles')

    def __str__(self):
        return self.user.username
    
class AdminUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='admin_profile')

    def __str__(self):
        return self.user.username

class EmailDevice(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='accounts_email_devices')
    email = models.EmailField()
    token = models.CharField(max_length=20)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def generate_challenge(self):
        self.token = ''.join(random.choice('0123456789') for _ in range(6))
        self.save()

    def is_valid(self):
        return self.is_active and (timezone.now() < self.created_at + timedelta(minutes=1))

    def verify_token(self, token):
        return self.token == token

    def deactivate(self):
        self.is_active = False
        self.save()

class Amenity(models.Model):
    name = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.name

class PropertyCategory(models.Model):
    name = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.name

class LandProperty(models.Model):
    seller = models.ForeignKey(Seller, on_delete=models.CASCADE, related_name='land_properties')
    category = models.ForeignKey(PropertyCategory, on_delete=models.CASCADE, related_name='land_properties')
    area = models.DecimalField(max_digits=10, decimal_places=2, help_text='Area in cent or acre')
    price = models.DecimalField(max_digits=10, decimal_places=2, help_text='Price in lakhs')
    location = models.CharField(max_length=255)
    # images = models.ImageField(upload_to='property_images/', blank=True, null=True)
    video = models.FileField(upload_to='property_videos/', blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    amenities = models.ManyToManyField(Amenity)
    def __str__(self):
        return f"Land: {self.location}"

class ResidentialProperty(models.Model):
    PROPERTY_TYPE_CHOICES = [
        ('Villa', 'Villa'),
        ('Apartment', 'Apartment'),
    ]
    seller = models.ForeignKey(Seller, on_delete=models.CASCADE, related_name='residential_properties')
    category = models.ForeignKey(PropertyCategory, on_delete=models.CASCADE, related_name='residential_properties')
    property_type = models.CharField(max_length=50, choices=PROPERTY_TYPE_CHOICES)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    location = models.CharField(max_length=255)
    num_rooms = models.IntegerField()
    num_bathrooms = models.IntegerField()
    size = models.DecimalField(max_digits=10, decimal_places=2, help_text='Size in square feet')
    amenities = models.ManyToManyField(Amenity)
    description = models.TextField(blank=True, null=True)
    land_area = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True, help_text='Land area in cents (only for villas)')
    # images = models.ImageField(upload_to='property_images/', blank=True, null=True)
    video = models.FileField(upload_to='property_videos/', blank=True, null=True)
    
    def __str__(self):
        return f"{self.property_type}: {self.location}"
    
class PropertyImage(models.Model):
    image = models.ImageField(upload_to='property_images/')
    land_property  = models.ForeignKey(LandProperty, on_delete=models.CASCADE, related_name='images', null=True, blank=True)
    residential_property = models.ForeignKey(ResidentialProperty, on_delete=models.CASCADE, related_name='images', null=True, blank=True)

    def __str__(self) -> str:
        return f"Image for {self.land_property or self.residential_property}"
    
class Subscription(models.Model):
    seller = models.ForeignKey(Seller, on_delete=models.CASCADE)
    SUBSCRIPTION_TYPES = (
        ('monthly', 'Monthly'),
        ('yearly', 'Yearly'),
    )
    subscription_type = models.CharField(max_length=20, choices=SUBSCRIPTION_TYPES)
    
    PAYMENT_PLANS = (
        ('basic', 'Basic'),
        ('premium', 'Premium'),
    )
    payment_plan = models.CharField(max_length=20, choices=PAYMENT_PLANS, default='free')
    
    started_at = models.DateField(auto_now_add=True)
    ended_at = models.DateField(null=True, blank=True)
    
class SubscriptionPayment(models.Model):
    subscription = models.ForeignKey(Subscription, on_delete=models.CASCADE)
    user = models.ForeignKey(Seller, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_date = models.DateField(default=timezone.now)
    expiry_date = models.DateField()
    
    PAYMENT_STATUSES = (
        ('paid', 'Paid'),
        ('pending', 'Pending'),
        ('failed', 'Failed'),
    )
    payment_status = models.CharField(max_length=10, choices=PAYMENT_STATUSES)
    
    transaction_id = models.CharField(max_length=100)


