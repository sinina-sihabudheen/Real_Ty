from django.db import models
from django.contrib.auth.models import AbstractUser
import random
from django.utils import timezone
from datetime import timedelta
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey

def user_profile_image_path(instance, filename):
    return f'images/{filename}'

SOCIAL_PROVIDERS = {'email': 'email', 'google': 'google'}

class User(AbstractUser):
    email = models.EmailField(unique=True)
    address = models.CharField(max_length=255, blank=True, null=True)
    contact_number = models.CharField(max_length=15, blank=True, null=True)
    profile_image = models.ImageField(upload_to=user_profile_image_path, blank=True, null=True)    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    social_provider = models.CharField(max_length=50, choices=[(key, value) for key, value in SOCIAL_PROVIDERS.items()], blank=True, null=True)
    social_id = models.CharField(max_length=255, blank=True, null=True)
    agency_name = models.CharField(max_length=255, blank=True, null=True)  # Optional for sellers
    subscription_status = models.CharField(max_length=50, default='basic')
    subscription_end_date = models.DateTimeField(default=timezone.now() + timezone.timedelta(days=30))
    is_admin = models.BooleanField(default=False)  # For admin users

    def __str__(self):
        return self.username

class EmailDevice(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='email_devices')
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

class Region(models.Model):
    name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)


    def __str__(self):
        return self.name
    
class Amenity(models.Model):
    name = models.CharField(max_length=255, unique=True)
    def __str__(self):
        return self.name

class PropertyCategory(models.Model):
    name = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.name

class LandProperty(models.Model):
    seller = models.ForeignKey(User, on_delete=models.CASCADE)
    category = models.ForeignKey(PropertyCategory, on_delete=models.CASCADE)
    area = models.DecimalField(max_digits=10, decimal_places=2, help_text='Area in cent or acre')
    price = models.DecimalField(max_digits=10, decimal_places=2, help_text='Price in lakhs')

    location = models.CharField(max_length=255)
    latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    
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
    seller = models.ForeignKey(User, on_delete=models.CASCADE)    
    category = models.ForeignKey(PropertyCategory, on_delete=models.CASCADE)
    property_type = models.CharField(max_length=50, choices=PROPERTY_TYPE_CHOICES)
    price = models.DecimalField(max_digits=10, decimal_places=2)

    location = models.CharField(max_length=255)
    latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)

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
    seller = models.ForeignKey(User, on_delete=models.CASCADE)
    SUBSCRIPTION_TYPES = (
        ('monthly', 'Monthly'),
        ('yearly', 'Yearly'),
    )
    subscription_type = models.CharField(max_length=20, choices=SUBSCRIPTION_TYPES)
    
    PAYMENT_PLANS = (
        ('basic', 'Basic'),
        ('premium', 'Premium'),
    )
    payment_plan = models.CharField(max_length=20, choices=PAYMENT_PLANS, default='basic')
    
    started_at = models.DateField(auto_now_add=True)
    ended_at = models.DateField(null=True, blank=True)
    stripe_subscription_id = models.CharField(max_length=255, blank=True, null=True)

    
class SubscriptionPayment(models.Model):
    subscription = models.ForeignKey(Subscription, on_delete=models.CASCADE)
    # user = models.ForeignKey(User, on_delete=models.CASCADE)
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


# class Message(models.Model):
#     sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sent_messages")
#     receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name="received_messages")
#     text = models.TextField()
#     timestamp = models.DateTimeField(auto_now_add=True)
#     property_land = models.ForeignKey(LandProperty, on_delete=models.CASCADE, null=True, blank=True)
#     property_resident = models.ForeignKey(ResidentialProperty, on_delete=models.CASCADE, null=True, blank=True)


#     def __str__(self):
#         return f"Message from {self.sender} to {self.receiver} - {self.timestamp}"


class Message(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sent_messages")
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name="received_messages")
    text = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    # Generic Foreign Key for the property
    property_content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True, blank=True)
    property_object_id = models.PositiveIntegerField(null=True, blank=True)
    property = GenericForeignKey('property_content_type', 'property_object_id')

    def __str__(self):
        return f"Message from {self.sender} to {self.receiver} - {self.timestamp}"

    class Meta:
        ordering = ['timestamp']