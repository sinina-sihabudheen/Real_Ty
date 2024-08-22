from django.contrib import admin
from .models import (
    User, Region, EmailDevice, Amenity, PropertyCategory,
    LandProperty, ResidentialProperty, Subscription, SubscriptionPayment, PropertyImage
)

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['id','username', 'email', 'contact_number', 'agency_name', 'address','is_admin','created_at','profile_image','subscription_status','subscription_end_date']
    search_fields = ['username', 'email']

@admin.register(Region)
class RegionAdmin(admin.ModelAdmin):
    list_display = ['name','is_active']


@admin.register(EmailDevice)
class EamilDeviceAdmin(admin.ModelAdmin):
    list_display = ['user','email', 'token', 'created_at', 'is_active']

@admin.register(Amenity)
class AmenityAdmin(admin.ModelAdmin):
    list_display = ['id','name']

@admin.register(PropertyCategory)
class PropertyCategoryAdmin(admin.ModelAdmin):
    list_display = ['id','name']

@admin.register(LandProperty)
class LandPropertyAdmin(admin.ModelAdmin):
    list_display = ['id', 'seller', 'category', 'price', 'area', 'location', 'video', 'description']
    search_fields = ['location']

@admin.register(ResidentialProperty)
class ResidentialPropertyAdmin(admin.ModelAdmin):
    list_display = ['id', 'seller', 'category', 'property_type', 'price', 'location', 'num_rooms', 'num_bathrooms', 'size', 'video', 'description', 'land_area']
    search_fields = ['location']

@admin.register(PropertyImage)
class PropertyImageAdmin(admin.ModelAdmin):
    list_display = ['id' ,'image']

@admin.register(Subscription)
class SubscriptionAdmin(admin.ModelAdmin):
    list_display = ['id', 'seller', 'subscription_type', 'started_at', 'ended_at', 'payment_plan',]


@admin.register(SubscriptionPayment)
class SubscriptionPaymentAdmin(admin.ModelAdmin):
    list_display = ['id', 'subscription', 'amount', 'payment_date', 'expiry_date', 'payment_status','transaction_id']
  