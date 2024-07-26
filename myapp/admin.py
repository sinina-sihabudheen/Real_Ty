from django.contrib import admin
# from .models import User, Region, Seller, Buyer, EmailDevice, Amenity, PropertyCategory, LandProperty, ResidentialProperty
# Register your models here
from .models import (
    User, Seller, Buyer, Region, EmailDevice, Amenity, PropertyCategory,
    LandProperty, ResidentialProperty, Subscription, SubscriptionPayment
)

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['id','username', 'email', 'contact_number', 'address', 'is_seller', 'is_buyer','is_admin','created_at','profile_image']
    list_filter = ['is_seller', 'is_buyer']
    search_fields = ['username', 'email']

@admin.register(Region)
class RegionAdmin(admin.ModelAdmin):
    list_display = ['name','is_active']

@admin.register(Seller)
class SellerAdmin(admin.ModelAdmin):
    list_display = ['user', 'agency_name', 'subscription_status']
    list_filter = ['subscription_status']
    search_fields = ['user__username', 'agency_name']

@admin.register(Buyer)
class BuyerAdmin(admin.ModelAdmin):
    list_display = ['user']

@admin.register(EmailDevice)
class EamilDeviceAdmin(admin.ModelAdmin):
    list_display = ['email', 'token', 'created_at', 'is_active']

@admin.register(Amenity)
class AmenityAdmin(admin.ModelAdmin):
    list_display = ['id','name']

@admin.register(PropertyCategory)
class PropertyCategoryAdmin(admin.ModelAdmin):
    list_display = ['id','name']

@admin.register(LandProperty)
class LandPropertyAdmin(admin.ModelAdmin):
    list_display = ['id', 'seller', 'category', 'price', 'area', 'location', 'images', 'video', 'description']
    search_fields = ['location']

@admin.register(ResidentialProperty)
class ResidentialPropertyAdmin(admin.ModelAdmin):
    list_display = ['id', 'seller', 'category', 'property_type', 'price', 'location', 'num_rooms', 'num_bathrooms', 'size', 'images', 'video', 'description', 'land_area']
    search_fields = ['location']