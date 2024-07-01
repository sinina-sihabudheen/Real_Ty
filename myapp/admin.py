from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User,Seller,Region,Buyer

admin.site.register(User, UserAdmin)
admin.site.register(Seller)
admin.site.register(Buyer)
admin.site.register(Region)
