from django.contrib import admin
from django.urls import path, include
from myapp.views import GoogleLogin
from dj_rest_auth.registration.views import SocialAccountListView, SocialAccountDisconnectView
from django.conf import settings
from django.conf.urls.static import static



urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('myapp.urls')),
    path('api/auth/', include('dj_rest_auth.urls')),  
    path('api/auth/registration/', include('dj_rest_auth.registration.urls')),
    path('api/auth/social/', include('allauth.socialaccount.urls')),
    path('dj-rest-auth/google/', GoogleLogin.as_view(), name='google_login'),


]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)