from django.contrib import admin
from django.urls import path, include
# from dj_rest_auth.registration.views import SocialAccountListView, SocialAccountDisconnectView
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import TemplateView
from django.http import JsonResponse


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('myapp.urls')),
    path('payments/', include('subscriptions.urls')),
    path('notifications/', include('notification_chat.urls')),

    path('', lambda request: JsonResponse({'message': 'Welcome to the API!'})),

    # path('api/auth/', include('dj_rest_auth.urls')),  
    # path('api/auth/registration/', include('dj_rest_auth.registration.urls')),
    # path('api/auth/social/', include('allauth.socialaccount.urls')),

]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)