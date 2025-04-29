from django.urls import path
from .views import *
urlpatterns = [
    path('users/', CustomUserView.as_view(), name='custom_user'),
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('social-login/', SocialLoginView.as_view(), name='social-login'),
    
    
]
