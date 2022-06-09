from django.urls import path
from vee.views import *
from rest_framework import generics

# from django.views.decorators.csrf import csrf_exempt

urlpatterns = [
    path('index', IndexAPIView.as_view(), name='index'),
    path('register', RegisterAPIView.as_view(), name='register'),
    path('login', LoginAPIView.as_view(), name='login'),
    path('connect', WalletConnectView.as_view(), name='connect'),
    path('transaction', CreateTxView.as_view(), name='transaction'),
    path('tokenrequest', TokenRequestTxView.as_view(), name='tokenrequest'),
    path('approvetokenrequest/<int:pk>', ApproveTokenRequestTxView.as_view(), name='approvetokenrequest'),
    path('tokenrequestlist', TokenRequestList.as_view(), name='tokenrequestlist'),
    path('userlist', UserList.as_view(), name='userlist'),

    path('forgotpassword', ForgotPasswordAPIView.as_view(), name='forgotpassword'),
    path('otpcheck', OTPCheckAPIView.as_view(), name='otpcheck'),
    path('setnewpassword', SetNewPasswordAPIView.as_view(), name='setnewpassword'),

    # path('tokenrequestlist', generics.ListCreateAPIView.as_view(queryset=BuyApplication.objects.all(), serializer_class=TokenRequestSerializer), name='tokenrequestlist'),
    # path('userlist', generics.ListCreateAPIView.as_view(queryset=User.objects.all(), serializer_class=UserSerializer), name='userlist'),
]