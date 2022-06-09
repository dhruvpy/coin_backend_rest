from django.http.response import JsonResponse
from django.shortcuts import render
from rest_framework.generics import GenericAPIView, ListAPIView, CreateAPIView, UpdateAPIView, RetrieveAPIView
from rest_framework.response import Response
from rest_framework import status
from vee.serializers import *
from vee.models import User, UserToken
import jwt, json
import string,random
from django.conf import settings
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate
from django.core.mail import send_mail
from django.contrib.auth.hashers import make_password
# from vee.pagination import CustomPagination
from django.db.models import Q
from django.template.loader import render_to_string
from django.http import HttpResponseRedirect
from rest_framework import generics

# Create your views here.


class IndexAPIView(ListAPIView):
    # permission_classes = [AllowAny]
    def get(self, request, *args, **kwargs):
        return Response(data={'status':status.HTTP_202_ACCEPTED, 'Message':'Hello world!'},status=status.HTTP_202_ACCEPTED)


class RegisterAPIView(CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = UserRegisterSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():
            return Response(data={'status': status.HTTP_400_BAD_REQUEST, 'error':True, 'message':serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']


        if serializer.is_valid():
            if User.objects.filter(email=email).exists():
                return Response(data={'status': status.HTTP_400_BAD_REQUEST,
                                    'error': True,
                                    "message":"Email already exist",
                                    },status=status.HTTP_400_BAD_REQUEST)
            else:
                serializer.save()
                user = User.objects.get(email=email)
                User.objects.filter(email=email).update(created_by=user.id,updated_by=user.id)

                # letters = string.ascii_letters
                # random_string = ''.join(random.choice(letters) for i in range(15))
                payload = {'id': user.id, 'email': user.email}
                encoded_token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
                # existing = 
                
                UserToken.objects.create(user=user, token=encoded_token)
                # try:
                #     button_path = request.build_absolute_uri('/api/users/verify_mail/'+ encoded_token)
                #     img_path = request.build_absolute_uri(settings.STATIC_URL + 'image/logo.png')
                #     html_message = render_to_string('account_activation_email.html', {
                #         'button_path':button_path,
                #         'img_path':img_path,
                #     })
                #     # from_mail = settings.EMAIL_HOST_USER
                #     from_mail = settings.SENDER_EMAIL
                #     subject = 'Email Verification'
                #     message = ''
                #     to = [email]
                #     send_mail(subject, message, from_mail , to, html_message=html_message)
                # except:
                #     return Response(data={'status': status.HTTP_400_BAD_REQUEST,
                #                         'error': True,
                #                         "message":"Invalid email",
                #                         },status=status.HTTP_400_BAD_REQUEST)
                return Response(data={'status': status.HTTP_201_CREATED,
                                        'error': False,
                                        "message":"User Register Successfully",
                                        "result":{'id': user.id,
                                                    'first_name':user.first_name, 
                                                    'last_name':user.last_name, 
                                                    'email':user.email,
                                                    'token':encoded_token}
                                        },status=status.HTTP_201_CREATED)


# def verify_mail(request, token):
#     # url = 'http://3.129.88.232/auth/login'
#     # path = request.get_host()
#     # path1 = path.split(':')
#     # url = 'http://'+path1[0]+'/auth/login'
#     url = settings.AUTH_LOGIN_URL+'auth/login'
#     usertoken = UserToken.objects.filter(token=token).first()
#     print(usertoken)
#     if usertoken:
#         user = User.objects.get(user=usertoken)
#         if user:
#             user.verified_status = True
#             user.save()
#         return HttpResponseRedirect(url)
#     return HttpResponseRedirect(url)


class LoginAPIView(GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = UserLoginSerializer


    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.POST)

        if not serializer.is_valid():
            return Response(data={'status': status.HTTP_400_BAD_REQUEST, 'error':True, 'message':serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        # print(serializer['avatar'])
        # avatar = serializer.validated_data['avatar']
        user1 = User.objects.get(email=email)
        print(user1.email,'-------------------------')
       
        if user1 is not None:
            # if user1.verified_status == True:
            try:
                user = authenticate(request, email=user1.email, password=password)
                if user is None:
                    return Response(data={"status": status.HTTP_400_BAD_REQUEST, 'error':True, 'message': "Invalid email or password"},status=status.HTTP_400_BAD_REQUEST)
            except:
                return Response(data={"status": status.HTTP_400_BAD_REQUEST, 'error':True, 'message': "Invalid email or password"},status=status.HTTP_400_BAD_REQUEST)
            # else:
            #     return Response(data={"status": status.HTTP_400_BAD_REQUEST, 'error':True, 'message': "Email is not verified"},status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(data={"status": status.HTTP_400_BAD_REQUEST, 'error':True, 'message': "Invalid email or password"},status=status.HTTP_400_BAD_REQUEST)

        if user:
            payload = {
                'id': user.id,
                'email': user.email,
            }
            print(payload)
            jwt_token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
            UserToken.objects.create(user=user, token=jwt_token)
            return Response(data={"status": status.HTTP_200_OK,
                                "error": False,
                                "message": "User Login Successfully.",
                                 "result": {'id': user.id,
                                            'first_name':user.first_name, 
                                            'last_name':user.last_name, 
                                            'token': jwt_token,
                                            'is_admin':user.is_admin}},
                                status=status.HTTP_200_OK)



class WalletConnectView(GenericAPIView):
    # permission_classes = [AllowAny]
    serializer_class = UserConnectSerializer



    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.POST)
        if not serializer.is_valid():
            return Response(data={'status': status.HTTP_400_BAD_REQUEST, 'error':True, 'message':serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
       
        user_id = serializer.validated_data['user']
        address = serializer.validated_data['address']
        wallet = serializer.validated_data['wallet']

        user = User.objects.get(id=user_id)
        if not UserWallet.objects.filter(address=address).exists():
            UserWallet.objects.create(user=user,address=address,wallet=wallet)
            user.address = address
            user.save()
        else:
            wallet = UserWallet.objects.get(user=user)
            wallet.adderss = address
            wallet.save()
            user.address = address
            user.save()
        return Response(data={"status": status.HTTP_200_OK,
                            "error": False,
                            "message": "Connected Successfully.",
                                "result": {'address':address,
                                            'user' : user.first_name}},
                            status=status.HTTP_200_OK)



class CreateTxView(GenericAPIView):
    # permission_classes = [AllowAny]
    serializer_class = TxSerializer



    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.POST)
        if not serializer.is_valid():
            return Response(data={'status': status.HTTP_400_BAD_REQUEST, 'error':True, 'message':serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
       
        serializer.save()
        return Response(data={"status": status.HTTP_200_OK,
                            "error": False,
                            "message": "Transaction added Successfully.",
                                "result": {}},
                            status=status.HTTP_200_OK)


class TokenRequestTxView(GenericAPIView):
    # permission_classes = [AllowAny]
    serializer_class = TokenRequestSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.POST)
        if not serializer.is_valid():
            return Response(data={'status': status.HTTP_400_BAD_REQUEST, 'error':True, 'message':serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
       
        serializer.save()
        return Response(data={"status": status.HTTP_200_OK,
                            "error": False,
                            "message": "Request submited Successfully.",
                                "result": {'address':serializer.validated_data['address'],
                                            'amount' : serializer.validated_data['amount'],
                                            'status' : serializer.validated_data['approved'],}},
                            status=status.HTTP_200_OK)


class ApproveTokenRequestTxView(GenericAPIView):
    # permission_classes = [AllowAny]
    serializer_class = TokenRequestSerializer

    def post(self, request, *args, **kwargs):
        request_id = self.kwargs['pk']
        token_request = BuyApplication.objects.get(id=request_id)
        token_request.approved=True
        token_request.save()
        print(token_request.approved)
        # serializer = self.get_serializer(data=request.POST)
        # if not serializer.is_valid():
        #     return Response(data={'status': status.HTTP_400_BAD_REQUEST, 'error':True, 'message':serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        # serializer.save()
        return Response(data={"status": status.HTTP_200_OK,
                            "error": False,
                            "message": "Request approved Successfully.",
                                "result": {'address':token_request.address,
                                            'amount' : token_request.amount,
                                            'status' : token_request.approved,}},
                            status=status.HTTP_200_OK)



# class TokenRequestAPIView(ListAPIView):
#     # permission_classes = [AllowAny]
#     serializer_class = TokenRequestSerializer

#     def get(self, request, *args, **kwargs):


#         return Response(data={"status": status.HTTP_200_OK,
#                             "error": False,
#                             "message": "Request approved Successfully.",
#                                 "result": {'address':token_request.address,
#                                             'amount' : token_request.amount,
#                                             'status' : token_request.approved,}},
#                             status=status.HTTP_200_OK)


class TokenRequestList(GenericAPIView):
    # queryset = BuyApplication.objects.all()
    serializer_class = TokenRequestSerializer

    def get(self, request):
        result = []
        app =  BuyApplication.objects.all()
        for i in app:
            result.append({
                "id": i.id,
                "address": i.address,
                "amount": i.amount,
                "approved": i.approved,
                "user": str(i.user)
            })
        return Response(data={"status": status.HTTP_200_OK,
                            "error": False,
                            "message": "working",
                                "result": {"data":result}},
                            status=status.HTTP_200_OK)


class UserList(GenericAPIView):
    # queryset = BuyApplication.objects.all()
    serializer_class = UserSerializer

    def get(self, request):
        result = []
        user =  User.objects.all()
        for i in user:
            result.append({
                "address": i.first_name,
                "amount": i.last_name,
                "approved": i.email,
                "user": str(i.address)
            })
        return Response(data={"status": status.HTTP_200_OK,
                            "error": False,
                            "message": "working",
                                "result": {"data":result}},
                            status=status.HTTP_200_OK)


class ForgotPasswordAPIView(GenericAPIView):
    # permission_classes = [AllowAny]
    serializer_class = ForgotPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():
            return Response(data={'status': status.HTTP_400_BAD_REQUEST, 'error':True, 'message':serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']

        if not User.objects.filter(email=email).exists():
            return Response(data={"status": status.HTTP_400_BAD_REQUEST, 'error':True, 'message': "email is not registered", }, status=status.HTTP_400_BAD_REQUEST)
        
        if User.objects.filter(email=email).exists:
            user = User.objects.get(email=email)
            random_num = random.randint(100000,999999)
            otp = random_num
            subject = "OTP for forgot password"
            message = " "
            to_list = [user.email]
            from_mail = settings.SENDER_EMAIL
            # from_mail = 'admin@squiznow.com'
            html_message = render_to_string('forgot_password_otp.html', {
                    'random_num':random_num,
                })
            rest = send_mail(subject, message, from_mail , to_list, html_message=html_message)
            EmailOTP.objects.create(user=user, otp=otp)
            return Response(data={"status": status.HTTP_200_OK, "error": False, 'message': 'We have sent you a otp to reset your password'}, status=status.HTTP_200_OK)


class OTPCheckAPIView(GenericAPIView):
    # permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        otp = request.data.get('otp')
        email = request.data.get('email')

        if otp is None:
            return Response(data={"status": status.HTTP_400_BAD_REQUEST, 'error':True, 'message': 'please enter otp'}, status=status.HTTP_400_BAD_REQUEST)

        if email is None:
            return Response(data={"status": status.HTTP_400_BAD_REQUEST, 'error':True, 'message': 'please enter email address'}, status=status.HTTP_400_BAD_REQUEST)

        emailotp = EmailOTP.objects.filter(user__email=email).last()
        if emailotp:
            if emailotp.user.email == email and emailotp.otp == int(otp):
                emailotp.otp_check = True
                emailotp.save()
                return Response(data={'status':status.HTTP_200_OK, 'error':False, 'message': 'otp check please set new password'}, status=status.HTTP_200_OK)
            else:
                return Response(data={"status": status.HTTP_400_BAD_REQUEST, 'error':True, 'message': 'otp is expire or not valid this mail'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(data={"status": status.HTTP_400_BAD_REQUEST, 'error':True, 'message': 'please enter valid email or otp'}, status=status.HTTP_400_BAD_REQUEST)


class SetNewPasswordAPIView(GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = SetNewPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():
            return Response(data={'status': status.HTTP_400_BAD_REQUEST, 'error':True, 'message':serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        confirm_password = serializer.validated_data['confirm_password']
        

        if serializer.is_valid():
            user_obj = User.objects.filter(email=email).last()
            emailotp_obj = EmailOTP.objects.filter(user=user_obj).last()
            if user_obj:
                try:
                    if emailotp_obj.otp_check == True:
                        user_obj.password = make_password(password)
                        user_obj.confirm_password = confirm_password
                        user_obj.save()
                        emailotp_obj.delete()
                        EmailOTP.objects.filter(user=user_obj).delete()
                        return Response(data={'status':status.HTTP_200_OK, 'error':False, 'message': 'Successfully set new password'}, status=status.HTTP_200_OK)
                    else:
                        return Response(data={"status": status.HTTP_400_BAD_REQUEST, 'error':True, 'message': 'please check validate otp to this mail'}, status=status.HTTP_400_BAD_REQUEST)
                except:
                    return Response(data={"status": status.HTTP_400_BAD_REQUEST, 'error':True, 'message': 'please check validate otp to this mail'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(data={"status": status.HTTP_400_BAD_REQUEST, 'error':True, 'message': 'please enter valid email'}, status=status.HTTP_400_BAD_REQUEST)
