from urllib import request
from rest_framework import serializers
# from vee.models import User, UserWallet, UserTransaction, BuyApplication
from vee.models import *
from django.contrib.auth.hashers import make_password
from rest_framework.response import Response


class UserSerializer(serializers.ModelSerializer):
    email = serializers.CharField(required=True)
    # password = serializers.CharField()

    class Meta:
        model = User
        fields = ('first_name','last_name','email','address')



class UserRegisterSerializer(serializers.ModelSerializer):
    email = serializers.CharField(required=True)
    password = serializers.CharField()

    class Meta:
        model = User
        fields = ('first_name','last_name','email','password')

    # def validate_email(self, email):
    #     existing = User.objects.filter(email=email).first()
    #     if existing:
    #         raise serializers.ValidationError("Email already exist")
    #     return email

    

    # def validate(self, data):
    #     if not data.get('password'):
    #         raise serializers.ValidationError("Please enter a password")
    #     return data

    def create(self, validate_data):
        password = validate_data.pop('password', None)
        instance = self.Meta.model(**validate_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.CharField(required=True)
    password = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ('email','password')

class UserConnectSerializer(serializers.ModelSerializer):
    user = serializers.CharField(required=True)
    address = serializers.CharField(required=True)
    wallet = serializers.CharField(required=True)
    class Meta:
        model = UserWallet
        fields = ('user','address','wallet')


class TxSerializer(serializers.ModelSerializer):
    address = serializers.CharField(required=True)
    txn = serializers.CharField(required=True)
    method = serializers.CharField(required=True)
    time = serializers.CharField(required=True)
    from_ac = serializers.CharField(required=True)
    to_ac = serializers.CharField(required=True)
    vee_amount = serializers.CharField(required=True)
    class Meta:
        model = UserTransaction
        fields = '__all__'



class UserByAddress(serializers.ModelSerializer):
    # user = models.ForeignKey(User, related_name="tx_user", on_delete=models.CASCADE)
    first_name = models.CharField(null=True, max_length=500)
    last_name = models.CharField(null=True, max_length=500)

    class Meta:
        model = User
        fields = ('first_name','last_name')


class ForgotPasswordSerializer(serializers.ModelSerializer):
    email = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ('email',)

class TokenRequestSerializer(serializers.ModelSerializer):
    # address = serializers.CharField(required=True)
    # amount = serializers.CharField(required=True)
    # approved = serializers.BooleanField(required=False) 
    # user = 
    # field_fk = UserByAddress()
    class Meta:
        model = BuyApplication
        fields = '__all__'

class SetNewPasswordSerializer(serializers.ModelSerializer):
    email = serializers.CharField(required=True)
    password = serializers.CharField()
    confirm_password = serializers.CharField()

    class Meta:
        model = User
        fields = ('email','password', 'confirm_password')

    def validate(self, data):
        if not data.get('password') or not data.get('confirm_password'):
            raise serializers.ValidationError("Please enter a password and confirm it.")
        if data.get('password') != data.get('confirm_password'):
            raise serializers.ValidationError("Those passwords don't match.")
        return data
