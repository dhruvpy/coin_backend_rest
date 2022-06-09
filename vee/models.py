from pyexpat import model
from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.
class User(AbstractUser):
    username = None
    first_name = models.CharField(null=True, blank=True, max_length=128)
    last_name = models.CharField(null=True, blank=True, max_length=128)
    email = models.EmailField(null=True, blank=True, max_length=128, unique=True)
    password = models.CharField(max_length=128, null=True, blank=True)
    address = models.CharField(null=True, max_length=500)
    is_admin = models.BooleanField(default=0)
    created_at = models.DateTimeField(null=True, auto_now_add=True)
    updated_at = models.DateTimeField(null=True, auto_now=True)
    created_by = models.IntegerField(null=True, blank=True)
    updated_by = models.IntegerField(null=True, blank=True)


    USERNAME_FIELD= 'email'
    REQUIRED_FIELDS= []

    def __str__(self):
        return str(self.first_name + ' ' + self.last_name)

class UserToken(models.Model):
    user = models.ForeignKey(User, related_name="user", on_delete=models.CASCADE)
    token = models.CharField(null=True, max_length=500)
    created_at = models.DateTimeField(null=True, auto_now_add=True)
    updated_at = models.DateTimeField(null=True, auto_now=True)

    def __str__(self):
        return str(self.user)


class UserWallet(models.Model):
    user = models.ForeignKey(User, related_name="wallet_user", on_delete=models.CASCADE)
    address = models.CharField(null=True, max_length=500)
    wallet = models.CharField(null=True, max_length=500)
    created_at = models.DateTimeField(null=True, auto_now_add=True)
    updated_at = models.DateTimeField(null=True, auto_now=True)

    def __str__(self):
        return str(self.user)

class UserTransaction(models.Model):
    # user = models.ForeignKey(User, related_name="tx_user", on_delete=models.CASCADE)
    address = models.CharField(null=True, max_length=500)
    txn = models.CharField(null=True, max_length=500)
    method = models.CharField(null=True, max_length=500)
    time = models.CharField(null=True, max_length=500)
    from_ac = models.CharField(null=True, max_length=500)
    to_ac = models.CharField(null=True, max_length=500)
    vee_amount = models.IntegerField(null=True,default=0)

    def __str__(self):
        return str(self.method)



class EmailOTP(models.Model):
    otp = models.IntegerField(null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    otp_check = models.BooleanField(default=False)
    created_at = models.DateTimeField(null=True, auto_now_add=True)
    updated_at = models.DateTimeField(null=True, auto_now=True)


class BuyApplication(models.Model):
    user = models.ForeignKey(User, related_name="tx_user", on_delete=models.CASCADE)
    address = models.CharField(null=True, max_length=500)
    amount = models.CharField(null=True, max_length=500)
    approved = models.BooleanField(default=0)

    def __str__(self):
        return str(self.user)