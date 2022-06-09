# Generated by Django 4.0.4 on 2022-05-31 07:05

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('vee', '0009_user_is_admin'),
    ]

    operations = [
        migrations.AddField(
            model_name='buyapplication',
            name='user',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, related_name='tx_user', to=settings.AUTH_USER_MODEL),
            preserve_default=False,
        ),
    ]