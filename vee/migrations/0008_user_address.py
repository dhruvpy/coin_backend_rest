# Generated by Django 4.0.4 on 2022-05-31 05:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vee', '0007_buyapplication'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='address',
            field=models.CharField(max_length=500, null=True),
        ),
    ]
