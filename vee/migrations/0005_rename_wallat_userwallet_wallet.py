# Generated by Django 4.0.4 on 2022-05-23 08:47

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('vee', '0004_userwallet'),
    ]

    operations = [
        migrations.RenameField(
            model_name='userwallet',
            old_name='wallat',
            new_name='wallet',
        ),
    ]
