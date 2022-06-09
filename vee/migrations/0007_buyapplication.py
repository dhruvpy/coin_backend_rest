# Generated by Django 4.0.4 on 2022-05-26 08:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vee', '0006_usertransaction'),
    ]

    operations = [
        migrations.CreateModel(
            name='BuyApplication',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('address', models.CharField(max_length=500, null=True)),
                ('amount', models.CharField(max_length=500, null=True)),
                ('approved', models.BooleanField(default=0)),
            ],
        ),
    ]
