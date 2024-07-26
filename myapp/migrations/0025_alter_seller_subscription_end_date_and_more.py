# Generated by Django 5.0.6 on 2024-07-25 14:29

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0024_alter_seller_subscription_end_date_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='seller',
            name='subscription_end_date',
            field=models.DateTimeField(default=datetime.datetime(2024, 8, 24, 14, 29, 53, 453276, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='user',
            name='social_provider',
            field=models.CharField(blank=True, default=(('email', 'email'), ('google', 'google'), ('facebook', 'facebook')), max_length=50, null=True),
        ),
    ]
