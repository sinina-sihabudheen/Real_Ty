# Generated by Django 5.0.6 on 2024-07-01 15:01

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0008_alter_seller_subscription_end_date'),
    ]

    operations = [
        migrations.AlterField(
            model_name='seller',
            name='subscription_end_date',
            field=models.DateTimeField(default=datetime.datetime(2024, 7, 31, 15, 1, 8, 126689, tzinfo=datetime.timezone.utc)),
        ),
    ]
