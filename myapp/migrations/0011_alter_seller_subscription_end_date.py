# Generated by Django 5.0.6 on 2024-07-03 14:12

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0010_alter_seller_subscription_end_date'),
    ]

    operations = [
        migrations.AlterField(
            model_name='seller',
            name='subscription_end_date',
            field=models.DateTimeField(default=datetime.datetime(2024, 8, 2, 14, 12, 55, 951038, tzinfo=datetime.timezone.utc)),
        ),
    ]
