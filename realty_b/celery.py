from __future__ import absolute_import, unicode_literals
import os
from celery import Celery

from celery.schedules import crontab
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'realty_b.settings')

celery_app = Celery('realty_b')
celery_app.config_from_object('django.conf:settings', namespace='CELERY')
celery_app.autodiscover_tasks()

# Periodic task to check for subscriptions expiring in 5 days
celery_app.conf.beat_schedule = {
    'send-subscription-end-notification-daily': {
        'task': 'notification_chat.tasks.send_subscription_end_notification',
        'schedule': crontab(minute=0, hour=0),  # Runs daily at midnight
    },
}


