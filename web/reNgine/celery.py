from __future__ import absolute_import
import os
import django
from celery import Celery
from celery.signals import setup_logging

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'reNgine.settings')
django.setup()

# Celery app
app = Celery('reNgine')
app.config_from_object('django.conf:settings', namespace='CELERY')

# Default configuration for all tasks
app.conf.update(
    task_track_started=True,
    task_default_queue='orchestrator_queue',
    task_acks_late=True,
    worker_prefetch_multiplier=1,
)

app.autodiscover_tasks(['reNgine.tasks'])

@setup_logging.connect()
def config_loggers(*args, **kwargs):
    from logging.config import dictConfig
    dictConfig(app.conf['LOGGING'])

