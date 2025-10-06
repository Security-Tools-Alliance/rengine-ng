import os

from celery import Celery
from celery.signals import setup_logging
import django


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "reNgine.settings")
django.setup()

# Celery app
app = Celery("reNgine")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()


@setup_logging.connect()
def config_loggers(*args, **kwargs):
    from logging.config import dictConfig

    dictConfig(app.conf["LOGGING"])
