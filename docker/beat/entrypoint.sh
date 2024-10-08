#!/bin/bash

if [ ! "$CELERY_LOGLEVEL" ]; then
  export CELERY_LOGLEVEL='info'
fi

poetry run -C $HOME/ celery -A reNgine beat --loglevel=$CELERY_LOGLEVEL --scheduler django_celery_beat.schedulers:DatabaseScheduler

exec "$@"