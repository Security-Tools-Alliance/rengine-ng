#!/bin/bash

if [ ! "$CELERY_LOGLEVEL" ]; then
  export CELERY_LOGLEVEL='info'
fi

RENGINE_FOLDER="/home/$USERNAME/rengine"

poetry run -C $RENGINE_FOLDER celery -A reNgine beat --loglevel=$CELERY_LOGLEVEL --scheduler django_celery_beat.schedulers:DatabaseScheduler

exec "$@"
