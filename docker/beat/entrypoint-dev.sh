#!/bin/bash

if [ "$CELERY_DEBUG" == "1" ]; then
    # Django debug toolbar
    pip install django-debug-toolbar==4.3.0
    python3 manage.py collectstatic --noinput
fi

# Check if remote debugging is enabled and set concurrency to 1 for easier debug
if [ "$CELERY_REMOTE_DEBUG" == "1" ]; then
    # Live debug
    pip install debugpy

    # To debug opened port with netstat
    apt install net-tools -y
fi

./beat-entrypoint.sh