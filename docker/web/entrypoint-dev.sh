#!/bin/bash

if [ "$UI_DEBUG" == "1" ]; then
    # Django debug toolbar
    pip install django-debug-toolbar==4.3.0
    poetry run -C $HOME/ python3 manage.py collectstatic --noinput
fi

# Check if remote debugging is enabled and set concurrency to 1 for easier debug
if [ "$UI_REMOTE_DEBUG" == "1" ]; then
    # Live debug
    pip install debugpy

    # To debug opened port with netstat
    poetry run -C $HOME/ apt install net-tools -y
fi

poetry run -C $HOME/ python3 manage.py runserver 0.0.0.0:8000

exec "$@"