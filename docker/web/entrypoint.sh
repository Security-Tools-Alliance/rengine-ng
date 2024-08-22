#!/bin/bash

# Collect static files
poetry run -C $HOME/ python3 manage.py collectstatic --noinput

# Run production server
poetry run -C $HOME/ gunicorn reNgine.wsgi:application -w 8 --bind 0.0.0.0:8000 --limit-request-line 0

exec "$@"