#!/bin/bash

RENGINE_FOLDER="/home/$USERNAME/rengine"

# Collect static files
poetry run -C $RENGINE_FOLDER python3 manage.py collectstatic --noinput

# Run production server
poetry run -C $RENGINE_FOLDER gunicorn reNgine.wsgi:application -w 8 --bind 0.0.0.0:8000 --limit-request-line 0

exec "$@"
