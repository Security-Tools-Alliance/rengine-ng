#!/bin/bash

# Collect static files for development
poetry run -C $HOME/ python3 manage.py collectstatic --noinput

# Run development server
poetry run -C $HOME/ python3 manage.py runserver 0.0.0.0:8000

exec "$@"