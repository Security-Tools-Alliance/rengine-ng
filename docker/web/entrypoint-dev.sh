#!/bin/bash

if [ "$UI_DEBUG" == "1" ]; then
    # Collect static files for development
    poetry run -C $HOME/ python3 manage.py collectstatic --noinput
fi

# Run development server
poetry run -C $HOME/ python3 manage.py runserver 0.0.0.0:8000

exec "$@"