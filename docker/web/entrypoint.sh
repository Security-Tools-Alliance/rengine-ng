#!/bin/bash

print_msg() {
  printf "\r\n"
  printf "========================================\r\n"
  printf "$1\r\n"
  printf "========================================\r\n\r\n"
}

print_msg "Generate Django migrations files"
poetry run -C $HOME/ python3 manage.py makemigrations

print_msg "Migrate database"
poetry run -C $HOME/ python3 manage.py migrate

print_msg "Collect static files"
poetry run -C $HOME/ python3 manage.py collectstatic --noinput

print_msg "Starting ASGI server with Uvicorn"
poetry run -C $HOME/ uvicorn reNgine.asgi:application \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 4 \
    --log-level info \
    --ws-ping-interval 20 \
    --ws-ping-timeout 30 \
    --timeout-keep-alive 65

exec "$@"