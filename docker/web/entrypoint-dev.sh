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

# Collect static files for development
print_msg "Collect static files"
poetry run -C $HOME/ python3 manage.py collectstatic --noinput

# Run development server
print_msg "Launching Django development Web server"
poetry run -C $HOME/ python3 manage.py runserver 0.0.0.0:8000

exec "$@"
