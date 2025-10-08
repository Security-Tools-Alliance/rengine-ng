#!/bin/bash

print_msg() {
  printf "\r\n"
  printf "========================================\r\n"
  printf "$1\r\n"
  printf "========================================\r\n\r\n"
}

RENGINE_FOLDER="/home/$USERNAME/rengine"

print_msg "Installing dev dependencies"
poetry install --only dev --no-root

print_msg "Generate Django migrations files"
poetry run -C $RENGINE_FOLDER python3 manage.py makemigrations

print_msg "Migrate database"
poetry run -C $RENGINE_FOLDER python3 manage.py migrate

print_msg "Collect static files"
poetry run -C $RENGINE_FOLDER python3 manage.py collectstatic --noinput

print_msg "Starting web server with auto-restart enabled"

# Start static files watcher in background
print_msg "Starting static files watcher"
watchmedo shell-command \
    --patterns="*.js;*.css;*.scss;*.sass;*.less" \
    --command="echo 'Collecting static files...' && poetry run -C $RENGINE_FOLDER python3 manage.py collectstatic --noinput" \
    --recursive \
    --wait \
    "$RENGINE_FOLDER/static" &

# Start web server with watchmedo for Python files
watchmedo auto-restart \
    --recursive \
    --pattern="*.py" \
    --directory="$RENGINE_FOLDER" \
    -- \
    poetry run -C $RENGINE_FOLDER daphne -b 0.0.0.0 -p 8000 --verbosity 2 reNgine.asgi:application

exec "$@"
