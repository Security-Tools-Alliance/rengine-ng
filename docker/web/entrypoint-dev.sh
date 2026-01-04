#!/bin/bash

print_msg() {
  printf "\r\n"
  printf "========================================\r\n"
  printf "$1\r\n"
  printf "========================================\r\n\r\n"
}

RENGINE_FOLDER="/home/$USERNAME/rengine"

# =========================================================================
# Temporary for debug: Install Secator from local repo
# =========================================================================
if [ -d "/opt/secator" ] && [ -f "/opt/secator/pyproject.toml" ]; then
    echo "🔧 Temporary for debug: Installing Secator from local repo (/opt/secator)..." >&2
        
    # Step 2: Install Secator from local repo with Poetry in editable mode
    echo "   → Step 1: Modifying pyproject.toml to use local Secator..." >&2
    cd "$HOME" || exit 1

    # Replace secator dependency with path-based editable dependency
    sed -i 's|secator = {version = .*}|secator = {path = "/opt/secator", develop = true, extras = ["redis"]}|' pyproject.toml

    # Step 2 update Secator
    echo "   → Step 2: Updating Secator..." >&2
    poetry update secator 2>&1 | tee /tmp/poetry_lock.log || {
        echo "   ❌ Failed to update Secator" >&2
        exit 1
    }

    echo "   ✅ Secator from local repo installed successfully" >&2
    cd "$RENGINE_FOLDER" || exit 1
fi
# =========================================================================

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
# Find all static directories in Django apps and watch them
find "$RENGINE_FOLDER" -type d -name "static" | while read -r static_dir; do
    echo "Watching static directory: $static_dir"
    watchmedo shell-command \
        --patterns="*.js;*.css;*.scss;*.sass;*.less" \
        --command="echo 'Collecting static files...' && poetry run -C $RENGINE_FOLDER python3 manage.py collectstatic --noinput" \
        --recursive \
        --wait \
        "$static_dir" &
done

# Start web server with watchmedo for Python files
watchmedo auto-restart \
    --recursive \
    --pattern="*.py" \
    --directory="$RENGINE_FOLDER" \
    -- \
    poetry run -C $RENGINE_FOLDER daphne -b 0.0.0.0 -p 8000 --verbosity 2 reNgine.asgi:application

exec "$@"
