#!/bin/bash

print_msg() {
  printf "\r\n"
  printf "========================================\r\n"
  printf "$1\r\n"
  printf "========================================\r\n\r\n"
}

RENGINE_FOLDER="/home/$USERNAME/rengine"
USER_HOME="${HOME:-/home/$USERNAME}"

# Ensure SSH key exists for worker SSH auth (persisted in rengine_ssh_keys volume when used)
SSH_DIR="${USER_HOME}/.ssh"
SSH_KEY="${SSH_DIR}/id_ed25519"
if [ ! -f "$SSH_KEY" ] && command -v ssh-keygen >/dev/null 2>&1; then
  mkdir -p "$SSH_DIR"
  chmod 700 "$SSH_DIR" 2>/dev/null || true
  ssh-keygen -t ed25519 -f "$SSH_KEY" -N "" -q
  chmod 600 "$SSH_KEY" "${SSH_KEY}.pub" 2>/dev/null || true
fi
[ -d "$SSH_DIR" ] && chmod 700 "$SSH_DIR" 2>/dev/null || true
[ -f "$SSH_KEY" ] && chmod 600 "$SSH_KEY" 2>/dev/null || true
[ -f "${SSH_KEY}.pub" ] && chmod 600 "${SSH_KEY}.pub" 2>/dev/null || true

# Create wrapper script for run_scheduled_scans (used by scheduled-scans loop)
RUN_SCHEDULED_SCRIPT="${USER_HOME}/run_scheduled_scans.sh"
if [ ! -x "$RUN_SCHEDULED_SCRIPT" ]; then
  printf '#!/bin/bash\ncd "%s" && poetry run python3 manage.py run_scheduled_scans\n' "$RENGINE_FOLDER" > "$RUN_SCHEDULED_SCRIPT"
  chmod +x "$RUN_SCHEDULED_SCRIPT"
fi

# Run scheduled scans every minute (no cron daemon, no root required)
( while true; do "$RUN_SCHEDULED_SCRIPT" 2>/dev/null || true; sleep 60; done ) &

print_msg "Installing dev dependencies"
poetry install --only dev --no-root

print_msg "Generate Django migrations files"
poetry run -C $RENGINE_FOLDER python3 manage.py makemigrations

print_msg "Migrate database"
poetry run -C $RENGINE_FOLDER python3 manage.py migrate

print_msg "Ensure scheduled scans (if any schedule exists)"
poetry run -C $RENGINE_FOLDER python3 manage.py ensure_scheduled_scans_cron || true

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
