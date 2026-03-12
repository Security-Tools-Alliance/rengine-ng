#!/bin/bash

print_msg() {
  printf "\r\n"
  printf "============================================================\r\n"
  printf "$1\r\n"
  printf "============================================================\r\n\r\n"
}

USER_HOME="${HOME:-/home/rengine}"
RENGINE_FOLDER="${USER_HOME}/rengine"

# Ensure SSH key exists for worker SSH auth (persisted in rengine_ssh_keys volume)
SSH_DIR="${USER_HOME}/.ssh"
SSH_KEY="${SSH_DIR}/id_ed25519"
if [ ! -f "$SSH_KEY" ] && command -v ssh-keygen >/dev/null 2>&1; then
  mkdir -p "$SSH_DIR"
  chmod 700 "$SSH_DIR" 2>/dev/null || true
  ssh-keygen -t ed25519 -f "$SSH_KEY" -N "" -q
  chmod 600 "$SSH_KEY" "${SSH_KEY}.pub" 2>/dev/null || true
fi
# Always enforce strict permissions so mounted or existing keys are accepted by SSH
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

# Use direct PostgreSQL (not PgBouncer) for management commands that need it (migrations, cron, API key, load).
run_with_direct_db() {
  POSTGRES_HOST="${POSTGRES_DIRECT_HOST:-db}" POSTGRES_PORT="${POSTGRES_DIRECT_PORT:-5432}" "$@"
}

# Run all setup steps in a single Python process to avoid repeated Django startup time
print_msg "Django setup (migrations, cron, Secator load, collectstatic)"
run_with_direct_db poetry run -C $RENGINE_FOLDER python3 manage.py entrypoint_setup

print_msg "Starting ASGI server with Uvicorn"
poetry run -C $RENGINE_FOLDER uvicorn reNgine.asgi:application \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 4 \
    --log-level info \
    --ws-ping-interval 20 \
    --ws-ping-timeout 30 \
    --timeout-keep-alive 120

exec "$@"
