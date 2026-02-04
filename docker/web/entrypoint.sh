#!/bin/bash

print_msg() {
  printf "\r\n"
  printf "========================================\r\n"
  printf "$1\r\n"
  printf "========================================\r\n\r\n"
}

USER_HOME="${HOME:-/home/rengine}"
RENGINE_FOLDER="${USER_HOME}/rengine"

# Create wrapper script for run_scheduled_scans (used by cron)
RUN_SCHEDULED_SCRIPT="${USER_HOME}/run_scheduled_scans.sh"
if [ ! -x "$RUN_SCHEDULED_SCRIPT" ]; then
  printf '#!/bin/bash\ncd "%s" && poetry run python3 manage.py run_scheduled_scans\n' "$RENGINE_FOLDER" > "$RUN_SCHEDULED_SCRIPT"
  chmod +x "$RUN_SCHEDULED_SCRIPT"
fi

# Start cron so scheduled scans can run
if command -v cron >/dev/null 2>&1; then
  cron
fi

print_msg "Generate Django migrations files"
poetry run -C $RENGINE_FOLDER python3 manage.py makemigrations

print_msg "Migrate database"
poetry run -C $RENGINE_FOLDER python3 manage.py migrate

# Ensure run_scheduled_scans is in crontab if any schedule exists
print_msg "Ensure scheduled scans cron (if any schedule exists)"
poetry run -C $RENGINE_FOLDER python3 manage.py ensure_scheduled_scans_cron || true

print_msg "Collect static files"
poetry run -C $RENGINE_FOLDER python3 manage.py collectstatic --noinput

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
