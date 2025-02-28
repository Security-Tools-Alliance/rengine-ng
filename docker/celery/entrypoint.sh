#!/bin/bash

print_msg() {
  printf "\r\n"
  printf "========================================\r\n"
  printf "$1\r\n"
  printf "========================================\r\n\r\n"
}

RENGINE_FOLDER="/home/$USERNAME/rengine"
MAX_CONCURRENCY=${MAX_CONCURRENCY:-20}
MIN_CONCURRENCY=${MIN_CONCURRENCY:-5}
CELERY_LOGLEVEL=${CELERY_LOGLEVEL:-info}

print_msg "Generate Django migrations files"
poetry run -C $RENGINE_FOLDER python3 manage.py makemigrations
print_msg "Migrate database"
poetry run -C $RENGINE_FOLDER python3 manage.py migrate
print_msg "Collect static files"
poetry run -C $RENGINE_FOLDER python3 manage.py collectstatic --no-input --clear

# Load default engines, keywords, and external tools
print_msg "Load default engines"
poetry run -C $RENGINE_FOLDER python3 manage.py loaddata fixtures/default_scan_engines.yaml --app scanEngine.EngineType
print_msg "Load default keywords"
poetry run -C $RENGINE_FOLDER python3 manage.py loaddata fixtures/default_keywords.yaml --app scanEngine.InterestingLookupModel
print_msg "Load default external tools"
poetry run -C $RENGINE_FOLDER python3 manage.py loaddata fixtures/external_tools.yaml --app scanEngine.InstalledExternalTool

worker_command() {
    local queue=$1
    local worker_name=$2
    
    if [ "$CELERY_DEBUG" = "1" ]; then
        echo "watchmedo auto-restart --recursive --pattern=\"*.py\" --directory=\"$RENGINE_FOLDER\" -- \
            poetry run -C $RENGINE_FOLDER celery -A reNgine worker \
            --pool=solo \
            --loglevel=$CELERY_LOGLEVEL \
            -Q $queue -n $worker_name"
    else
        echo "poetry run -C $RENGINE_FOLDER celery -A reNgine worker \
            --pool=gevent \
            --loglevel=$CELERY_LOGLEVEL \
            --autoscale=$MAX_CONCURRENCY,$MIN_CONCURRENCY \
            -Q $queue -n $worker_name"
    fi
}

queues=(
    "orchestrator_queue:orchestrator_worker"
    "io_queue:io_worker"
    "run_command_queue:run_command_worker"
    "cpu_queue:cpu_worker"
    "report_queue:report_worker"
    "send_notif_queue:send_notif_worker"
)

commands=""
for queue in "${queues[@]}"; do
    IFS=':' read -r queue worker_name <<< "$queue"
    commands+="$(worker_command "$queue" "$worker_name") &"$'\n'
done

eval "$commands"

wait

exec "$@"