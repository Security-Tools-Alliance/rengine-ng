#!/bin/bash

print_msg() {
  printf "\r\n"
  printf "========================================\r\n"
  printf "$1\r\n"
  printf "========================================\r\n\r\n"
}

RENGINE_FOLDER="/home/$USERNAME/rengine"
CELERY_LOGLEVEL=${CELERY_LOGLEVEL:-info}

# Configuration by environment
if [ "$CELERY_ENV" = "production" ]; then
    MAX_CONCURRENCY=${MAX_CONCURRENCY:-50}
    MIN_CONCURRENCY=${MIN_CONCURRENCY:-10}
    ORCHESTRATOR_WORKERS=${ORCHESTRATOR_WORKERS:-2}
    IO_WORKERS=${IO_WORKERS:-4}
    CPU_WORKERS=${CPU_WORKERS:-2}
    COMMAND_WORKERS=${COMMAND_WORKERS:-3}
    REPORT_WORKERS=${REPORT_WORKERS:-2}
    NOTIFICATION_WORKERS=${NOTIFICATION_WORKERS:-1}
    POOL_TYPE="gevent"
else
    MAX_CONCURRENCY=${MAX_CONCURRENCY:-20}
    MIN_CONCURRENCY=${MIN_CONCURRENCY:-5}
    ORCHESTRATOR_WORKERS=${ORCHESTRATOR_WORKERS:-1}
    IO_WORKERS=${IO_WORKERS:-2}
    CPU_WORKERS=${CPU_WORKERS:-1}
    COMMAND_WORKERS=${COMMAND_WORKERS:-2}
    REPORT_WORKERS=${REPORT_WORKERS:-1}
    NOTIFICATION_WORKERS=${NOTIFICATION_WORKERS:-1}
    POOL_TYPE="solo"
fi

print_msg "Generate Django migrations files"
poetry run -C $RENGINE_FOLDER python3 manage.py makemigrations
print_msg "Migrate database"
poetry run -C $RENGINE_FOLDER python3 manage.py migrate
print_msg "Collect static files"
poetry run -C $RENGINE_FOLDER python3 manage.py collectstatic --no-input --clear

# Load default engines, keywords, and external tools
print_msg "Load default engines"
poetry run -C $RENGINE_FOLDER python3 manage.py loaddefaultengines
print_msg "Load default keywords"
poetry run -C $RENGINE_FOLDER python3 manage.py loaddata fixtures/default_keywords.yaml --app scanEngine.InterestingLookupModel
print_msg "Load default external tools"
poetry run -C $RENGINE_FOLDER python3 manage.py loaddata fixtures/external_tools.yaml --app scanEngine.InstalledExternalTool

worker_command() {
    local queue=$1
    local worker_name=$2
    local workers_count=$3
    local concurrency=$4
    local pool_type=$5
    
    for i in $(seq 1 $workers_count); do
        local worker_id="${worker_name}_${i}"
        
        if [ "$CELERY_DEBUG" = "1" ]; then
            watchmedo auto-restart --recursive --pattern="*.py" --directory="$RENGINE_FOLDER" -- \
                poetry run -C $RENGINE_FOLDER celery -A reNgine worker \
                --pool=solo \
                --loglevel=$CELERY_LOGLEVEL \
                -Q $queue -n $worker_id &
        else
            poetry run -C $RENGINE_FOLDER celery -A reNgine worker \
                --pool=$pool_type \
                --loglevel=$CELERY_LOGLEVEL \
                --autoscale=$concurrency,$MIN_CONCURRENCY \
                -Q $queue -n $worker_id &
        fi
    done
}

# Configuration optimized queues with specialized pools
print_msg "Starting Celery workers with optimized configuration"

# Orchestrator - Pool solo for sequentiality
worker_command "orchestrator_queue" "orchestrator" $ORCHESTRATOR_WORKERS 2 "solo"

# I/O Intensif - Pool gevent for async
worker_command "io_queue" "io" $IO_WORKERS 15 "gevent"

# Commandes système - Pool prefork for isolation
worker_command "run_command_queue" "command" $COMMAND_WORKERS 8 "prefork"

# CPU Intensif - Pool prefork for parallelism
worker_command "cpu_queue" "cpu" $CPU_WORKERS 6 "prefork"

# Rapports - Pool gevent for I/O
worker_command "report_queue" "report" $REPORT_WORKERS 5 "gevent"

# Notifications - Pool gevent for I/O
worker_command "notification_queue" "notification" $NOTIFICATION_WORKERS 5 "gevent"

# Batch processing - Pool gevent for I/O
worker_command "batch_queue" "batch" 2 10 "gevent"

wait

exec "$@"