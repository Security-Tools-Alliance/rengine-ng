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
poetry run -C $RENGINE_FOLDER python3 manage.py loaddefaultengines
print_msg "Load default keywords"
poetry run -C $RENGINE_FOLDER python3 manage.py loaddata fixtures/default_keywords.yaml --app scanEngine.InterestingLookupModel
print_msg "Load default external tools"
poetry run -C $RENGINE_FOLDER python3 manage.py loaddata fixtures/external_tools.yaml --app scanEngine.InstalledExternalTool

# Load Secator workflows and tasks
print_msg "Load Secator workflows"
poetry run -C $RENGINE_FOLDER python3 manage.py load_workflows --force
print_msg "Migrate engines to Secator"
poetry run -C $RENGINE_FOLDER python3 manage.py migrate_engines_to_secator

# Configure Secator to use Redis
print_msg "Configure Secator with Redis"
secator config set celery.broker_url redis://redis:6379/0
secator config set celery.result_backend redis://redis:6379/0

# Start Secator worker
print_msg "Starting Secator worker"
if [ "$CELERY_DEBUG" = "1" ]; then
    echo "Starting Secator worker in debug mode"
    secator worker
else
    echo "Starting Secator worker in production mode"
    secator worker --loglevel=$CELERY_LOGLEVEL --concurrency=$MAX_CONCURRENCY
fi

wait

exec "$@"