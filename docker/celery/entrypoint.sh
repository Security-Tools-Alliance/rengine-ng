#!/bin/bash

print_msg() {
  printf "\r\n"
  printf "========================================\r\n"
  printf "$1\r\n"
  printf "========================================\r\n\r\n"
}

RENGINE_FOLDER="/home/$USERNAME/rengine"

print_msg "Generate Django migrations files"
poetry run -C $RENGINE_FOLDER python3 manage.py makemigrations
print_msg "Migrate database"
poetry run -C $RENGINE_FOLDER python3 manage.py migrate
print_msg "Collect static files"
poetry run -C $RENGINE_FOLDER python3 manage.py collectstatic --no-input --clear

# Load default engines, keywords, and external tools
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

# Validate required environment variables for Secator worker
REQUIRED_ENV_VARS=("SECATOR_LOG_LEVEL" "SECATOR_BROKER_URL" "SECATOR_CONCURRENCY")
for VAR in "${REQUIRED_ENV_VARS[@]}"; do
    if [ -z "${!VAR}" ]; then
        echo "Error: Required environment variable $VAR is not set."
        exit 1
    fi
done

# Provide defaults for optional environment variables
SECATOR_PREFETCH_MULTIPLIER=${SECATOR_PREFETCH_MULTIPLIER:-4}

# Add concurrency
MAX_CONCURRENCY=${MAX_CONCURRENCY:-20}
CONCURRENCY=${SECATOR_CONCURRENCY:-$MAX_CONCURRENCY}

# Add log level
SECATOR_LOG_LEVEL=${SECATOR_LOG_LEVEL:-info}

# Build Secator worker command with appropriate options
SECATOR_CMD="secator worker --loglevel $SECATOR_LOG_LEVEL --broker $SECATOR_BROKER_URL --concurrency $CONCURRENCY --prefetch-multiplier $SECATOR_PREFETCH_MULTIPLIER"

# Development mode options
if [ "$SECATOR_DEV_MODE" = "1" ]; then
    echo "Starting Secator worker in DEVELOPMENT mode"
    SECATOR_CMD="$SECATOR_CMD --dev"
    
    # Add reload for auto-restart on code changes
    if [ "$SECATOR_RELOAD" = "1" ]; then
        SECATOR_CMD="$SECATOR_CMD --reload"
        echo "  - Autoreload enabled"
    fi
else
    echo "Starting Secator worker in PRODUCTION mode"
fi

# Quiet mode
if [ "$SECATOR_QUIET" = "1" ]; then
    SECATOR_CMD="$SECATOR_CMD --quiet"
fi

# Disable gossip/mingle for dev (reduces overhead)
if [ "$SECATOR_WITHOUT_GOSSIP" = "1" ]; then
    SECATOR_CMD="$SECATOR_CMD --without-gossip"
fi

if [ "$SECATOR_WITHOUT_MINGLE" = "1" ]; then
    SECATOR_CMD="$SECATOR_CMD --without-mingle"
fi

# Disable heartbeat if needed (useful for debugging)
if [ "$SECATOR_WITHOUT_HEARTBEAT" = "1" ]; then
    SECATOR_CMD="$SECATOR_CMD --without-heartbeat"
fi

# Custom queue if specified
if [ -n "$SECATOR_QUEUE" ]; then
    SECATOR_CMD="$SECATOR_CMD --queue=$SECATOR_QUEUE"
fi

# Custom pool if specified
if [ -n "$SECATOR_POOL" ]; then
    SECATOR_CMD="$SECATOR_CMD --pool=$SECATOR_POOL"
fi

# Check if custom reload is requested
if [ "$SECATOR_USE_CUSTOM_RELOAD" = "1" ]; then
    echo "Using smart reload script for development..."
    echo "Starting reNgine development worker with smart reload..."
    
    # Set working directory to reNgine
    cd /home/rengine/rengine
    
    # Use smart reload Python script
    exec python3 /home/rengine/smart_reload.py
else
    # Display final command
    echo "Executing: $SECATOR_CMD"
    echo "Concurrency: $CONCURRENCY | Log level: $SECATOR_LOG_LEVEL"
    
    # Execute Secator worker
    eval $SECATOR_CMD
fi

wait

exec "$@"