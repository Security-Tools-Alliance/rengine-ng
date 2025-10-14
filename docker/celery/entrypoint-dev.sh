#!/bin/bash

# Development mode configuration
export CELERY_DEBUG=${CELERY_DEBUG:-1}
export CELERY_LOGLEVEL=${CELERY_LOGLEVEL:-debug}

# Enable custom reload for development
export USE_CUSTOM_RELOAD=1

# Use dev mode for easier debugging
export SECATOR_DEV_MODE=1

# Check if remote debugging is enabled and set concurrency to 1 for easier debug
if [ "$CELERY_REMOTE_DEBUG" == "1" ]; then
    # Set celery concurrency to 1 because thread processes is hard to debug
    export MIN_CONCURRENCY=1
    export MAX_CONCURRENCY=1
    export SECATOR_CONCURRENCY=1
else
    # In dev mode without remote debug, use low concurrency for better monitoring
    export MIN_CONCURRENCY=${MIN_CONCURRENCY:-2}
    export MAX_CONCURRENCY=${MAX_CONCURRENCY:-5}
    export SECATOR_CONCURRENCY=${SECATOR_CONCURRENCY:-3}
fi

# Development-specific settings
export FLOWER_UNAUTHENTICATED_API=true
export SECATOR_QUIET=0  # Verbose output in dev

# Enable additional Secator dev options
export SECATOR_WITHOUT_GOSSIP=1
export SECATOR_WITHOUT_MINGLE=1

RENGINE_FOLDER="/home/$USERNAME/rengine"

# Call main entrypoint
/entrypoint.sh