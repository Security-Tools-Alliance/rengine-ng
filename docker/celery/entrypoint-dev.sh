#!/bin/bash

# Check if remote debugging is enabled and set concurrency to 1 for easier debug
if [ "$CELERY_REMOTE_DEBUG" == "1" ]; then
    # Set celery concurrency to 1 because thread processes is hard to debug
    export MAX_CONCURRENCY=1
    export SECATOR_CONCURRENCY=1
else
    # In dev mode without remote debug, use low concurrency for better monitoring
    export MAX_CONCURRENCY=${MAX_CONCURRENCY:-5}
    export SECATOR_CONCURRENCY=${SECATOR_CONCURRENCY:-3}
fi

RENGINE_FOLDER="/home/$USERNAME/rengine"

# Call main entrypoint
/entrypoint.sh