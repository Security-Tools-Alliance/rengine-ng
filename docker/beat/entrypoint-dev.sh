#!/bin/bash

# Check if remote debugging is enabled and set concurrency to 1 for easier debug
if [ "$CELERY_REMOTE_DEBUG" == "1" ]; then
    # Set celery concurrency to 1 because thread processes is hard to debug
    export MAX_CONCURRENCY=1
fi

/entrypoint.sh