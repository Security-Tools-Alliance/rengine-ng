#!/bin/bash

if [ "$CELERY_DEBUG" == "1" ]; then
    export CELERY_LOGLEVEL='debug'
fi

# Check if remote debugging is enabled and set concurrency to 1 for easier debug
if [ "$CELERY_REMOTE_DEBUG" == "1" ]; then
    # Set celery concurrency to 1 because thread processes is hard to debug
    export MIN_CONCURRENCY=1
    export MAX_CONCURRENCY=1
fi

RENGINE_FOLDER="/home/$USERNAME/rengine"
export FLOWER_UNAUTHENTICATED_API=true
poetry run -C $RENGINE_FOLDER celery flower &

/entrypoint.sh