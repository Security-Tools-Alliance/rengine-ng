#!/bin/bash
set -e

echo "🔧 Secator worker dev entrypoint starting..." >&2

exec secator "$@" --reload --use-command-runner
#exec secator "$@" --reload
