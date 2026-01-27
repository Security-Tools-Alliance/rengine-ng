#!/bin/bash
set -e

echo "🔧 Secator worker entrypoint starting..." >&2

exec secator "$@"
