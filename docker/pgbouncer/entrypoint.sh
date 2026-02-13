#!/bin/sh
# Create the Unix user matching POSTGRES_USER so pgbouncer can setuid to it
# (config [pgbouncer] user = $POSTGRES_USER is used for both setuid and DB connection).
if [ -n "${POSTGRES_USER}" ]; then
    adduser -D -h /nonexistent -s /sbin/nologin "${POSTGRES_USER}" 2>/dev/null || true
fi
# Ensure edoburu entrypoint has DB_* from POSTGRES_* (avoids compose substitution issues with special chars in password).
export DB_USER="${DB_USER:-$POSTGRES_USER}"
export DB_PASSWORD="${DB_PASSWORD:-$POSTGRES_PASSWORD}"
exec /entrypoint.sh "$@"
