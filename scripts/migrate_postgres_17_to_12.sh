#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE="docker/docker-compose.yml"
export RENGINE_VERSION="$(cat web/reNgine/version.txt)"
OLD_VOLUME="rengine_postgres_data"
BACKUP_DIR="${HOME}/postgres-migration-backups"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NEW_VOLUME="rengine_postgres_data_v12_${STAMP}"
PG17_CONTAINER="rengine-pg17-migration"
PG12_CONTAINER="rengine-pg12-migration"

env_value() {
  local key="$1"
  sed -n "s/^${key}=//p" .env | tail -n 1 | tr -d '\r'
}

cleanup() {
  docker rm -f "${PG17_CONTAINER}" "${PG12_CONTAINER}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

[[ -f .env ]] || { echo "Missing .env"; exit 1; }
[[ -f "${COMPOSE_FILE}" ]] || { echo "Missing ${COMPOSE_FILE}"; exit 1; }

db_name="$(env_value POSTGRES_DB)"
db_user="$(env_value POSTGRES_USER)"
[[ "${db_name}" =~ ^[A-Za-z0-9_]+$ ]] || { echo "Invalid POSTGRES_DB"; exit 1; }
[[ "${db_user}" =~ ^[A-Za-z0-9_]+$ ]] || { echo "Invalid POSTGRES_USER"; exit 1; }

current_volume="$(env_value POSTGRES_VOLUME_NAME)"
if [[ "${current_volume}" == rengine_postgres_data_v12_* ]]; then
  if current_version="$(docker run --rm -v "${current_volume}:/data:ro" alpine:3.20 cat /data/PG_VERSION 2>/dev/null)" &&
     [[ "${current_version}" == "12" ]]; then
    echo "PostgreSQL migration already completed: ${current_volume}"
    exit 0
  fi
  echo "Configured migration volume ${current_volume} is missing or invalid; rebuilding it from ${OLD_VOLUME}"
fi

docker volume inspect "${OLD_VOLUME}" >/dev/null
source_version="$(docker run --rm -v "${OLD_VOLUME}:/data:ro" alpine:3.20 cat /data/PG_VERSION)"
[[ "${source_version}" == "17" ]] || {
  echo "Expected PostgreSQL 17 source volume, found ${source_version}"
  exit 1
}

install -d -m 700 "${BACKUP_DIR}"
source_kb="$(docker run --rm -v "${OLD_VOLUME}:/data:ro" alpine:3.20 sh -c 'du -sk /data | cut -f1')"
available_kb="$(df -Pk "${BACKUP_DIR}" | awk 'NR==2 {print $4}')"
required_kb="$((source_kb * 2 + 1048576))"
(( available_kb >= required_kb )) || {
  echo "Insufficient disk space for physical and logical backups"
  exit 1
}

echo "Stopping application containers without deleting volumes"
docker compose -f "${COMPOSE_FILE}" down --remove-orphans

physical_backup="${BACKUP_DIR}/postgres17-${STAMP}.tar.gz"
logical_backup="${BACKUP_DIR}/postgres17-${STAMP}.sql"

echo "Creating physical backup"
docker run --rm \
  -v "${OLD_VOLUME}:/source:ro" \
  -v "${BACKUP_DIR}:/backup" \
  alpine:3.20 \
  tar -C /source -czf "/backup/$(basename "${physical_backup}")" .

echo "Starting temporary PostgreSQL 17"
docker run -d --name "${PG17_CONTAINER}" \
  -v "${OLD_VOLUME}:/var/lib/postgresql/data" \
  postgres:17 >/dev/null

for _ in {1..60}; do
  if docker exec "${PG17_CONTAINER}" pg_isready -U "${db_user}" -d "${db_name}" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
docker exec "${PG17_CONTAINER}" pg_isready -U "${db_user}" -d "${db_name}" >/dev/null

echo "Creating logical backup"
docker exec "${PG17_CONTAINER}" \
  pg_dump -U "${db_user}" -d "${db_name}" \
  --format=plain --no-owner --no-privileges > "${logical_backup}"
[[ -s "${logical_backup}" ]] || { echo "Logical backup is empty"; exit 1; }
grep -q '^-- PostgreSQL database dump' "${logical_backup}" || {
  echo "Logical backup header validation failed"
  exit 1
}
sed -i \
  -e '/^\\restrict /d' \
  -e '/^\\unrestrict /d' \
  -e '/^SET transaction_timeout = /d' \
  "${logical_backup}"

docker rm -f "${PG17_CONTAINER}" >/dev/null

echo "Creating new PostgreSQL 12 volume"
docker volume create "${NEW_VOLUME}" >/dev/null
docker run -d --name "${PG12_CONTAINER}" \
  --env-file .env \
  -v "${NEW_VOLUME}:/var/lib/postgresql/data" \
  "ghcr.io/security-tools-alliance/rengine-ng:rengine-postgres-v$(cat web/reNgine/version.txt)" >/dev/null

for _ in {1..60}; do
  if docker exec "${PG12_CONTAINER}" pg_isready -U "${db_user}" -d "${db_name}" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
docker exec "${PG12_CONTAINER}" pg_isready -U "${db_user}" -d "${db_name}" >/dev/null

echo "Restoring logical backup into PostgreSQL 12"
docker exec -i "${PG12_CONTAINER}" \
  psql -v ON_ERROR_STOP=1 -U "${db_user}" -d "${db_name}" < "${logical_backup}"

table_count="$(docker exec "${PG12_CONTAINER}" \
  psql -U "${db_user}" -d "${db_name}" -Atqc \
  "SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname = 'public';")"
[[ "${table_count}" =~ ^[0-9]+$ ]] || { echo "Unable to verify restored tables"; exit 1; }

docker rm -f "${PG12_CONTAINER}" >/dev/null

if grep -q '^POSTGRES_VOLUME_NAME=' .env; then
  sed -i "s/^POSTGRES_VOLUME_NAME=.*/POSTGRES_VOLUME_NAME=${NEW_VOLUME}/" .env
else
  printf '\nPOSTGRES_VOLUME_NAME=%s\n' "${NEW_VOLUME}" >> .env
fi
chmod 600 .env

echo "Migration completed with ${table_count} public tables"
echo "Original volume retained: ${OLD_VOLUME}"
echo "Physical and logical backups retained in ${BACKUP_DIR}"
