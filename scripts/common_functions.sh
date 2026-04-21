#!/bin/bash

# Define color codes.
COLOR_BLACK=0
COLOR_RED=1 # For errors and important messages
COLOR_GREEN=2 # For succesful output/messages
COLOR_YELLOW=3 # For questions and choices
COLOR_BLUE=4
COLOR_MAGENTA=5
COLOR_CYAN=6 # For actions that are being executed
COLOR_WHITE=7 # Default, we don't really use this explicitly
COLOR_DEFAULT=$COLOR_WHITE # Use white as default for clarity

# Log messages in different colors
log() {
  local color=${2:-$COLOR_DEFAULT}  # Use default color if $2 is not set
  if [ "$color" -ne $COLOR_DEFAULT ]; then
    tput setaf "$color"
  fi
  printf "$1\r\n"
  tput sgr0  # Reset text color
}

# Ensure required commands are in PATH; exit with a consistent message if any are missing.
# Usage: require_commands jq curl
require_commands() {
  local cmd
  for cmd in "$@"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      log "Error: $cmd is required but not installed. Please install $cmd and re-run this script." $COLOR_RED
      exit 1
    fi
  done
}

# Append to .env any KEY=value line from .env-dist whose KEY is not already present in .env.
# root_dir: repository root containing .env and .env-dist.
# Preserves existing user values; only adds missing keys. Exception: POSTGRES_HOST and POSTGRES_PORT
# are always taken from .env-dist (lines removed from .env then re-added from .env-dist).
merge_env_from_dist_at_root() {
  local root_dir="${1:?}"
  local env_dist="${root_dir}/.env-dist"
  local env_file="${root_dir}/.env"
  [[ ! -f "$env_dist" ]] && return 0
  if [[ -f "$env_file" ]]; then
    sed -i '/^POSTGRES_HOST=/d' "$env_file"
    sed -i '/^POSTGRES_PORT=/d' "$env_file"
  fi
  local line key
  while IFS= read -r line; do
    if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      key="${BASH_REMATCH[1]}"
      if ! grep -q "^${key}=" "$env_file" 2>/dev/null; then
        echo "$line" >> "$env_file"
      fi
    fi
  done < "$env_dist"
}

# Default web container name for reNgine-ng (used by install.sh and update.sh).
RENGINE_WEB_CONTAINER="rengine-web-1"

# Placeholder value in .env-dist; if this is the only value in .env, the key is not really configured.
RENGINE_SECATOR_API_KEY_PLACEHOLDER="your-generated-api-key-here"

# Return 0 if env_file has a real Secator API key (present and not the placeholder). Return 1 otherwise.
# Normalize value (strip control chars, trim) so placeholder is never mistaken for configured on any system.
is_secator_api_key_configured() {
  local env_file="${1:?}"
  [[ ! -f "$env_file" ]] && return 1
  local raw val
  raw=$(grep -E '^SECATOR_ADDONS_API_KEY=' "$env_file" 2>/dev/null | head -1 | cut -d= -f2-)
  val=$(printf '%s' "$raw" | tr -d '\r\n' | tr -d '\000-\037\177' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  [[ -z "$val" ]] && return 1
  [[ "$val" == "your-generated-api-key-here" ]] && return 1
  [[ "$val" == "$RENGINE_SECATOR_API_KEY_PLACEHOLDER" ]] && return 1
  [[ "$val" == "your-generated-api-key-here"* ]] && return 1
  return 0
}

# Run a command inside the web container. Usage: run_in_web_container "cmd"
run_in_web_container() {
  local cmd="$1"
  local container="${2:-$RENGINE_WEB_CONTAINER}"
  docker exec "$container" bash -c "$cmd"
}

# Path used inside the web container to pass the key back (avoids parsing mixed stdout from manage.py).
RENGINE_SECATOR_KEY_FILE="/tmp/rengine_secator_key_script.txt"

# Output Secator API key from container (create if missing; do not use --recreate). Empty if key exists or error.
# Uses --output-file in the container so we do not depend on stdout (avoids logo/banner mixed in).
# When the command fails, the error message is written to stderr so the caller can capture and display it.
# Optional first arg: container name; default RENGINE_WEB_CONTAINER.
get_secator_api_key_from_container() {
  local container="${1:-$RENGINE_WEB_CONTAINER}"
  local err_file
  err_file=$(mktemp) || return 1
  docker exec "$container" rm -f "$RENGINE_SECATOR_KEY_FILE" 2>/dev/null || true
  run_in_web_container "poetry run python3 manage.py generate_secator_api_key --raw-key --output-file=$RENGINE_SECATOR_KEY_FILE" "$container" 2> "$err_file"
  local exitcode=$?
  local key
  key=$(docker exec "$container" cat "$RENGINE_SECATOR_KEY_FILE" 2>/dev/null | tr -d '\r\n')
  docker exec "$container" rm -f "$RENGINE_SECATOR_KEY_FILE" 2>/dev/null || true
  if [ "$exitcode" -ne 0 ] && [ -s "$err_file" ]; then
    cat "$err_file" >&2
  fi
  rm -f "$err_file"
  printf '%s' "$key"
}

# Return 0 if a Secator API key already exists in DB, 1 otherwise. Optional first arg: container name.
has_secator_api_key_in_db() {
  local container="${1:-$RENGINE_WEB_CONTAINER}"
  local out
  out=$(run_in_web_container 'poetry run python3 manage.py generate_secator_api_key 2>&1' "$container" || true)
  echo "$out" | grep -q "already exists"
}

# Remove existing Secator block from env_file and append standard block with key. Uses temp file then mv.
# Usage: write_secator_env_block /path/to/.env "api_key_value"
write_secator_env_block() {
  local env_file="$1"
  local key="$2"
  [[ -z "$env_file" || -z "$key" ]] && return 1
  [[ ! -f "$env_file" || ! -w "$env_file" ]] && return 1
  local tmp_file
  tmp_file=$(mktemp "${env_file}.XXXXXX") || return 1
  awk '
    BEGIN { skip = 0 }
    /^# Secator Worker API Configuration/ { next }
    /^# BEGIN Secator Worker API Configuration/ { skip = 1; next }
    /^# END Secator Worker API Configuration/ { skip = 0; next }
    skip == 1 { next }
    /^SECATOR_ADDONS_API_ENABLED=/ { next }
    /^SECATOR_ADDONS_API_KEY=/ { next }
    /^SECATOR_ADDONS_API_HEADER_NAME=/ { next }
    /^SECATOR_ADDONS_API_WORKSPACE_GET_ENDPOINT=/ { next }
    /^SECATOR_ADDONS_API_URL=/ { next }
    /^SECATOR_ADDONS_API_FORCE_SSL=/ { next }
    /^RENGINE_API_KEY=/ { next }
    /^RENGINE_API_URL=/ { next }
    { print }
  ' "$env_file" > "$tmp_file" || { rm -f "$tmp_file"; return 1; }
  {
    echo ""
    echo "# Secator Worker API Configuration (auto-generated)"
    echo "SECATOR_ADDONS_API_ENABLED=true"
    echo "SECATOR_ADDONS_API_KEY=$key"
    echo "SECATOR_ADDONS_API_HEADER_NAME=Api-Key"
    echo "SECATOR_ADDONS_API_WORKSPACE_GET_ENDPOINT="
    echo "SECATOR_ADDONS_API_URL=https://proxy/api/secator"
    echo "SECATOR_ADDONS_API_FORCE_SSL=false"
  } >> "$tmp_file" || { rm -f "$tmp_file"; return 1; }
  mv "$tmp_file" "$env_file"
  # When run as root (e.g. sudo), restore .env ownership to the user who invoked sudo
  if [[ "$EUID" -eq 0 && -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
    chown "$SUDO_USER:$SUDO_USER" "$env_file" 2>/dev/null || chown "$SUDO_USER" "$env_file" 2>/dev/null || true
  fi
}

# Ensure .env has a real Secator API key: if not (missing or placeholder), get or create key and write block.
# Usage: ensure_secator_api_key_in_env env_file repo_root [make_output_log_file]
# Returns 0 on success (key configured or written or "already exists" warning). Returns 1 on hard failure.
# Optional make_output_log_file: if set, make restart output is appended to this file.
ensure_secator_api_key_in_env() {
  local env_file="${1:?}"
  local repo_root="${2:?}"
  local make_log_file="${3:-}"
  if is_secator_api_key_configured "$env_file"; then
    log "Secator API key already configured in .env" $COLOR_GREEN
    return 0
  fi
  log "Generating Secator API key..." $COLOR_CYAN
  local err_file
  err_file=$(mktemp) || return 1
  local key
  key=$(get_secator_api_key_from_container 2>"$err_file")
  if [[ -n "$key" ]]; then
    log "Secator API key generated successfully" $COLOR_GREEN
    if write_secator_env_block "$env_file" "$key"; then
      log "Secator API configuration written to .env" $COLOR_GREEN
      # Container must be restarted so it reloads .env and uses the new API key (COLD=1 for full env reload).
      log "Restarting web service (cold) to load new API key..." $COLOR_CYAN
      if [[ -n "$make_log_file" ]]; then
        (cd "$repo_root" && make restart web COLD=1) >> "$make_log_file" 2>&1 || log "Warning: make restart web COLD=1 failed" $COLOR_YELLOW
      else
        (cd "$repo_root" && make restart web COLD=1) || log "Warning: make restart web COLD=1 failed" $COLOR_YELLOW
      fi
    else
      log "Warning: Could not update .env file. Manually add Secator API configuration." $COLOR_YELLOW
    fi
    rm -f "$err_file"
    return 0
  fi
  if [[ -s "$err_file" ]] && grep -q "already exists" "$err_file" 2>/dev/null; then
    log "Secator API key already exists in database but could not be retrieved; .env may be out of sync." $COLOR_YELLOW
    log "To fix: make shell, then python3 manage.py generate_secator_api_key --recreate --show-key, and add SECATOR_ADDONS_API_KEY to .env" $COLOR_YELLOW
    [[ -n "$make_log_file" ]] && echo "WARNING: Secator key exists in DB but not in .env; user should sync manually" >> "$make_log_file"
    rm -f "$err_file"
    return 0
  fi
  log "Secator API key could not be generated:" $COLOR_RED
  if [[ -s "$err_file" ]]; then
    while IFS= read -r line; do log "$line" $COLOR_RED; done < "$err_file"
  else
    log "Empty output from generate_secator_api_key --raw-key. Run the command manually for details." $COLOR_RED
  fi
  log "Fix the error above (e.g. database connection, PgBouncer auth). Then run: make shell, then python3 manage.py generate_secator_api_key --recreate --show-key" $COLOR_YELLOW
  rm -f "$err_file"
  return 1
}

# Set SCRIPT_DIR and REPO_ROOT from the path of the script that sources common_functions.
# Usage: resolve_repo_paths "${BASH_SOURCE[0]}"  (call from the script that was sourced)
resolve_repo_paths() {
  local script_path="${1:?}"
  SCRIPT_DIR="$(cd "$(dirname "$script_path")" && pwd)"
  REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
}

# Exit with message if not running as root. Use for scripts that must be run with sudo (e.g. update.sh).
require_running_as_root() {
  if [ "$(whoami)" != "root" ]; then
    log "Error updating reNgine-ng: please run this script as root!" $COLOR_RED
    log "Example: sudo ./scripts/update.sh (from repository root)" $COLOR_RED
    exit 1
  fi
}

# Exit if not run with sudo from a non-root user (e.g. install.sh).
require_sudo_from_non_root() {
  if [ -z "${SUDO_USER:-}" ]; then
    log "Error: This script must be run with sudo." $COLOR_RED
    log "Example: 'sudo ./install.sh'" $COLOR_RED
    exit 1
  fi
  if [ "$EUID" -eq 0 ] && { [ "$SUDO_USER" = "root" ] || [ -z "$SUDO_USER" ]; }; then
    log "Error: Do not run this script as root user. Use 'sudo' with a non-root user." $COLOR_RED
    log "Example: 'sudo ./install.sh'" $COLOR_RED
    exit 1
  fi
}
