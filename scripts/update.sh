#!/bin/bash

# Import common functions and resolve script/repo paths (run as: sudo ./scripts/update.sh from repo root)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common_functions.sh"
resolve_repo_paths "${BASH_SOURCE[0]}"

# Parse arguments and strip known flags so "$@" does not accumulate on re-exec
POST_UPDATE=0
FORCE_UPDATE=0
NON_INTERACTIVE=0
RESUME=0
SHOW_HELP=0
ARGS=()
for arg in "$@"; do
  case "$arg" in
    --post-update) POST_UPDATE=1 ;;
    --force)       FORCE_UPDATE=1 ;;
    -n|--non-interactive) NON_INTERACTIVE=1 ;;
    --resume)      RESUME=1 ;;
    -h|--help)     SHOW_HELP=1 ;;
    *)             ARGS+=("$arg") ;;
  esac
done
set -- "${ARGS[@]}"

show_usage() {
  echo "Usage: sudo ./scripts/update.sh [OPTIONS]"
  echo "Update reNgine-ng from the repository (compare version, git pull, post-update steps)."
  echo ""
  echo "Options:"
  echo "  -h, --help             Show this help and exit"
  echo "  --post-update          Internal: run only post-update steps (after git pull)"
  echo "  --resume               Restart from a failed update (make down, make up, no git pull)"
  echo "  --force                Allow update even when current version is not older than latest"
  echo "  -n, --non-interactive  No prompts; use defaults or environment variables"
  echo ""
  echo "Environment (for non-interactive or re-exec):"
  echo "  NON_INTERACTIVE=1              Same as -n"
  echo "  RENGINE_UPDATE_INSTALL_TYPE    pre-built or source (default: pre-built)"
  echo "  RENGINE_UPDATE_APPLY_CHANGES    y or n to apply local changes after pull (default: n)"
  echo ""
  echo "Example: sudo ./scripts/update.sh"
  echo "         sudo ./scripts/update.sh -n --force"
}

# --post-update and --resume are mutually exclusive (internal vs user re-run)
if [[ $POST_UPDATE -eq 1 && $RESUME -eq 1 ]]; then
  echo "Error: --post-update and --resume cannot be used together. Aborting." >&2
  exit 1
fi

if [[ $SHOW_HELP -eq 1 ]]; then
  show_usage
  exit 0
fi

for arg in "$@"; do
  if [[ "$arg" == -* ]]; then
    echo "Error: Unknown option: $arg" >&2
    show_usage >&2
    exit 1
  fi
done

require_running_as_root

# Run git as the user who invoked sudo, so repo files keep correct ownership (not root).
GIT_AS_USER="${SUDO_USER:-}"
if [[ -z "$GIT_AS_USER" ]]; then
  GIT_AS_USER=$(stat -c '%U' "$REPO_ROOT" 2>/dev/null) || GIT_AS_USER=$(stat -f '%Su' "$REPO_ROOT" 2>/dev/null) || true
fi
run_git() {
  if [[ -n "$GIT_AS_USER" && "$GIT_AS_USER" != "root" ]]; then
    sudo -u "$GIT_AS_USER" git "$@"
  else
    git "$@"
  fi
}

# Function to compare version strings
version_compare() {
  if [[ $1 == "$2" ]]; then
    return 0
  fi
  local IFS=.
  local i ver1=($1) ver2=($2)
  for ((i=${#ver1[@]}; i<${#ver2[@]}; i++)); do
    ver1[i]=0
  done
  for ((i=0; i<${#ver1[@]}; i++)); do
    if [[ -z ${ver2[i]} ]]; then
      ver2[i]=0
    fi
    if ((10#${ver1[i]} > 10#${ver2[i]})); then
      return 1
    fi
    if ((10#${ver1[i]} < 10#${ver2[i]})); then
      return 2
    fi
  done
  return 0
}

# Create update log file and log a line (also to stdout via log() if desired).
# Preserve LOG_FILE from environment when re-exec'd with --post-update so we keep one log file and debug lands in it.
LOG_FILE="${LOG_FILE:-}"
log_to_file() {
  local msg="$1"
  if [[ -n "$LOG_FILE" && -f "$LOG_FILE" ]]; then
    echo "$(date -Iseconds) $msg" >> "$LOG_FILE"
  fi
}

# Create timestamped update log file under REPO_ROOT/logs/ and write optional first message.
# Call this at the start of each major code path (resume, post-update, normal) so all runs are logged.
# Log file and logs/ dir are chown'd to GIT_AS_USER so they are owned by the current user, not root.
setup_update_log() {
  local first_msg="${1:-}"
  mkdir -p "$REPO_ROOT/logs"
  if [[ -n "$GIT_AS_USER" && "$GIT_AS_USER" != "root" ]]; then
    chown "$GIT_AS_USER" "$REPO_ROOT/logs" 2>/dev/null || true
  fi
  LOG_FILE="$REPO_ROOT/logs/rengine_update_$(date +%Y-%m-%d_%H%M%S).log"
  : > "$LOG_FILE"
  if [[ -n "$GIT_AS_USER" && "$GIT_AS_USER" != "root" ]]; then
    chown "$GIT_AS_USER" "$LOG_FILE" 2>/dev/null || true
  fi
  [[ -n "$first_msg" ]] && log_to_file "$first_msg"
}

# Ask for input; in non-interactive use default or env (treat empty env as unset).
# Optional 4th arg: allowed values as "a|b|c" (e.g. "pre-built|source" or "y|n"). When set, value is validated and script exits on invalid env/default in non-interactive mode.
ask_or_default() {
  local prompt="$1"
  local default="$2"
  local env_var="${3:-}"
  local allowed="${4:-}"
  local val=""

  _is_allowed() {
    local v="$1"
    local list="$2"
    [[ -z "$list" ]] && return 0
    local i
    IFS='|' read -ra parts <<< "$list"
    for i in "${parts[@]}"; do
      [[ "$v" == "$i" ]] && return 0
    done
    return 1
  }

  if [[ $NON_INTERACTIVE -eq 1 ]]; then
    [[ -n "$env_var" ]] && val="${!env_var:-}"
    [[ -z "$val" ]] && val="$default"
    if [[ -n "$allowed" ]] && ! _is_allowed "$val" "$allowed"; then
      log "Invalid value '$val' for ${env_var:-option} in non-interactive mode. Allowed: ${allowed//|/, }." $COLOR_RED
      log "Fix the environment variable or unset it to use the default '$default'." $COLOR_RED
      exit 1
    fi
    echo "$val"
    return 0
  fi

  while true; do
    read -p "$prompt" answer
    [[ -z "$answer" && -n "$default" ]] && answer="$default"
    if [[ -z "$allowed" ]] || _is_allowed "$answer" "$allowed"; then
      echo "$answer"
      return 0
    fi
    log "Invalid input. Allowed values: ${allowed//|/, }." $COLOR_YELLOW
  done
}

# --- Post-update flow: optionally make down (when resume), then make up, Secator key, load_secator_all ---
# When skip_initial_steps=1 (--post-update after re-exec): caller already did make down + git pull; only do make up and init.
# When skip_initial_steps=0 (--resume): do make down then make up and init (no git pull).
run_post_update_flow() {
  local skip_initial_steps="${1:-0}"
  local install_type
  local apply_changes

  # After re-exec (--post-update), reuse exported answers to avoid asking again
  if [[ "$skip_initial_steps" -eq 1 && -n "${RENGINE_UPDATE_INSTALL_TYPE:-}" && -n "${RENGINE_UPDATE_APPLY_CHANGES:-}" ]]; then
    install_type="${RENGINE_UPDATE_INSTALL_TYPE}"
    apply_changes="${RENGINE_UPDATE_APPLY_CHANGES}"
    if [[ "$install_type" != "pre-built" && "$install_type" != "source" ]]; then
      log "Error: invalid RENGINE_UPDATE_INSTALL_TYPE '$install_type'. Must be 'pre-built' or 'source'." $COLOR_RED
      return 1
    fi
    if [[ "$apply_changes" != "y" && "$apply_changes" != "n" ]]; then
      log "Error: invalid RENGINE_UPDATE_APPLY_CHANGES '$apply_changes'. Must be 'y' or 'n'." $COLOR_RED
      return 1
    fi
  else
    install_type="$(ask_or_default "Do you want to update from pre-built images or build from source? (pre-built/source, default is pre-built): " "pre-built" "RENGINE_UPDATE_INSTALL_TYPE" "pre-built|source")"
    apply_changes="$(ask_or_default "Do you want to apply your local changes after updating? (y/n): " "n" "RENGINE_UPDATE_APPLY_CHANGES" "y|n")"
  fi

  log "Install type: $install_type, Apply local changes: $apply_changes" $COLOR_CYAN
  log_to_file "Install type: $install_type, Apply local changes: $apply_changes"

  if [[ "$skip_initial_steps" -eq 0 ]]; then
    if ! (cd "$REPO_ROOT" && make down); then
      log "Failed to stop reNgine-ng" $COLOR_RED
      log_to_file "ERROR: make down failed"
      return 1
    fi
    log_to_file "make down completed"
  fi

  if [[ "$install_type" == "pre-built" ]]; then
    if ! (cd "$REPO_ROOT" && make up); then
      log "Failed to pull and start updated images" $COLOR_RED
      log_to_file "ERROR: make up failed"
      return 1
    fi
  else
    if ! (cd "$REPO_ROOT" && make build_up); then
      log "Failed to build and start updated images" $COLOR_RED
      log_to_file "ERROR: make build_up failed"
      return 1
    fi
  fi
  log_to_file "make up / build_up completed"

  log "Merging .env with .env-dist (add missing keys, keep POSTGRES_HOST/POSTGRES_PORT from dist)..." $COLOR_CYAN
  merge_env_from_dist_at_root "$REPO_ROOT"
  log_to_file "merge_env_from_dist_at_root completed"

  log "Waiting for web container to be ready..." $COLOR_CYAN
  for i in $(seq 1 30); do
    if docker exec "$RENGINE_WEB_CONTAINER" echo "ready" >/dev/null 2>&1; then
      log "Web container is ready!" $COLOR_GREEN
      break
    fi
    if [[ $i -eq 30 ]]; then
      log "Timeout waiting for web container" $COLOR_RED
      log_to_file "ERROR: web container timeout"
      return 1
    fi
    sleep 2
  done

  log "Checking Secator API key..." $COLOR_CYAN
  if ensure_secator_api_key_in_env "$REPO_ROOT/.env" "$REPO_ROOT" "$LOG_FILE"; then
    log_to_file "Secator API key check completed"
  else
    log_to_file "ERROR: Secator API key could not be generated"
    return 1
  fi

  log "Loading Secator components (tasks, workflows, scans)..." $COLOR_CYAN
  if ! docker exec "$RENGINE_WEB_CONTAINER" bash -c 'poetry run python3 manage.py load_secator_all' >> "$LOG_FILE" 2>&1; then
    log "Warning: load_secator_all had non-zero exit" $COLOR_YELLOW
  fi
  log_to_file "load_secator_all completed"

  if [[ "$apply_changes" == "y" ]]; then
    log "Reapplying local changes (git stash apply)..." $COLOR_CYAN
    if (cd "$REPO_ROOT" && run_git stash apply) >> "$LOG_FILE" 2>&1; then
      log "Local changes reapplied successfully." $COLOR_GREEN
      log_to_file "git stash apply completed"
    else
      log "Warning: git stash apply failed; local changes may need to be applied manually." $COLOR_YELLOW
      log_to_file "WARNING: git stash apply failed"
    fi
  fi

  log "Post-update initialization completed!" $COLOR_GREEN
  return 0
}

# --- Resume: run post-update flow only (no version check, no git pull in main flow; run_post_update_flow does pull if apply_changes) ---
if [[ $RESUME -eq 1 ]]; then
  setup_update_log "Resume mode started"
  log "Resume mode: running post-update steps only." $COLOR_CYAN
  if run_post_update_flow 0; then
    log "Update log written to: $LOG_FILE" $COLOR_GREEN
    exit 0
  else
    log "Update failed. Update log written to: $LOG_FILE" $COLOR_RED
    log "Please attach this file when reporting the issue to maintainers." $COLOR_YELLOW
    exit 1
  fi
fi

# --- Post-update mode: skip version check, run post-update flow only ---
if [[ $POST_UPDATE -eq 1 ]]; then
  if [[ -n "${LOG_FILE:-}" && -f "$LOG_FILE" ]]; then
    mkdir -p "$REPO_ROOT/logs"
    log_to_file "Post-update mode started (re-exec)"
  else
    setup_update_log "Post-update mode started"
  fi
  if run_post_update_flow 1; then
    log "Update log written to: $LOG_FILE" $COLOR_GREEN
    exit 0
  else
    log "Update failed at post-update step. You can run: sudo $REPO_ROOT/scripts/update.sh --resume to retry." $COLOR_RED
    log "Update log written to: $LOG_FILE" $COLOR_YELLOW
    log "Please attach this file when reporting the issue to maintainers." $COLOR_YELLOW
    exit 1
  fi
fi

# --- Normal flow: version check, then optionally update ---
setup_update_log "Update check started"

VERSION_FILE="$REPO_ROOT/web/reNgine/version.txt"
if [[ ! -r "$VERSION_FILE" ]]; then
  log "Error: version file not found or not readable: $VERSION_FILE" $COLOR_RED
  log_to_file "ERROR: version.txt missing or unreadable"
  exit 1
fi
CURRENT_VERSION=$(cat "$VERSION_FILE")

require_commands jq curl

CURRENT_BRANCH=$(cd "$REPO_ROOT" && run_git branch --show-current 2>/dev/null)
[[ -z "$CURRENT_BRANCH" ]] && CURRENT_BRANCH="(detached HEAD)"

cat "$REPO_ROOT/web/art/reNgine.txt"
echo ""

if [[ "$CURRENT_BRANCH" == "master" || "$CURRENT_BRANCH" == "main" ]]; then
  # Stable branch: compare local version to GitHub latest release
  LATEST_VERSION=$(curl -s https://api.github.com/repos/Security-Tools-Alliance/rengine-ng/releases/latest \
    | jq -r '.tag_name // empty' \
    | sed 's/^v//')
  if [[ -z "$LATEST_VERSION" ]]; then
    log "Could not fetch latest version from GitHub (rate limit, network, or malformed tag)." $COLOR_RED
    log_to_file "ERROR: could not fetch or parse latest version from GitHub releases API"
    exit 1
  fi
  version_compare "$CURRENT_VERSION" "$LATEST_VERSION"
  comparison_result=$?

  log "" $COLOR_DEFAULT
  log "Current version: $CURRENT_VERSION (branch: $CURRENT_BRANCH)" $COLOR_CYAN
  log "Latest version: $LATEST_VERSION (stable, from GitHub release)" $COLOR_CYAN
  log "Update will bring you to the latest stable release." $COLOR_CYAN
  log "" $COLOR_DEFAULT
  log_to_file "Current: $CURRENT_VERSION (branch: $CURRENT_BRANCH), Latest: $LATEST_VERSION (stable), comparison_result=$comparison_result"

  # comparison_result: 0 = equal, 1 = current > latest, 2 = current < latest
  SHOULD_PROCEED=0
  case $comparison_result in
    0)
      log "You are already on the latest version." $COLOR_GREEN
      if [[ $FORCE_UPDATE -eq 1 ]]; then
        SHOULD_PROCEED=1
      elif [[ $NON_INTERACTIVE -eq 1 ]]; then
        log "Non-interactive mode and no --force: skipping update." $COLOR_YELLOW
        log_to_file "Exit: already latest, non-interactive without force"
        log "Update log written to: $LOG_FILE" $COLOR_GREEN
        exit 0
      else
        answer=$(ask_or_default "Do you want to force the update anyway? (y/n) " "n")
        if [[ "$answer" == "y" ]]; then
          SHOULD_PROCEED=1
        else
          log_to_file "Exit: user declined force update"
          log "Update log written to: $LOG_FILE" $COLOR_GREEN
          exit 0
        fi
      fi
      ;;
    1)
      log "Your version is newer than the latest release." $COLOR_YELLOW
      if [[ $FORCE_UPDATE -eq 1 ]]; then
        SHOULD_PROCEED=1
      elif [[ $NON_INTERACTIVE -eq 1 ]]; then
        log "Non-interactive mode and no --force: skipping update." $COLOR_YELLOW
        log_to_file "Exit: version newer, non-interactive without force"
        log "Update log written to: $LOG_FILE" $COLOR_GREEN
        exit 0
      else
        answer=$(ask_or_default "Do you want to force the update anyway? (y/n) " "n")
        if [[ "$answer" == "y" ]]; then
          SHOULD_PROCEED=1
        else
          log_to_file "Exit: user declined force update"
          log "Update log written to: $LOG_FILE" $COLOR_GREEN
          exit 0
        fi
      fi
      ;;
    2)
      log "An update is available." $COLOR_CYAN
      if [[ $NON_INTERACTIVE -eq 1 ]]; then
        SHOULD_PROCEED=1
      else
        answer=$(ask_or_default "Do you want to update to the latest version? (y/n) " "y")
        if [[ "$answer" == "y" ]]; then
          SHOULD_PROCEED=1
        fi
      fi
      if [[ $SHOULD_PROCEED -eq 0 ]]; then
        log "Update cancelled." $COLOR_YELLOW
        log_to_file "Exit: user cancelled update"
        log "Update log written to: $LOG_FILE" $COLOR_GREEN
        exit 0
      fi
      ;;
    *)
      log "Error comparing versions." $COLOR_RED
      log_to_file "ERROR: version comparison failed"
      exit 1
      ;;
  esac
else
  # Non-stable branch: compare local to origin/branch version; show stable for info
  log "Fetching origin to read remote branch version..." $COLOR_CYAN
  (cd "$REPO_ROOT" && run_git fetch origin) >> "$LOG_FILE" 2>&1 || true

  REMOTE_BRANCH_VERSION=$(cd "$REPO_ROOT" && run_git show "origin/$CURRENT_BRANCH:web/reNgine/version.txt" 2>/dev/null) || REMOTE_BRANCH_VERSION=""
  STABLE_VERSION=$(curl -s https://api.github.com/repos/Security-Tools-Alliance/rengine-ng/releases/latest \
    | jq -r '.tag_name // empty' \
    | sed 's/^v//') || STABLE_VERSION=""
  [[ -z "$STABLE_VERSION" ]] && STABLE_VERSION="(unavailable)"

  log "" $COLOR_DEFAULT
  log "Current version: $CURRENT_VERSION (branch: $CURRENT_BRANCH)" $COLOR_CYAN
  if [[ -n "$REMOTE_BRANCH_VERSION" ]]; then
    log "Remote branch version: $REMOTE_BRANCH_VERSION (origin/$CURRENT_BRANCH)" $COLOR_CYAN
  else
    log "Remote branch version: (unable to read or branch not on origin)" $COLOR_YELLOW
  fi
  log "Stable version: $STABLE_VERSION (from GitHub release)" $COLOR_CYAN
  log "Update will pull from origin; you will get the version of your current branch (not the stable release)." $COLOR_CYAN
  log "" $COLOR_DEFAULT

  if [[ -n "$REMOTE_BRANCH_VERSION" ]]; then
    version_compare "$CURRENT_VERSION" "$REMOTE_BRANCH_VERSION"
    comparison_result=$?
  else
    comparison_result=2
  fi
  log_to_file "Current: $CURRENT_VERSION (branch: $CURRENT_BRANCH), Remote branch: $REMOTE_BRANCH_VERSION, Stable: $STABLE_VERSION, comparison_result=$comparison_result"

  SHOULD_PROCEED=0
  case $comparison_result in
    0)
      log "You are already up to date for this branch." $COLOR_GREEN
      if [[ $FORCE_UPDATE -eq 1 ]]; then
        SHOULD_PROCEED=1
      elif [[ $NON_INTERACTIVE -eq 1 ]]; then
        log "Non-interactive mode and no --force: skipping update." $COLOR_YELLOW
        log_to_file "Exit: already up to date for branch, non-interactive without force"
        log "Update log written to: $LOG_FILE" $COLOR_GREEN
        exit 0
      else
        answer=$(ask_or_default "Do you want to force the pull anyway? (y/n) " "n")
        if [[ "$answer" == "y" ]]; then
          SHOULD_PROCEED=1
        else
          log_to_file "Exit: user declined force pull"
          log "Update log written to: $LOG_FILE" $COLOR_GREEN
          exit 0
        fi
      fi
      ;;
    1)
      log "Your local version is ahead of origin. Pull may merge or fast-forward." $COLOR_YELLOW
      if [[ $FORCE_UPDATE -eq 1 ]]; then
        SHOULD_PROCEED=1
      elif [[ $NON_INTERACTIVE -eq 1 ]]; then
        log "Non-interactive mode and no --force: skipping update." $COLOR_YELLOW
        log_to_file "Exit: local ahead of origin, non-interactive without force"
        log "Update log written to: $LOG_FILE" $COLOR_GREEN
        exit 0
      else
        answer=$(ask_or_default "Do you want to pull anyway? (y/n) " "n")
        if [[ "$answer" == "y" ]]; then
          SHOULD_PROCEED=1
        else
          log_to_file "Exit: user declined pull"
          log "Update log written to: $LOG_FILE" $COLOR_GREEN
          exit 0
        fi
      fi
      ;;
    2)
      log "An update is available for your branch." $COLOR_CYAN
      if [[ $NON_INTERACTIVE -eq 1 ]]; then
        SHOULD_PROCEED=1
      else
        answer=$(ask_or_default "Do you want to update to the latest version of this branch? (y/n) " "y")
        if [[ "$answer" == "y" ]]; then
          SHOULD_PROCEED=1
        fi
      fi
      if [[ $SHOULD_PROCEED -eq 0 ]]; then
        log "Update cancelled." $COLOR_YELLOW
        log_to_file "Exit: user cancelled update"
        log "Update log written to: $LOG_FILE" $COLOR_GREEN
        exit 0
      fi
      ;;
    *)
      log "Error comparing versions." $COLOR_RED
      log_to_file "ERROR: version comparison failed"
      exit 1
      ;;
  esac
fi

if [[ $SHOULD_PROCEED -eq 0 ]]; then
  log "Update log written to: $LOG_FILE" $COLOR_GREEN
  exit 0
fi

# Gather install_type and apply_changes for the re-exec (so post-update script does not ask again)
if [[ $NON_INTERACTIVE -eq 1 ]]; then
  RENGINE_UPDATE_INSTALL_TYPE="${RENGINE_UPDATE_INSTALL_TYPE:-pre-built}"
  RENGINE_UPDATE_APPLY_CHANGES="${RENGINE_UPDATE_APPLY_CHANGES:-n}"
else
  if [[ -z "${RENGINE_UPDATE_INSTALL_TYPE:-}" ]]; then
    while true; do
      read -p "Do you want to update from pre-built images or build from source? (pre-built/source, default is pre-built): " it
      it="${it:-pre-built}"
      if [[ "$it" == "pre-built" || "$it" == "source" ]]; then
        export RENGINE_UPDATE_INSTALL_TYPE="$it"
        break
      fi
      log "Invalid input. Please enter 'pre-built' or 'source'." $COLOR_YELLOW
    done
  fi
  if [[ -z "${RENGINE_UPDATE_APPLY_CHANGES:-}" ]]; then
    while true; do
      read -p "Do you want to apply your local changes after updating? (y/n): " ac
      if [[ "$ac" == "y" || "$ac" == "n" ]]; then
        export RENGINE_UPDATE_APPLY_CHANGES="$ac"
        break
      fi
      log "Invalid input. Please enter 'y' or 'n'." $COLOR_YELLOW
    done
  fi
fi

log_to_file "Proceeding: make down"
log "Stopping reNgine-ng..." $COLOR_CYAN
if ! (cd "$REPO_ROOT" && make down) >> "$LOG_FILE" 2>&1; then
  log "Failed to stop reNgine-ng" $COLOR_RED
  log_to_file "ERROR: make down failed"
  log "Update failed. You can run: sudo $REPO_ROOT/scripts/update.sh --resume to retry from post-update steps." $COLOR_YELLOW
  log "Update log written to: $LOG_FILE" $COLOR_YELLOW
  log "Please attach this file when reporting the issue to maintainers." $COLOR_YELLOW
  exit 1
fi

log_to_file "Proceeding: git stash + git pull (current branch)"
log "Stashing local changes and pulling latest code..." $COLOR_CYAN
if ! (cd "$REPO_ROOT" && run_git stash save 2>/dev/null; run_git pull) >> "$LOG_FILE" 2>&1; then
  log "Failed to update" $COLOR_RED
  log_to_file "ERROR: git pull failed"
  log "Update failed. Update log written to: $LOG_FILE" $COLOR_YELLOW
  log "Please attach this file when reporting the issue to maintainers." $COLOR_YELLOW
  exit 1
fi

# Re-exec the script in post-update mode so the NEW script (after git pull) runs the rest
log "Re-running update script (post-update steps)..." $COLOR_CYAN
log_to_file "Exec: $REPO_ROOT/scripts/update.sh --post-update"
export RENGINE_UPDATE_INSTALL_TYPE="${RENGINE_UPDATE_INSTALL_TYPE:-pre-built}"
export RENGINE_UPDATE_APPLY_CHANGES="${RENGINE_UPDATE_APPLY_CHANGES:-n}"
export LOG_FILE
exec "$REPO_ROOT/scripts/update.sh" --post-update
