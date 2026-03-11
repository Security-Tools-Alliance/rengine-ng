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
