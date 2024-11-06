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
