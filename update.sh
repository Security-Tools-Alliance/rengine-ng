#!/bin/bash

# Define color codes.
# Using `tput setaf` at some places because the variable only works with log/echo

COLOR_BLACK=0
COLOR_RED=1
COLOR_GREEN=2
COLOR_YELLOW=3
COLOR_BLUE=4
COLOR_MAGENTA=5
COLOR_CYAN=6
COLOR_WHITE=7
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

log
read -p "Do you want to apply your local changes after updating? (y/n) " answer

if [[ $answer == "y" ]]; then
  make down && git stash save && git pull && git stash apply && make build && make up
  tput setaf 2;
  echo "Successfully updated"
elif [[ $answer == "n" ]]; then
  make down && git stash && git stash drop && git pull && make build && make up
  tput setaf 2;
  echo "Successfully updated"
else
  echo "Invalid input. Please enter 'y' or 'n'."
fi
