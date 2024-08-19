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

# Function to compare version strings
version_compare() {
    if [[ $1 == $2 ]]
    then
        return 0
    fi
    local IFS=.
    local i ver1=($1) ver2=($2)
    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++))
    do
        ver1[i]=0
    done
    for ((i=0; i<${#ver1[@]}; i++))
    do
        if [[ -z ${ver2[i]} ]]
        then
            ver2[i]=0
        fi
        if ((10#${ver1[i]} > 10#${ver2[i]}))
        then
            return 1
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]}))
        then
            return 2
        fi
    done
    return 0
}

# Get current version
CURRENT_VERSION=$(cat ../web/reNgine/version.txt)

# Get latest release version from GitHub
LATEST_VERSION=$(curl -s https://api.github.com/repos/Security-Tools-Alliance/rengine-ng/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | sed 's/v//')

cat ../web/art/reNgine.txt

log "\n" $COLOR_DEFAULT
log "Current version: $CURRENT_VERSION" $COLOR_CYAN
log "Latest version: $LATEST_VERSION" $COLOR_CYAN
log "\n" $COLOR_DEFAULT

# Compare versions
version_compare $CURRENT_VERSION $LATEST_VERSION
case $? in
  0) log "You are already on the latest version." $COLOR_GREEN
     #exit 0
     ;;
  1) log "Your version is newer than the latest release. No update needed." $COLOR_YELLOW
     #exit 0
     ;;
  2) log "An update is available." $COLOR_CYAN
     ;;
esac

read -p "Do you want to update to the latest version? (y/n) " answer

if [[ $answer == "y" ]]; then
  read -p "Do you want to update from prebuilt images or build from source? (prebuilt/source) " install_type
  read -p "Do you want to apply your local changes after updating? (y/n) " apply_changes

  cd ..
  if [[ $apply_changes == "y" ]]; then
    make down && git stash save && git pull && git stash apply
    if [[ $install_type == "prebuilt" ]]; then
      make pull_up
    elif [[ $install_type == "source" ]]; then
      make build_up
    else
      log "Invalid installation type. Update cancelled." $COLOR_RED
      exit 1
    fi
    log "Successfully updated to version $LATEST_VERSION and local changes have been reapplied" $COLOR_GREEN
  elif [[ $apply_changes == "n" ]]; then
    make down && git stash && git stash drop && git pull
    if [[ $install_type == "prebuilt" ]]; then
      make pull_up
    elif [[ $install_type == "source" ]]; then
      make build_up
    else
      log "Invalid installation type. Update cancelled." $COLOR_RED
      exit 1
    fi
    log "Successfully updated to version $LATEST_VERSION" $COLOR_GREEN
  else
    log "Invalid input. Update cancelled." $COLOR_RED
    exit 1
  fi
else
  log "Update cancelled." $COLOR_YELLOW
fi