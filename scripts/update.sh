#!/bin/bash

# Import common functions
source "$(pwd)/common_functions.sh"

# Check for root privileges
if [ "$(whoami)" != "root" ]; then
  log "Error updating reNgine-ng: please run this script as root!" $COLOR_RED
  log "Example: sudo ./update.sh" $COLOR_RED
  exit 1
fi

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

# Compare versions
version_compare $CURRENT_VERSION $LATEST_VERSION
comparison_result=$?

log "\n" $COLOR_DEFAULT
log "Current version: $CURRENT_VERSION" $COLOR_CYAN
log "Latest version: $LATEST_VERSION" $COLOR_CYAN
log "\n" $COLOR_DEFAULT

case $comparison_result in
  0) log "You are already on the latest version." $COLOR_GREEN
     exit 0
     ;;
  1) log "Your version is newer than the latest release. No update needed." $COLOR_YELLOW
     exit 0
     ;;
  2) log "An update is available." $COLOR_CYAN
     ;;
  *) log "Error comparing versions." $COLOR_RED
     exit 1
     ;;
esac

read -p "Do you want to update to the latest version? (y/n) " answer

if [[ $answer == "y" ]]; then
  while true; do
    read -p "Do you want to update from pre-built images or build from source? (pre-built/source, default is pre-built): " install_type
    install_type=${install_type:-pre-built}  # Set default to pre-built if empty
    if [[ $install_type == "pre-built" || $install_type == "source" ]]; then
      break
    else
      log "Invalid input. Please enter 'pre-built' or 'source'." $COLOR_YELLOW
    fi
  done

  log "Selected installation type: $install_type" $COLOR_CYAN

  while true; do
    read -p "Do you want to apply your local changes after updating? (y/n) " apply_changes
    if [[ $apply_changes == "y" || $apply_changes == "n" ]]; then
      break
    else
      log "Invalid input. Please enter 'y' or 'n'." $COLOR_YELLOW
    fi
  done
  
  if [[ $apply_changes == "y" ]]; then
    if ! (cd .. && make down); then
      log "Failed to stop reNgine-ng" $COLOR_RED
      exit 1
    fi
    if ! sudo -u rengine git stash save && sudo -u rengine git pull && sudo -u rengine git stash apply; then
      log "Failed to update and apply local changes" $COLOR_RED
      exit 1
    fi
    if [[ $install_type == "pre-built" ]]; then
      if ! (cd .. && make up); then
        log "Failed to pull and start updated images" $COLOR_RED
        exit 1
      fi
    elif [[ $install_type == "source" ]]; then
      if ! (cd .. && make build_up); then
        log "Failed to build and start updated images" $COLOR_RED
        exit 1
      fi
    fi
    log "Successfully updated to version $LATEST_VERSION and local changes have been reapplied" $COLOR_GREEN
  elif [[ $apply_changes == "n" ]]; then
    if ! (cd .. && make down); then
      log "Failed to stop reNgine-ng" $COLOR_RED
      exit 1
    fi
    if ! sudo -u rengine git stash && sudo -u rengine git stash drop && sudo -u rengine git pull; then
      log "Failed to update" $COLOR_RED
      exit 1
    fi
    if [[ $install_type == "pre-built" ]]; then
      if ! (cd .. && make up); then
        log "Failed to pull and start updated images" $COLOR_RED
        exit 1
      fi
    elif [[ $install_type == "source" ]]; then
      if ! (cd .. && make build_up); then
        log "Failed to build and start updated images" $COLOR_RED
        exit 1
      fi
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