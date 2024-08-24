#!/bin/bash

# Import common functions
source "$(pwd)/common_functions.sh"

cat ../web/art/reNgine.txt

# Check for root privileges
if [ "$(whoami)" != "root" ]
  then
  log ""
  log "Error uninstalling reNgine-ng: please run this script as root!" $COLOR_RED
  log "Example: sudo ./uninstall.sh" $COLOR_RED
  exit
fi

log ""
log "Uninstalling reNgine-ng..." $COLOR_CYAN
log ""

tput setaf $COLOR_RED;
read -p "This action will stop and remove all containers, volumes and networks of reNgine-ng. Do you want to continue? [y/n] " -n 1
log ""

if [[ $REPLY =~ ^[Yy]$ ]]
then
  log ""

  log "Stopping reNgine-ng..." $COLOR_CYAN
  if (cd .. && make down); then
    log "Stopped reNgine-ng" $COLOR_GREEN
  else
    log "Failed to stop reNgine-ng" $COLOR_RED
    exit 1
  fi
  log ""

  log "Removing all volumes related to reNgine-ng..." $COLOR_CYAN
  if docker volume rm $(docker volume ls -q --filter name=rengine_) 2>/dev/null || true; then
    log "Removed all volumes related to reNgine-ng" $COLOR_GREEN
  else
    log "Warning: Failed to remove some or all volumes" $COLOR_YELLOW
  fi
  log ""

  log "Removing all networks related to reNgine-ng..." $COLOR_CYAN
  if docker network rm rengine_network; then
    log "Removed all networks related to reNgine-ng" $COLOR_GREEN
  else
    log "Warning: Failed to remove rengine_network" $COLOR_YELLOW
  fi
  log ""
else
  log ""
  log "Exiting!" $COLOR_DEFAULT
  exit 1
fi

tput setaf $COLOR_RED;
read -p "Do you want to remove Docker images related to reNgine-ng? [y/n] " -n 1 -r
log ""

if [[ $REPLY =~ ^[Yy]$ ]]
then
  log ""
  log "Removing all Docker images related to reNgine-ng..." $COLOR_CYAN
  if (cd .. && make remove_images); then
    log "Removed all Docker images" $COLOR_GREEN
  else
    log "Warning: Failed to remove some or all Docker images" $COLOR_YELLOW
  fi
  log ""
else
  log ""
  log "Skipping removal of Docker images" $COLOR_CYAN
fi

tput setaf $COLOR_RED;
read -p "Do you want to remove all Docker-related leftovers? [y/n] " -n 1 -r
log ""

if [[ $REPLY =~ ^[Yy]$ ]]
then
  log ""
  log "Removing all Docker-related leftovers..." $COLOR_CYAN
  if docker system prune -a -f; then
    log "Removed all Docker-related leftovers" $COLOR_GREEN
  else
    log "Warning: Failed to remove some or all Docker-related leftovers" $COLOR_YELLOW
  fi
  log ""
else
  log ""
  log "Skipping removal of Docker-related leftovers..." $COLOR_CYAN
  log ""
fi

log "Finished uninstalling." $COLOR_GREEN