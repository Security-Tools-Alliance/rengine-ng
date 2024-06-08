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

cat ../web/art/reNgine.txt

log ""
log "Uninstalling reNgine-ng..." $COLOR_CYAN

# Check for root privileges
if [ "$(whoami)" != "root" ]
  then
  log ""
  log "Error uninstalling reNgine-ng: please run this script as root!" $COLOR_RED
  log "Example: sudo ./uninstall.sh" $COLOR_RED
  exit
fi

log ""

tput setaf 1
read -p "This action will stop and remove all containers, volumes and networks of reNgine-ng. Do you want to continue? [y/n] " -n 1
log ""

if [[ $REPLY =~ ^[Yy]$ ]]
then
  log ""

  log "Stopping reNgine-ng..." $COLOR_CYAN
  docker stop rengine-web-1 rengine-db-1 rengine-celery-1 rengine-celery-beat-1 rengine-redis-1 rengine-proxy-1
  log "Stopped reNgine-ng" $COLOR_GREEN
  log ""

  log "Removing all containers related to reNgine-ng..." $COLOR_CYAN
  docker rm rengine-web-1 rengine-db-1 rengine-celery-1 rengine-celery-beat-1 rengine-redis-1 rengine-proxy-1
  log "Removed all containers related to reNgine-ng" $COLOR_GREEN
  log ""

  log "Removing all volumes related to reNgine-ng..." $COLOR_CYAN
  docker volume rm rengine_gf_patterns rengine_github_repos rengine_nuclei_templates rengine_postgres_data rengine_scan_results rengine_tool_config rengine_static_volume rengine_wordlist
  log "Removed all volumes related to reNgine-ng" $COLOR_GREEN
  log ""

  log "Removing all networks related to reNgine-ng..." $COLOR_CYAN
  docker network rm rengine_rengine_network rengine_default
  log "Removed all networks related to reNgine-ng" $COLOR_GREEN
  log ""
else
  log ""
  log "Exiting!" $COLOR_DEFAULT
  exit 1
fi

tput setaf 1;
read -p "Do you want to remove Docker images related to reNgine-ng? [y/n] " -n 1 -r
log ""

if [[ $REPLY =~ ^[Yy]$ ]]
then
  log ""
  log "Removing all Docker images related to reNgine-ng..." $COLOR_CYAN
  docker image rm rengine-celery rengine-celery-beat rengine-certs docker.pkg.github.com/yogeshojha/rengine/rengine nginx:alpine redis:alpine postgres:12.3-alpine
  log "Removed all Docker images" $COLOR_GREEN
  log ""
else
  log ""
  log "Skipping removal of Docker images" $COLOR_CYAN
fi

tput setaf 1;
read -p "Do you want to remove all Docker-related leftovers? [y/n] " -n 1 -r
log ""

if [[ $REPLY =~ ^[Yy]$ ]]
then
  log ""
  log "Removing all Docker-related leftovers..." $COLOR_CYAN
  docker system prune -a -f
  log "Removed all Docker-related leftovers" $COLOR_GREEN
  log ""
else
  log ""
  log "Skipping removal of Docker-related leftovers..." $COLOR_CYAN
  log ""
fi

log "Finished uninstalling." $COLOR_GREEN
