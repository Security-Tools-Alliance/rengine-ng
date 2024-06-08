#!/bin/bash

tput setaf 2;
cat ../web/art/reNgine.txt

tput setaf 3;
log ""
log "Uninstalling reNGine"

if [ "$EUID" -ne 0 ]
  then
  log ""
  log "Error uninstalling reNGine, Please run this script as root!"
  log "Example: sudo ./uninstall.sh"
  exit
fi

tput setaf 1;
log ""
read -p "This action will stop and remove all containers, volumes and networks of reNGine. Do you want to continue? [y/n] " -n 1 -r
log ""

if [[ $REPLY =~ ^[Yy]$ ]]
then
  log ""
  tput setaf 3;
  log "Stopping reNGine"
  tput setaf 4;
  docker stop rengine-web-1 rengine-db-1 rengine-celery-1 rengine-celery-beat-1 rengine-redis-1 rengine-proxy-1
  tput setaf 3;
  log "Stopped reNGine"
  log ""

  log "Removing all containers related to reNGine"
  tput setaf 4;
  docker rm rengine-web-1 rengine-db-1 rengine-celery-1 rengine-celery-beat-1 rengine-redis-1 rengine-proxy-1
  tput setaf 3;
  log "Removed all containers related to reNGine"
  log ""

  log "Removing all volumes related to reNGine"
  tput setaf 4;
  docker volume rm rengine_gf_patterns rengine_github_repos rengine_nuclei_templates rengine_postgres_data rengine_scan_results rengine_tool_config rengine_static_volume rengine_wordlist
  tput setaf 3;
  log "Removed all volumes related to reNGine"
  log ""

  log "Removing all networks related to reNGine"
  tput setaf 4;
  docker network rm rengine_rengine_network rengine_default
  tput setaf 3;
  log "Removed all networks related to reNGine"
  log ""
else
  tput setaf 2;
  log ""
  log "Exiting!"
  exit 1
fi

tput setaf 1;
read -p "Do you want to remove Docker images related to reNGine? [y/n] " -n 1 -r
log ""

if [[ $REPLY =~ ^[Yy]$ ]]
then
  log ""
  tput setaf 3;
  log "Removing all Docker images related to reNGine"
  tput setaf 4;
  docker image rm rengine-celery rengine-celery-beat rengine-certs docker.pkg.github.com/yogeshojha/rengine/rengine nginx:alpine redis:alpine postgres:12.3-alpine
  tput setaf 3;
  log "Removed all Docker images"
  log ""
else
  tput setaf 2;
  log ""
  log "Skipping removal of Docker images"
fi

tput setaf 1;
read -p "Do you want to remove all Docker-related leftovers? [y/n] " -n 1 -r
log ""

if [[ $REPLY =~ ^[Yy]$ ]]
then
  log ""
  tput setaf 3;
  log "Removing all Docker-related leftovers"
  tput setaf 4;
  docker system prune -a -f
  tput setaf 3;
  log "Removed all Docker-related leftovers"
  log ""
else
  log ""
  log "Skipping removal of Docker-related leftovers"
  log ""
fi


tput setaf 2;
log "Finished uninstalling."
