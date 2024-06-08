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

# Check for root privileges
if [ "$(whoami)" != "root" ]
  then
  log ""
  log "Error installing reNgine-ng: please run this script as root!" $COLOR_RED
  log "Example: sudo ./install.sh" $COLOR_RED
  exit
fi

log ""

log "\r\nBefore running this script, please make sure Docker is running and you have made changes to the .env file." $COLOR_RED
log "Changing the postgres username & password from .env is highly recommended.\r\n" $COLOR_RED

log "#########################################################################" $COLOR_CYAN
log "Please note that this installation script is only intended for Linux" $COLOR_CYAN
log "Only x86_64 platform are supported" $COLOR_CYAN
log "#########################################################################\r\n" $COLOR_CYAN

tput setaf 1;
read -p "Are you sure you made changes to the .env file (y/n)? " answer
case ${answer:0:1} in
    y|Y|yes|YES|Yes )
      log "Continuing installation...\n" $COLOR_CYAN
    ;;
    * )
      if [ -x "$(command -v nano)" ]; then
        log "nano already installed, skipping." $COLOR_CYAN
      else
        sudo apt update && sudo apt install nano -y
        log "nano installed!" $COLOR_GREEN
      fi
    nano .env
    ;;
esac

log "=========================================================================" 6
log "Installing reNgine-ng and its dependencies..." 6
log "=========================================================================" 6

log "\r\n#########################################################################" 6
log "Installing curl..." 6

if ! command -v curl 2> /dev/null; then
  apt update && apt install curl -y
  log "CURL installed!" 2
else
  log "CURL already installed, skipping." 2
fi


log "\r\n#########################################################################" 6
log "Installing Docker..." 6

if ! command -v docker 2> /dev/null; then
  curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh
  log "Docker installed!" 2
else
  log "Docker already installed, skipping." 2
fi

log "\r\n#########################################################################" 6
log "Installing Docker Compose..." 6

if ! command -v docker compose 2> /dev/null; then
  curl -L "https://github.com/docker/compose/releases/download/v2.27.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
  chmod +x /usr/local/bin/docker-compose
  ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
  log "Docker Compose installed!" 2
else
  log "Docker Compose already installed, skipping." 2
fi

log "\r\n#########################################################################" 6
log "Installing make..." 6

if ! command -v make 2> /dev/null; then
  apt install make -y
  log "make installed!" 2
else
  log "make already installed, skipping." 2
fi

log "\r\n#########################################################################" 6
log "Checking Docker status..." 6
if docker info >/dev/null 2>&1; then
  log "Docker is running." 2
else
  log "Docker is not running. Please run docker and try again." 1
  log "You can run Docker service using: sudo systemctl start docker" 1
  exit 1
fi

log "\r\n#########################################################################" 6
log "Installing reNgine-ng, please be patient as it could take a while..." 6
sleep 5

log "\r\n=========================================================================" 6
log "Generating certificates and building Docker images..." 6
log "=========================================================================" 6
make certs && make build && log "reNgine-ng is built" 2 || { log "reNgine-ng installation failed!" 1; exit 1; }

log "\r\n=========================================================================" 6
log "Docker containers starting, please wait as Celery container could take a while..." 6
sleep 5
log "=========================================================================" 6
make up && log "reNgine-ng is installed!" 2 || { log "reNgine-ng installation failed!" 1; exit 1; }


log "\r\n#########################################################################" 6
log "Creating an account..." 6
log "#########################################################################" 6
make username

log "\r\nThank you for installing reNgine-ng, happy recon!" 2
