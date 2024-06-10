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

cat web/art/reNgine.txt

log "\r\nBefore running this script, please make sure Docker is running and you have made changes to the '.env' file." $COLOR_RED
log "Changing the PostgreSQL username & password in the '.env' is highly recommended.\r\n" $COLOR_RED

log "Please note that this installation script is only intended for Linux" $COLOR_RED
log "Only x86_64 platform are supported" $COLOR_RED

log ""
tput setaf 1;
read -p "Are you sure you made changes to the '.env' file (y/n)? " answer
case ${answer:0:1} in
    y|Y|yes|YES|Yes )
      log "\nContinuing installation!\n" $COLOR_GREEN
    ;;
    * )
      if ! command -v nano &> /dev/null; then
        . /etc/os-release
        case "$ID" in
          ubuntu|debian) sudo apt update && sudo apt install -y nano ;;
          fedora) sudo dnf install -y nano ;;
          centos|rhel) sudo yum install -y nano ;;
          arch) sudo pacman -Sy nano ;;
          opensuse|suse) sudo zypper install -y nano ;;
          *) log "Unsupported Linux distribution. Please install nano manually." $COLOR_RED; exit 1 ;;
        esac
        [ $? -eq 0 ] && log "nano installed!" $COLOR_GREEN || { log "Failed to install nano." $COLOR_RED; exit 1; }
      else
        log "nano already installed, skipping." $COLOR_GREEN
      fi
    nano .env
    ;;
esac

log "Installing reNgine-ng and its dependencies..." $COLOR_CYAN

log "Installing curl..." $COLOR_CYAN

if ! command -v curl &> /dev/null; then
  . /etc/os-release
  case "$ID" in
    ubuntu|debian) sudo apt update && sudo apt install -y curl ;;
    fedora) sudo dnf install -y curl ;;
    centos|rhel) sudo yum install -y curl ;;
    arch) sudo pacman -Sy curl ;;
    opensuse|suse) sudo zypper install -y curl ;;
    *) log "Unsupported Linux distribution. Please install curl manually." $COLOR_RED; exit 1 ;;
  esac
  [ $? -eq 0 ] && log "CURL installed!" $COLOR_GREEN || { log "Failed to install CURL." $COLOR_RED; exit 1; }
else
  log "CURL already installed, skipping." $COLOR_GREEN
fi

log "Installing Docker..." $COLOR_CYAN
if ! command -v docker 2> /dev/null; then
  curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh
  log "Docker installed!" $COLOR_GREEN
else
  log "Docker already installed, skipping." $COLOR_GREEN
fi

log "Installing Docker Compose..." $COLOR_CYAN
if ! command -v docker compose 2> /dev/null; then
  curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
  chmod +x /usr/local/bin/docker-compose
  ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
  log "Docker Compose installed!" $COLOR_GREEN
else
  log "Docker Compose already installed, skipping." $COLOR_GREEN
fi

if ! command -v make &> /dev/null; then
  . /etc/os-release
  case "$ID" in
    ubuntu|debian) sudo apt update && sudo apt install -y make ;;
    fedora) sudo dnf install -y make ;;
    centos|rhel) sudo yum install -y make ;;
    arch) sudo pacman -Sy make ;;
    opensuse|suse) sudo zypper install -y make ;;
    *) log "Unsupported Linux distribution. Please install make manually." $COLOR_RED; exit 1 ;;
  esac
  [ $? -eq 0 ] && log "make installed!" $COLOR_GREEN || { log "Failed to install make." $COLOR_RED; exit 1; }
else
  log "make already installed, skipping." $COLOR_GREEN
fi

log "Checking Docker status..." $COLOR_CYAN
if docker info >/dev/null 2>&1; then
  log "Docker is running." $COLOR_GREEN
else
  log "Docker is not running. Please run Docker and try again." $COLOR_RED
  log "You can run Docker service using: sudo systemctl start docker" $COLOR_RED
  exit 1
fi

log "Installing reNgine-ng, please be patient as it could take a while..." $COLOR_CYAN
sleep 5

log "Generating certificates and building Docker images..." $COLOR_CYAN
make certs && make build && log "reNgine-ng is built" $COLOR_GREEN || { log "reNgine-ng installation failed!" $COLOR_RED; exit 1; }

log "Docker containers starting, please wait as Celery container could take a while..." $COLOR_CYAN
sleep 5
make up && log "reNgine-ng is installed!" $COLOR_GREEN || { log "reNgine-ng installation failed!" $COLOR_RED; exit 1; }

log "Creating an account..." $COLOR_CYAN
make username

log "\r\nThank you for installing reNgine-ng, happy recon!" $COLOR_GREEN
