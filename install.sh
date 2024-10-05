#!/bin/bash

# Import common functions
source "$(pwd)/scripts/common_functions.sh"

# Fetch the internal and external IP address
external_ip=$(curl -s https://ipecho.net/plain)
internal_ips=$(ip -4 -br addr | awk '$2 == "UP" {print $3} /^lo/ {print $3}' | cut -d'/' -f1)
formatted_ips=""
for ip in $internal_ips; do
    formatted_ips="${formatted_ips}https://$ip\n"
done

# Check Docker Compose version and set the appropriate command
check_docker_compose() {
  if command -v docker &> /dev/null && docker compose version &> /dev/null; then
    DOCKER_COMPOSE="docker compose"
  elif command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
  else
    log "Docker Compose is not installed. Please install Docker Compose and try again." $COLOR_RED
    exit 1
  fi

  # Check Docker Compose version
  local version=$($DOCKER_COMPOSE version --short)
  if [[ $(echo $version | cut -d. -f1) -lt 2 ]]; then
    log "Docker Compose version $version is not supported. Please upgrade to version 2.0.0 or higher." $COLOR_RED
    exit 1
  fi

  log "Using Docker Compose command: $DOCKER_COMPOSE" $COLOR_GREEN
  export DOCKER_COMPOSE
}

# Generic function to install a package
install_package() {
  local package_name="$1"
  log "Installing $package_name..." $COLOR_CYAN
  if ! command -v "$package_name" &> /dev/null; then
    . /etc/os-release
    DISTRO_FAMILY="${ID_LIKE:-$ID}"
    case "$DISTRO_FAMILY" in
      *debian*) sudo apt update && sudo apt install -y "$package_name" ;;
      *fedora*|*centos*|*rhel*) sudo dnf install -y "$package_name" ;;
      *arch*) sudo pacman -Sy "$package_name" ;;
      *suse*|*opensuse*) sudo zypper install -y "$package_name" ;;
      *) log "Unsupported Linux distribution: $DISTRO_FAMILY. Please install $package_name manually." $COLOR_RED; return 1 ;;
    esac
    if [ $? -eq 0 ]; then
      log "$package_name installed successfully!" $COLOR_GREEN
    else
      log "Failed to install $package_name. Please check your internet connection and try again." $COLOR_RED
      log "If the problem persists, try installing $package_name manually." $COLOR_YELLOW
      return 1
    fi
  else
    log "$package_name is already installed, skipping." $COLOR_GREEN
  fi
}

# Install nano text editor
install_nano() {
  install_package "nano"
}

# Install curl for downloading files
install_curl() {
  install_package "curl"
}

# Install make for building projects
install_make() {
  install_package "make"
}

# Install Docker
install_docker() {
  log "Installing Docker..." $COLOR_CYAN
  if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    if sudo sh get-docker.sh; then
      sudo usermod -aG docker $USER
      rm get-docker.sh
      log "Docker installed successfully!" $COLOR_GREEN
    else
      log "Failed to install Docker. Please check https://docs.docker.com/engine/install/ for manual installation instructions." $COLOR_RED
      return 1
    fi
  else
    log "Docker is already installed, skipping." $COLOR_GREEN
  fi
}

# Install Docker Compose
install_docker_compose() {
  log "Installing Docker Compose..." $COLOR_CYAN
  if ! command -v docker-compose &> /dev/null && ! (command -v docker &> /dev/null && docker compose version &> /dev/null); then
    sudo curl -L "https://github.com/docker/compose/releases/download/latest/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    if docker-compose --version &> /dev/null; then
      log "Docker Compose installed successfully!" $COLOR_GREEN
    else
      log "Failed to install Docker Compose. Please check https://docs.docker.com/compose/install/ for manual installation instructions." $COLOR_RED
      return 1
    fi
  else
    log "Docker Compose is already installed, skipping." $COLOR_GREEN
  fi
}

# Check for root privileges
if [ $EUID -eq 0 ]; then
  if [ "$SUDO_USER" = "root" ] || [ "$SUDO_USER" = "" ]; then
    log "Error: Do not run this script as root user. Use 'sudo' with a non-root user." $COLOR_RED
    log "Example: 'sudo ./install.sh'" $COLOR_RED
    exit 1
  fi
fi

# Check if the script is run with sudo
if [ -z "$SUDO_USER" ]; then
  log "Error: This script must be run with sudo." $COLOR_RED
  log "Example: 'sudo ./install.sh'" $COLOR_RED
  exit 1
fi

# Check that the project directory is not owned by root
project_dir=$(pwd)
if [ "$(stat -c '%U' $project_dir)" = "root" ]; then
  log "The project directory is owned by root. Changing ownership..." $COLOR_YELLOW
  sudo chown -R $SUDO_USER:$SUDO_USER $project_dir
  if [ $? -eq 0 ]; then
    log "Project directory ownership successfully changed." $COLOR_GREEN
  else
    log "Failed to change project directory ownership." $COLOR_RED
    exit 1
  fi
fi

usageFunction()
{
  log "Usage: $0 (-n) (-h)" $COLOR_GREEN
  log "\t-n Non-interactive installation (Optional)" $COLOR_GREEN
  log "\t-h Show usage" $COLOR_GREEN
  exit 1
}

# Main installation process
main() {
  cat web/art/reNgine.txt

  log "\r\nBefore running this script, please make sure Docker is running and you have made changes to the '.env' file." $COLOR_RED
  log "Changing the PostgreSQL username & password in the '.env' is highly recommended.\r\n" $COLOR_RED

  log "Please note that this installation script is only intended for Linux" $COLOR_RED
  log "x86_64 and arm64 platform (compatible with Apple Mx series) are supported" $COLOR_RED

  log "Raspberry Pi is not recommended, all install tests have failed" $COLOR_RED
  log ""
  tput setaf 1;

  isNonInteractive=false
  while getopts nh opt; do
     case $opt in
        n) isNonInteractive=true ;;
        h) usageFunction ;;
        ?) usageFunction ;;
     esac
  done

  log "Installing reNgine-ng and its dependencies..." $COLOR_CYAN

  install_curl
  install_docker
  install_docker_compose
  install_make
  check_docker_compose

  if [ $isNonInteractive = false ]; then
    read -p "Are you sure you made changes to the '.env' file (y/n)? " answer
    case ${answer:0:1} in
        y|Y|yes|YES|Yes )
          log "\nContinuing installation!\n" $COLOR_GREEN
        ;;
        * )
          install_nano
          nano .env
        ;;
    esac

    log "Do you want to build Docker images from source or use pre-built images (recommended)? \nThis saves significant build time but requires good download speeds for it to complete fast." $COLOR_RED
    log "1) From source" $COLOR_GREEN
    log "2) Use pre-built images (default)" $COLOR_GREEN
    read -p "Enter your choice (1 or 2, default is 2): " choice

    case $choice in
        1)
            INSTALL_TYPE="source"
            ;;
        2|"")
            INSTALL_TYPE="prebuilt"
            ;;
        *)
            log "Invalid choice. Defaulting to pre-built images." $COLOR_YELLOW
            INSTALL_TYPE="prebuilt"
            ;;
    esac

    log "Selected installation type: $INSTALL_TYPE" $COLOR_CYAN
  fi

  # Non-interactive install
  if [ $isNonInteractive = true ]; then
    # Load and verify .env file
    if [ -f .env ]; then
        export $(grep -v '^#' .env | xargs)
    else
        log "Error: .env file not found, copy/paste the .env-dist file to .env and edit it" $COLOR_RED
        exit 1
    fi

    if [ -z "$DJANGO_SUPERUSER_USERNAME" ] || [ -z "$DJANGO_SUPERUSER_EMAIL" ] || [ -z "$DJANGO_SUPERUSER_PASSWORD" ]; then
      log "Error: DJANGO_SUPERUSER_USERNAME, DJANGO_SUPERUSER_EMAIL, and DJANGO_SUPERUSER_PASSWORD must be set in .env for non-interactive installation" $COLOR_RED
      exit 1
    fi

    INSTALL_TYPE=${INSTALL_TYPE:-prebuilt}
    log "Non-interactive installation parameter set. Installation begins." $COLOR_GREEN
  fi

  log "Checking Docker status..." $COLOR_CYAN
  if docker info >/dev/null 2>&1; then
    log "Docker is running." $COLOR_GREEN
  else
    log "Docker is not running. Please run Docker and try again." $COLOR_RED
    log "You can run Docker service using: sudo systemctl start docker" $COLOR_RED
    exit 1
  fi

  if [ -z "$INSTALL_TYPE" ]; then
    log "Error: INSTALL_TYPE is not set" $COLOR_RED
    exit 1
  elif [ "$INSTALL_TYPE" != "prebuilt" ] && [ "$INSTALL_TYPE" != "source" ]; then
    log "Error: INSTALL_TYPE must be either 'prebuilt' or 'source'" $COLOR_RED
    exit 1
  fi

  log "Installing reNgine-ng from $INSTALL_TYPE, please be patient as the installation could take a while..." $COLOR_CYAN
  sleep 5

  log "Generating certificates..." $COLOR_CYAN
  make certs && log "Certificates have been generated" $COLOR_GREEN || { log "Certificate generation failed!" $COLOR_RED; exit 1; }

  if [ "$INSTALL_TYPE" = "source" ]; then
    log "Building Docker images..." $COLOR_CYAN
    make build && log "Docker images have been built" $COLOR_GREEN || { log "Docker images build failed!" $COLOR_RED; exit 1; }
  fi

  if [ "$INSTALL_TYPE" = "prebuilt" ]; then
    log "Pulling pre-built Docker images..." $COLOR_CYAN
    make pull && log "Docker images have been pulled" $COLOR_GREEN || { log "Docker images pull failed!" $COLOR_RED; exit 1; }
  fi

  log "Docker containers starting, please wait as starting the Celery container could take a while..." $COLOR_CYAN
  sleep 5
  make up && log "reNgine-ng is started!" $COLOR_GREEN || { log "reNgine-ng start failed!" $COLOR_RED; exit 1; }

  log "Creating an account..." $COLOR_CYAN
  make superuser_create isNonInteractive=$isNonInteractive

  log "reNgine-ng is successfully installed and started!" $COLOR_GREEN
  log "\r\nThank you for installing reNgine-ng, happy recon!" $COLOR_GREEN

  log "\r\nIn case you're running this locally, reNgine-ng should be available at one of the following IPs:\n$formatted_ips" $COLOR_GREEN
  log "In case you're running this on a server, reNgine-ng should be available at: https://$external_ip/" $COLOR_GREEN
}

# Run the main installation process
main