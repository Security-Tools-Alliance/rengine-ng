#!/bin/bash

# Import common functions
source "$(pwd)/scripts/common_functions.sh" # Open the file if you want to know the meaning of each color

# Import GPU support script
source "$(pwd)/scripts/gpu_support.sh"

# Fetch the internal and external IP address
external_ip=$(curl -s https://ipecho.net/plain)
internal_ips=$(ip -4 -br addr | awk '$2 == "UP" {print $3} /^lo/ {print $3}' | cut -d'/' -f1)
formatted_ips=""
for ip in $internal_ips; do
    formatted_ips="${formatted_ips}https://$ip\n"
done

# Check Docker installation
check_docker_installation() {
  while true; do
    log "Docker is not installed. You have two options for installation:" $COLOR_CYAN
    log "1) Docker Desktop: A user-friendly application with a GUI, suitable for developers. It includes Docker Engine, Docker CLI, Docker Compose, and other tools." $COLOR_GREEN
    log "2) Docker Engine: A lightweight, command-line interface suitable for servers and advanced users. It's the core of Docker without additional GUI tools." $COLOR_GREEN
    
    read -p "Enter your choice (1 or 2): " docker_choice

    case $docker_choice in
      1)
        log "Please install Docker Desktop from: https://docs.docker.com/desktop/" $COLOR_YELLOW
        break
        ;;
      2)
        log "Please install Docker Engine from: https://docs.docker.com/engine/install/" $COLOR_YELLOW
        break
        ;;
      *)
        log "Invalid choice. Please choose 1 or 2." $COLOR_RED
        ;;
    esac
  done

  log "After installation, please restart this script." $COLOR_CYAN
  exit 1
}

# Check Docker version and status
check_docker() {
  local min_version="20.10.0"
  log "Checking Docker installation (minimum required version: $min_version)..." $COLOR_CYAN

  if ! command -v docker &> /dev/null; then
    check_docker_installation
  fi

  if ! DOCKER_ERROR=$(docker info 2>&1); then
    echo "Docker check failed: ${DOCKER_ERROR}"
    log "Docker is not running. Please start Docker and try again." $COLOR_RED
    log "You can start Docker using: sudo systemctl start docker (on most Linux systems)" $COLOR_YELLOW
    exit 1
  fi

  local version=$(docker version --format '{{.Server.Version}}')

  if ! [[ "$(printf '%s\n' "$min_version" "$version" | sort -V | head -n1)" = "$min_version" ]]; then
    log "Docker version $version is installed, but reNgine-ng requires version $min_version or higher." $COLOR_RED
    log "Please upgrade Docker to continue. Visit https://docs.docker.com/engine/install/ for installation instructions." $COLOR_YELLOW
    exit 1
  fi

  log "Docker version $version is installed and running." $COLOR_GREEN
  log "It's recommended to use the latest version of Docker. Check https://docs.docker.com/engine/release-notes/ for updates." $COLOR_YELLOW
}

# Check Docker Compose version and set the appropriate command
check_docker_compose() {
  local min_version="2.2.0"
  log "Checking Docker Compose installation (minimum required version: $min_version)..." $COLOR_CYAN

  if command -v docker &> /dev/null && docker compose version &> /dev/null; then
    DOCKER_COMPOSE="docker compose"
  elif command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
  else
    if docker compose version 2>&1 | grep -q "is not a docker command"; then
      log "Docker Compose is not installed. Please install Docker Compose v$min_version or later from https://docs.docker.com/compose/install/" $COLOR_RED
      log "After installation, please restart this script." $COLOR_CYAN
      exit 1
    else
      log "An unexpected error occurred while checking for Docker Compose. Please ensure Docker and Docker Compose are correctly installed." $COLOR_RED
      exit 1
    fi
  fi

  local version=$($DOCKER_COMPOSE version --short)

  if ! [[ "$(printf '%s\n' "$min_version" "$version" | sort -V | head -n1)" = "$min_version" ]]; then
    log "Docker Compose version $version is installed, but reNgine-ng requires version $min_version or higher." $COLOR_RED
    log "Please upgrade Docker Compose to continue. Visit https://docs.docker.com/compose/install/ for installation instructions." $COLOR_YELLOW
    log "After upgrade, please restart this script." $COLOR_CYAN
    exit 1
  fi

  log "Using Docker Compose command: $DOCKER_COMPOSE (version $version)" $COLOR_GREEN
  log "It's recommended to use the latest version of Docker Compose. Check https://docs.docker.com/compose/release-notes/ for updates." $COLOR_YELLOW
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

# Check GPU support and install required dependencies
check_gpu_support() {
    log "Checking for GPU support..." $COLOR_CYAN
    
    # Execute GPU detection with error handling
    if ! GPU_TYPE=$(./scripts/gpu_support.sh 2>/dev/null); then
        log "GPU detection script failed, continuing with CPU-only setup" $COLOR_YELLOW
        # Add default GPU configuration
        {
            echo "GPU=0"
            echo "GPU_TYPE=none"
            echo "DOCKER_RUNTIME=none"
        } >> .env
        return 1
    fi
    
    # Validate GPU_TYPE output
    if [[ ! "$GPU_TYPE" =~ ^(nvidia|amd|none)$ ]]; then
        log "Invalid GPU type detected: $GPU_TYPE, continuing with CPU-only setup" $COLOR_YELLOW
        # Add default GPU configuration
        {
            echo "GPU=0"
            echo "GPU_TYPE=none"
            echo "DOCKER_RUNTIME=none"
        } >> .env
        return 1
    fi
    
    case $GPU_TYPE in
        "nvidia")
            log "NVIDIA GPU detected" $COLOR_GREEN
            if ! command -v nvidia-container-toolkit &> /dev/null; then
                log "Installing NVIDIA Container Toolkit..." $COLOR_CYAN
                
                # Add NVIDIA repository key
                if ! curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg; then
                    log "Failed to add NVIDIA repository key" $COLOR_RED
                    return 1
                fi
                
                # Add NVIDIA repository
                if ! curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | \
                    sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | \
                    sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list > /dev/null; then
                    log "Failed to add NVIDIA repository" $COLOR_RED
                    return 1
                fi
                
                # Update package list
                if ! sudo apt-get update; then
                    log "Failed to update package list" $COLOR_RED
                    return 1
                fi
                
                # Install NVIDIA Container Toolkit
                if ! sudo apt-get install -y nvidia-container-toolkit; then
                    log "Failed to install NVIDIA Container Toolkit" $COLOR_RED
                    return 1
                fi
                
                # Configure Docker runtime
                if ! sudo nvidia-ctk runtime configure --runtime=docker; then
                    log "Failed to configure Docker runtime for NVIDIA" $COLOR_RED
                    return 1
                fi
                
                # Restart Docker service
                if ! sudo systemctl restart docker; then
                    log "Failed to restart Docker service" $COLOR_RED
                    return 1
                fi
                
                log "NVIDIA Container Toolkit installed successfully" $COLOR_GREEN
            fi
            return 0
            ;;
            
        "amd")
            log "AMD GPU detected" $COLOR_GREEN
            if ! command -v amdgpu-install &> /dev/null; then
                log "Installing ROCm..." $COLOR_CYAN
                
                # Add ROCm repository key
                if ! curl -fsSL https://repo.radeon.com/rocm/rocm.gpg.key | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/rocm.gpg; then
                    log "Failed to add ROCm repository key" $COLOR_RED
                    return 1
                fi
                
                # Add ROCm repository
                if ! echo "deb [arch=amd64] https://repo.radeon.com/rocm/apt/debian ubuntu main" | sudo tee /etc/apt/sources.list.d/rocm.list > /dev/null; then
                    log "Failed to add ROCm repository" $COLOR_RED
                    return 1
                fi
                
                # Update package list
                if ! sudo apt-get update; then
                    log "Failed to update package list" $COLOR_RED
                    return 1
                fi
                
                # Install ROCm
                if ! sudo apt-get install -y rocm-dev; then
                    log "Failed to install ROCm" $COLOR_RED
                    return 1
                fi
                
                # Configure user groups
                if ! sudo usermod -aG render $USER || ! sudo usermod -aG video $USER; then
                    log "Failed to configure user groups" $COLOR_RED
                    return 1
                fi
                
                log "ROCm installed successfully" $COLOR_GREEN
            fi
            return 0
            ;;
            
        *)
            log "No supported GPU detected, continuing with CPU-only setup" $COLOR_YELLOW
            return 1
            ;;
    esac
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

  log "\r\nBefore running this script, please make sure Docker is installed and running, and you have made changes to the '.env' file." $COLOR_RED
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

  log "Checking and installing reNgine-ng prerequisites..." $COLOR_CYAN

  install_curl
  install_make
  check_docker
  check_docker_compose

  # Add GPU support check here
  if check_gpu_support; then
    if [ $isNonInteractive = true ]; then
        # Load existing GPU configuration from .env
        if [ -f .env ]; then
            GPU_ENABLED=$(grep "^GPU=" .env | cut -d '=' -f2)
            if [ "$GPU_ENABLED" = "1" ]; then
                # Remove existing GPU-related configurations
                sed -i '/^GPU=/d' .env
                sed -i '/^GPU_TYPE=/d' .env
                sed -i '/^DOCKER_RUNTIME=/d' .env
                
                # Add GPU configuration to environment
                {
                    echo "GPU=1"
                    echo "GPU_TYPE=$GPU_TYPE"
                    echo "DOCKER_RUNTIME=$GPU_TYPE"
                } >> .env
                log "GPU support has been enabled from existing configuration" $COLOR_GREEN
            else
                log "GPU support is disabled in .env" $COLOR_YELLOW
            fi
        fi
    else
        log "Do you want to enable GPU support for Ollama? (recommended for better LLM performance) [y/n] " $COLOR_CYAN
        read -p "" gpu_choice
        case $gpu_choice in
            [Yy]* )
                # Remove existing GPU-related configurations
                sed -i '/^GPU=/d' .env
                sed -i '/^GPU_TYPE=/d' .env
                sed -i '/^DOCKER_RUNTIME=/d' .env
                
                # Add GPU configuration to environment
                {
                    echo "GPU=1"
                    echo "GPU_TYPE=$GPU_TYPE"
                    echo "DOCKER_RUNTIME=$GPU_TYPE"
                } >> .env
                log "GPU support will be enabled" $COLOR_GREEN
                ;;
            * )
                # Remove existing GPU-related configurations
                sed -i '/^GPU=/d' .env
                sed -i '/^GPU_TYPE=/d' .env
                sed -i '/^DOCKER_RUNTIME=/d' .env
                # Add default GPU configuration
                {
                    echo "GPU=0"
                    echo "GPU_TYPE=none"
                    echo "DOCKER_RUNTIME=none"
                } >> .env
                log "Continuing without GPU support" $COLOR_YELLOW
                ;;
        esac
    fi
  fi

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
    log "1) From source" $COLOR_YELLOW
    log "2) Use pre-built images (default)" $COLOR_YELLOW
    read -p "Enter your choice (1 or 2, default is 2): " choice

    case $choice in
        1)
            INSTALL_TYPE="source"
            ;;
        2|"")
            INSTALL_TYPE="prebuilt"
            ;;
        *)
            log "Invalid choice. Defaulting to pre-built images." $COLOR_RED
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
