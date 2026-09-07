#!/usr/bin/env bash

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

# Import common functions
source "$SCRIPT_DIR/scripts/common_functions.sh"

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

read_env_value() {
  local key=$1
  awk -v key="$key" '
    $0 !~ /^[[:space:]]*#/ && index($0, key "=") == 1 {
      sub(/^[^=]*=/, "")
      sub(/\r$/, "")
      print
      exit
    }
  ' .env
}

load_installer_env() {
  if [ ! -f .env ]; then
    log "Error: .env file not found. Copy .env-dist to .env and review its values before installing." "$COLOR_RED"
    return 1
  fi

  INSTALL_TYPE=$(read_env_value INSTALL_TYPE)
  GPU_ENABLED=$(read_env_value GPU)
  DJANGO_SUPERUSER_USERNAME=$(read_env_value DJANGO_SUPERUSER_USERNAME)
  DJANGO_SUPERUSER_EMAIL=$(read_env_value DJANGO_SUPERUSER_EMAIL)
  DJANGO_SUPERUSER_PASSWORD=$(read_env_value DJANGO_SUPERUSER_PASSWORD)

  export INSTALL_TYPE DJANGO_SUPERUSER_USERNAME DJANGO_SUPERUSER_EMAIL
  export DJANGO_SUPERUSER_PASSWORD
}

validate_required_env() {
  local key
  local value
  local postgres_user
  local pg_user
  local required_keys=(
    POSTGRES_DB
    POSTGRES_USER
    PGUSER
    POSTGRES_PASSWORD
    POSTGRES_HOST
  )

  for key in "${required_keys[@]}"; do
    value=$(read_env_value "$key")
    if [ -z "$value" ]; then
      log "Error: $key must be set in .env." "$COLOR_RED"
      return 1
    fi
  done

  postgres_user=$(read_env_value POSTGRES_USER)
  pg_user=$(read_env_value PGUSER)
  if [ "$postgres_user" != "$pg_user" ]; then
    log "Error: POSTGRES_USER and PGUSER must have the same value in .env." "$COLOR_RED"
    return 1
  fi
}

update_env_value() {
  local key=$1
  local value=$2
  local temp_file

  temp_file=$(mktemp)
  awk -v key="$key" -v value="$value" '
    BEGIN { updated = 0 }
    index($0, key "=") == 1 {
      if (!updated) {
        print key "=" value
        updated = 1
      }
      next
    }
    { print }
    END {
      if (!updated) {
        print key "=" value
      }
    }
  ' .env > "$temp_file"
  cat "$temp_file" > .env
  rm -f "$temp_file"
}

set_gpu_environment() {
  local enabled=$1
  local gpu_type=$2

  update_env_value GPU "$enabled"
  update_env_value GPU_TYPE "$gpu_type"
  update_env_value DOCKER_RUNTIME "$gpu_type"
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

# Remove old Docker images from version 2.0.7
remove_old_images() {
  log "Checking for old reNgine 2.0.7 Docker containers and images..." $COLOR_CYAN
  
  # Stop and remove all containers
  if docker ps -a --format '{{.Names}}' | grep -qE '^rengine-|^postgres$|^redis$'; then
    log "Stopping existing reNgine containers..." $COLOR_YELLOW
    if ! make down; then
      log "Error: Failed to stop existing containers. Please stop them manually with 'make down' before continuing." $COLOR_RED
      exit 1
    fi
  fi
  
  declare -a old_images=(
    "rengine-celery"
    "rengine-celery-beat"
    "docker.pkg.github.com/yogeshojha/rengine/rengine"
    "rengine-certs"
    "nginx"
    "postgres"
    "redis"
  )

  local failed_removals=false
  
  for image in "${old_images[@]}"; do
    if docker images --format "{{.Repository}}:{{.Tag}}" | grep -qE "^${image}(:|$)"; then
      log "Removing old image: $image" $COLOR_YELLOW
      if ! docker rmi -f "$image"; then
        log "Failed to remove image: $image" $COLOR_RED
        failed_removals=true
      fi
    fi
  done

  if [ "$failed_removals" = true ]; then
    log "Error: Some old images could not be removed." $COLOR_RED
    log "Please remove them manually using these commands:" $COLOR_RED
    log "docker ps -a  # to check if containers are still running" $COLOR_YELLOW
    log "docker rm -f \$(docker ps -a -q)  # to force remove all containers" $COLOR_YELLOW
    log "docker images  # to list all images" $COLOR_YELLOW
    log "docker rmi -f <image_id>  # to force remove specific images" $COLOR_YELLOW
    log "Then run the installation script again." $COLOR_RED
    exit 1
  fi
}

fix_volumes_permissions() {
  local user_id=$1
  local group_id=${2:-$1}
  
  log "Fixing permissions for Docker volumes..." $COLOR_CYAN
  
  declare -a volumes=(
    "rengine_gf_patterns"
    "rengine_github_repos"
    "rengine_nuclei_templates"
    "rengine_scan_results"
    "rengine_tool_config"
    "rengine_wordlist"
  )

  for volume in "${volumes[@]}"; do
    if docker volume inspect "$volume" >/dev/null 2>&1; then
      log "Setting permissions for volume: $volume" $COLOR_YELLOW
      if ! docker run --rm -v "$volume:/data" alpine sh -c "chown -R $user_id:$group_id /data"; then
        log "Failed to set permissions for volume: $volume" $COLOR_RED
        return 1
      fi
    else
      log "Volume $volume not found, skipping..." $COLOR_YELLOW
    fi
  done
  
  log "Volume permissions updated successfully" $COLOR_GREEN
  return 0
}

fix_project_ownership() {
  local user_id=$1
  local group_id=${2:-$1}
  
  log "Setting correct ownership of the project directory..." $COLOR_CYAN
  project_dir=$(pwd)
  
  # Set ownership for both hidden and regular files in one command
  if ! find "$project_dir" -exec chown "${user_id}:${group_id}" {} +; then
      log "Failed to set ownership of project directory to $user_id" $COLOR_RED
      return 1
  fi
  
  log "Project directory ownership set to $user_id" $COLOR_GREEN
  return 0
}
# Check GPU support and install required dependencies
check_gpu_support() {
    log "Checking for GPU support..." $COLOR_CYAN
    
    # Execute GPU detection with error handling
    if ! GPU_TYPE=$(./scripts/gpu_support.sh 2>/dev/null); then
        log "GPU detection script failed, continuing with CPU-only setup" $COLOR_YELLOW
        return 1
    fi
    
    # Validate GPU_TYPE output
    if [[ ! "$GPU_TYPE" =~ ^(nvidia|amd|none)$ ]]; then
        log "Invalid GPU type detected: $GPU_TYPE, continuing with CPU-only setup" $COLOR_YELLOW
        return 1
    fi
    
    case $GPU_TYPE in
        "nvidia")
            log "NVIDIA GPU detected" $COLOR_GREEN
            if ! command -v nvidia-ctk &> /dev/null; then
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
                if ! sudo usermod -aG render "$SUDO_USER" || ! sudo usermod -aG video "$SUDO_USER"; then
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

check_privileges() {
  if [ "$EUID" -eq 0 ]; then
    if [ "${SUDO_USER:-}" = "root" ] || [ -z "${SUDO_USER:-}" ]; then
      log "Error: Do not run this script as root user. Use 'sudo' with a non-root user." "$COLOR_RED"
      log "Example: 'sudo ./install.sh'" "$COLOR_RED"
      return 1
    fi
  elif [ -z "${SUDO_USER:-}" ]; then
    log "Error: This script must be run with sudo." "$COLOR_RED"
    log "Example: 'sudo ./install.sh'" "$COLOR_RED"
    return 1
  fi
}

show_access_urls() {
  local external_ip=""
  local internal_ips=""
  local formatted_ips=""
  local ip_address

  external_ip=$(curl --fail --silent --show-error --max-time 10 https://ipecho.net/plain 2>/dev/null || true)
  if command -v ip >/dev/null 2>&1; then
    internal_ips=$(ip -4 -br addr | awk '$2 == "UP" || $1 == "lo" {print $3}' | cut -d/ -f1)
  elif command -v hostname >/dev/null 2>&1; then
    internal_ips=$(hostname -I 2>/dev/null || true)
  fi

  for ip_address in $internal_ips; do
    formatted_ips="${formatted_ips}https://${ip_address}\n"
  done

  if [ -n "$formatted_ips" ]; then
    log "\r\nFor a local installation, reNgine-ng should be available at:\n$formatted_ips" "$COLOR_GREEN"
  fi
  if [ -n "$external_ip" ]; then
    log "For a server installation, reNgine-ng should be available at: https://$external_ip/" "$COLOR_GREEN"
  fi
}

usageFunction()
{
  local exit_code=${1:-1}
  log "Usage: $0 [-n|--non-interactive] [-h|--help]" "$COLOR_GREEN"
  log "\t-n, --non-interactive  Run without interactive prompts" "$COLOR_GREEN"
  log "\t-h, --help             Show usage" "$COLOR_GREEN"
  return "$exit_code"
}

# Main installation process
main() {
  local isNonInteractive=false
  local arg

  for arg in "$@"; do
    case $arg in
      -n|--non-interactive)
        isNonInteractive=true
        ;;
      -h|--help)
        usageFunction 0
        return 0
        ;;
      *)
        log "Unknown argument: $arg" "$COLOR_RED"
        usageFunction 1
        return 1
        ;;
    esac
  done

  if ! check_privileges; then
    return 1
  fi

  cd "$SCRIPT_DIR" || return 1
  cat web/art/reNgine.txt

  log "\r\nBefore running this script, please make sure Docker is installed and running, and you have made changes to the '.env' file." $COLOR_RED
  log "Changing the PostgreSQL username & password in the '.env' is highly recommended.\r\n" $COLOR_RED

  log "Please note that this installation script is only intended for Linux" $COLOR_RED
  log "x86_64 and arm64 platform (compatible with Apple Mx series) are supported" $COLOR_RED

  log "Raspberry Pi is not recommended, all install tests have failed" $COLOR_RED
  log ""

  if ! load_installer_env; then
    return 1
  fi
  if ! validate_required_env; then
    return 1
  fi

  log "Checking and installing reNgine-ng prerequisites..." $COLOR_CYAN

  if ! install_curl || ! install_make; then
    return 1
  fi
  check_docker
  check_docker_compose

  # Add GPU support check here
  if check_gpu_support; then
    if [ "$isNonInteractive" = true ]; then
            if [ "$GPU_ENABLED" = "1" ]; then
                set_gpu_environment 1 "$GPU_TYPE"
                log "GPU support has been enabled from existing configuration" $COLOR_GREEN
            else
                set_gpu_environment 0 none
                log "GPU support is disabled in .env" $COLOR_YELLOW
            fi
    else
        log "Do you want to enable GPU support for Ollama? (recommended for better LLM performance) [y/n] " $COLOR_CYAN
        read -p "" gpu_choice
        case $gpu_choice in
            [Yy]* )
                set_gpu_environment 1 "$GPU_TYPE"
                log "GPU support will be enabled" $COLOR_GREEN
                ;;
            * )
                set_gpu_environment 0 none
                log "Continuing without GPU support" $COLOR_YELLOW
                ;;
        esac
    fi
  else
    set_gpu_environment 0 none
  fi

  if [ "$isNonInteractive" = false ]; then
    read -p "Are you sure you made changes to the '.env' file (y/n)? " answer
    case ${answer:0:1} in
        y|Y|yes|YES|Yes )
          log "\nContinuing installation!\n" $COLOR_GREEN
        ;;
        * )
          if ! install_nano || ! nano .env; then
            log "Failed to edit .env." "$COLOR_RED"
            return 1
          fi
        ;;
    esac
    if ! load_installer_env; then
      return 1
    fi
    if ! validate_required_env; then
      return 1
    fi
  fi

  # Remove old Docker images from version 2.0.7
  remove_old_images

  if [ -n "$SUDO_USER" ]; then
    current_id=$(id -u "$SUDO_USER")
    current_gid=$(id -g "$SUDO_USER")
  else
    current_id=$(id -u)
    current_gid=$(id -g)
  fi

  # Fix project directory ownership
  if ! fix_project_ownership "$current_id" "$current_gid"; then
      log "Failed to fix project directory ownership" $COLOR_RED
      exit 1
  fi

  # Fix Docker volumes permissions
  if ! fix_volumes_permissions "$current_id" "$current_gid"; then
      log "Failed to fix Docker volumes permissions" $COLOR_RED
      exit 1
  fi

  # Install type
  if [ "$current_id" -ne 1000 ]; then
      # If the user is not 1000, force source install because pre-built images are not compatible with user > 1000
      INSTALL_TYPE="source"
      log "Build has been forced because your user ID is not the same as the pre-built images. If you want to use pre-built images, your current user installing reNgine-ng must be 1000." $COLOR_RED
  else
      if [ "$isNonInteractive" = false ]; then
          log "Do you want to build Docker images from source or use pre-built images (recommended)?\nThis saves significant build time but requires good download speeds for it to complete fast." $COLOR_RED
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
      elif [ "$isNonInteractive" = true ]; then
        INSTALL_TYPE="${INSTALL_TYPE:-prebuilt}"
      fi
  fi

  # Non-interactive install
  if [ "$isNonInteractive" = true ]; then
    if [ -z "$DJANGO_SUPERUSER_USERNAME" ] || [ -z "$DJANGO_SUPERUSER_EMAIL" ] || [ -z "$DJANGO_SUPERUSER_PASSWORD" ]; then
      log "Error: DJANGO_SUPERUSER_USERNAME, DJANGO_SUPERUSER_EMAIL, and DJANGO_SUPERUSER_PASSWORD must be set in .env for non-interactive installation" $COLOR_RED
      exit 1
    fi

    log "Non-interactive installation parameter set. Installation begins." $COLOR_GREEN
  fi

  if [ -z "$INSTALL_TYPE" ]; then
    log "Error: INSTALL_TYPE is not set in .env, please set it to either 'prebuilt' or 'source'" $COLOR_RED
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

  # Add configuration files management
  log "Setting up tool configurations..." $COLOR_CYAN
  
  declare -A config_files=(
    ["theHarvester/api-keys.yaml"]="docker/celery/config/the-harvester-api-keys.yaml"
    ["amass/config.ini"]="docker/celery/config/amass.ini"
    ["gau/config.toml"]="docker/celery/config/gau.toml"
  )

  for target in "${!config_files[@]}"; do
    target_path="/home/rengine/.config/$target"
    source_path="${config_files[$target]}"
    
    if ! docker exec -u rengine rengine-celery-1 test -f "$target_path"; then
      log "Copying $target configuration..." $COLOR_CYAN
      if ! docker exec -u rengine rengine-celery-1 mkdir -p "$(dirname "$target_path")" ||
         ! docker cp "$(pwd)/$source_path" "rengine-celery-1:$target_path" ||
         ! docker exec -u root rengine-celery-1 chown rengine:rengine "$target_path" ||
         ! docker exec -u rengine rengine-celery-1 chmod 644 "$target_path"; then
        log "Failed to install configuration file $target" $COLOR_RED
        return 1
      fi
    else
      log "Configuration file $target already exists, skipping..." $COLOR_YELLOW
    fi
  done

  # Create symbolic link for theHarvester if it doesn't exist
  if ! docker exec -u rengine rengine-celery-1 bash -c '[ -L "/home/rengine/.theHarvester" ] || ln -s /home/rengine/.config/theHarvester /home/rengine/.theHarvester'; then
    log "Failed to create theHarvester configuration link" $COLOR_RED
    return 1
  fi

  log "Creating an account..." $COLOR_CYAN
  if ! make superuser_create isNonInteractive="$isNonInteractive"; then
    log "Failed to create the reNgine-ng administrator account" $COLOR_RED
    return 1
  fi

  log "reNgine-ng is successfully installed and started!" $COLOR_GREEN
  log "\r\nThank you for installing reNgine-ng, happy recon!" $COLOR_GREEN

  show_access_urls
}

# Run the main installation process
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
