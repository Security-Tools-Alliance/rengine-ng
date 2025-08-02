#!/bin/bash

# Import common functions
source "$(pwd)/common_functions.sh"

# Function to sync volumes with latest image content
sync_volumes() {
  log "Starting volume synchronization..." $COLOR_CYAN
  
  # Define volume mappings: volume_name:container_path:image_name:production_container
  local volumes=(
    "rengine_tool_config:/home/rengine/.config:rengine-celery:rengine-celery-1"
    "rengine_nuclei_templates:/home/rengine/nuclei-templates:rengine-celery:rengine-celery-1"
    "rengine_gf_patterns:/home/rengine/.gf:rengine-celery:rengine-celery-1"
    "rengine_wordlist:/home/rengine/wordlists:rengine-celery:rengine-celery-1"
    "rengine_github_repos:/home/rengine/github_repos:rengine-celery:rengine-celery-1"
    "rengine_ollama_data:/home/rengine/.ollama:rengine-ollama:rengine-ollama-1"
  )
  
  for volume_mapping in "${volumes[@]}"; do
    IFS=':' read -r volume_name container_path image_suffix prod_container <<< "$volume_mapping"
    # Use current version if it's higher than latest release (testing scenario)
    local sync_version
    version_compare $CURRENT_VERSION $LATEST_VERSION
    if [[ $? -eq 1 ]]; then
      sync_version=$CURRENT_VERSION
    else
      sync_version=$LATEST_VERSION
    fi
    local image_name="ghcr.io/security-tools-alliance/rengine-ng:${image_suffix}-v${sync_version}"
    
    log "Syncing $volume_name from $image_name..." $COLOR_CYAN
    
    # Check if volume exists
    if ! docker volume inspect "$volume_name" >/dev/null 2>&1; then
      log "Volume $volume_name does not exist, skipping..." $COLOR_YELLOW
      continue
    fi
    
    # Check if production container is running, use it if available
    local target_container=""
    if docker ps --format "table {{.Names}}" | grep -q "^${prod_container}$"; then
      target_container="$prod_container"
      log "Using running container: $prod_container" $COLOR_CYAN
    else
      # Create lightweight container for volume access
      target_container="rengine-sync-$(date +%s)"
      if ! docker run --name "$target_container" -d -v "$volume_name:$container_path" alpine:latest tail -f /dev/null >/dev/null 2>&1; then
        log "Failed to create sync container for $volume_name" $COLOR_RED
        continue
      fi
    fi
    
    # Extract files from image without running it (much faster)
    local source_container="rengine-extract-$(date +%s)"
    if ! docker create --name "$source_container" "$image_name" >/dev/null 2>&1; then
      log "Failed to create source container" $COLOR_RED
      if [[ "$target_container" != "$prod_container" ]]; then
        docker rm -f "$target_container" >/dev/null 2>&1
      fi
      continue
    fi
    
    # Use docker cp to extract files directly (no exec needed)
    local temp_dir="/tmp/rengine-sync-$$"
    mkdir -p "$temp_dir"
    
    if docker cp "$source_container:$container_path" "$temp_dir/" 2>/dev/null; then
      local base_path=$(basename "$container_path")
      find "$temp_dir/$base_path" -type f 2>/dev/null | while read -r local_file; do
        local relative_path="${local_file#$temp_dir/$base_path}"
        local target_path="$container_path$relative_path"
        
        # Check if file exists in target volume - NEVER overwrite existing files
        if ! docker exec "$target_container" test -f "$target_path" 2>/dev/null; then
          # File doesn't exist, copy it (preserves user modifications)
          local dir_path=$(dirname "$target_path")
          
          # Create directory if it doesn't exist
          docker exec "$target_container" mkdir -p "$dir_path" 2>/dev/null
          
          # Copy file to target container
          if docker cp "$local_file" "$target_container:$target_path" 2>/dev/null; then
            log "  Copied: $target_path" $COLOR_GREEN
            # Set proper ownership if not using production container
            if [[ "$target_container" != "$prod_container" ]]; then
              docker exec "$target_container" chown rengine:rengine "$target_path" 2>/dev/null
            fi
          else
            log "  Failed to copy: $target_path" $COLOR_RED
          fi
        fi
      done
    fi
    
    # Cleanup
    rm -rf "$temp_dir"
    docker rm -f "$source_container" >/dev/null 2>&1
    if [[ "$target_container" != "$prod_container" ]]; then
      docker rm -f "$target_container" >/dev/null 2>&1
    fi
  done
  
  log "Volume synchronization completed." $COLOR_GREEN
}

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
     read -p "Do you want to synchronize volumes with the latest image content? (y/n) " sync_answer
     if [[ $sync_answer == "y" ]]; then
       sync_volumes
     fi
     exit 0
     ;;
  1) log "Your version is newer than the latest release. No update needed." $COLOR_YELLOW
     read -p "Do you want to synchronize volumes with the release image content? (y/n) " sync_answer
     if [[ $sync_answer == "y" ]]; then
       sync_volumes
     fi
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
    log "Synchronizing volumes with updated image content..." $COLOR_CYAN
    sync_volumes
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
    log "Synchronizing volumes with updated image content..." $COLOR_CYAN
    sync_volumes
  else
    log "Invalid input. Update cancelled." $COLOR_RED
    exit 1
  fi
else
  log "Update cancelled." $COLOR_YELLOW
fi