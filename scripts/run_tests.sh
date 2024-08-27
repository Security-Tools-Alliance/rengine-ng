#!/bin/bash

# Exit on any error
set -e

# Import common functions
source "$(pwd)/common_functions.sh"

# Check for root privileges with WSL
if [ "$(whoami)" != "root" ] && [ "$(detect_wsl)" = 0 ]
  then
  log ""
  log "Error launching tests: please run this script as root!" $COLOR_RED
  log "Example: sudo $0" $COLOR_RED
  exit
fi

# Function to determine host architecture
get_host_architecture() {
    local arch=$(uname -m)
    case $arch in
        x86_64)
            echo "amd64"
            ;;
        aarch64)
            echo "arm64"
            ;;
        *)
            echo "Unsupported architecture: $arch" >&2
            exit 1
            ;;
    esac
}

# Function to display help message
show_help() {
    echo "Usage: $0 [--arch <amd64|arm64>] [--clean-temp] [--clean-all] [--without-build] <branch_name> <test_file> [test1] [test2] ..."
    echo
    echo "Run tests for the reNgine-ng project in a VM environment."
    echo
    echo "Mandatory arguments:"
    echo "  branch_name      The Git branch to test"
    echo "  test_file        The test file to run"
    echo
    echo "Optional arguments:"
    echo "  --arch           Specify the architecture (amd64 or arm64). If not specified, uses host architecture."
    echo "  --clean-temp     Clean temporary files and VM without prompting"
    echo "  --clean-all      Clean temporary files, VM, and installed packages without prompting"
    echo "  --without-build   Run all tests except the build test"
    echo "  test1 test2 ...  Specific tests to run from the test file"
    echo
    echo "Examples:"
    echo "  $0                                   # Run all tests on host architecture"
    echo "  $0 --arch amd64                      # Run all tests on amd64 architecture"
    echo "  $0 --arch arm64 feature-branch       # Run tests on arm64 for feature-branch"
    echo "  $0 --arch amd64 master makefile certs pull # Run specific tests on amd64"
    echo "  $0 --clean-temp                      # Clean temporary files and VM without prompting"
    echo "  $0 --clean-all                       # Clean temporary files, VM, and installed packages without prompting"
    echo "  $0 --without-build                    # Run all tests except the build test"
    echo
    echo "The script will create a VM for the specified architecture, set up the environment, and run the specified tests."
}

# Get host architecture
HOST_ARCH=$(get_host_architecture)

# Initialize cleanup variables
CLEAN_TEMP=false
CLEAN_ALL=false

# Parse command line arguments
ARCH=""
WITHOUT_BUILD=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --arch)
            ARCH="$2"
            shift 2
            ;;
        --clean-temp)
            CLEAN_TEMP=true
            shift
            ;;
        --clean-all)
            CLEAN_ALL=true
            shift
            ;;
        --without-build)
            WITHOUT_BUILD=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            break
            ;;
    esac
done

# If architecture is not specified, use host architecture
if [ -z "$ARCH" ]; then
    ARCH="$HOST_ARCH"
    log "Architecture not specified. Using host architecture: $ARCH" $COLOR_YELLOW
fi

# Validate architecture
if [ "$ARCH" != "amd64" ] && [ "$ARCH" != "arm64" ]; then
    log "Error: Invalid architecture. Must be either amd64 or arm64." $COLOR_RED
    exit 1
fi

# Function to check if a branch exists
branch_exists() {
    git ls-remote --exit-code --heads origin "$1" &>/dev/null
}

# Set default branch
DEFAULT_BRANCH="master"

# VM parameters
VM_NAME="test-rengine-ng"
VM_IMAGE="test-debian.qcow2"
VM_RAM="8G"
VM_CPUS="8"
VM_DISK_SIZE="60G"  # Adjust this value as needed

# SSH parameters
SSH_OPTIONS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

# Rengine root directory inside the VM
RENGINE_ROOT='~/rengine'

# Check if mandatory arguments are provided
if [ $# -lt 2 ]; then
    log "Error: branch_name and test_file are mandatory parameters." $COLOR_RED
    show_help
    exit 1
fi

# Extract branch_name and test_file from arguments
RELEASE_VERSION="$1"
TEST_FILE="$2"
shift 2

# Check if the branch exists
if ! branch_exists "$RELEASE_VERSION"; then
    log "Error: Branch $RELEASE_VERSION does not exist." $COLOR_RED
    exit 1
fi

# Extract test names from remaining arguments
TEST_NAMES="$@"

# Function to generate test names
generate_test_names() {
    local names=""
    for name in $TEST_NAMES; do
        names+="test_$name "
    done
    echo $names
}

# Generate the test names
FORMATTED_TEST_NAMES=$(generate_test_names)

# Create log directory if it doesn't exist
LOG_DIR="$(pwd)/../logs/tests"
mkdir -p "$LOG_DIR"

# Generate a unique log file name
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="${LOG_DIR}/test_${TEST_FILE}_log_${TIMESTAMP}.txt"

# When you're ready to use RELEASE_VERSION:
log "Checking out branch: $RELEASE_VERSION" $COLOR_CYAN

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install QEMU if not already installed
INSTALLED_PACKAGES_FOR_TESTS="qemu-system-x86 qemu-system-arm qemu-utils cloud-image-utils"
INSTALLED_COMMON_PACKAGES="socat wget openssh-client tar gzip git curl gpg coreutils"

# Create a temporary directory for the test
mkdir -p $HOME/tmp
TEST_DIR=$(mktemp -d -p $HOME/tmp)

# Function to clean up resources
cleanup() {
    local clean_temp=false
    local clean_packages=false

    if [ "$CLEAN_TEMP" = true ] || [ "$CLEAN_ALL" = true ]; then
        clean_temp=true
    fi

    if [ "$CLEAN_ALL" = true ]; then
        clean_packages=true
    fi

    if [ "$CLEAN_TEMP" = false ] && [ "$CLEAN_ALL" = false ]; then
        echo -e "\n\033[1;33mCleanup Confirmation\033[0m"
        read -p "Do you want to remove temporary files and VM? (y/n): " temp_response
        if [[ "$temp_response" == "y" ]]; then
            clean_temp=true
        fi

        read -p $'Do you want to uninstall the packages installed for testing?
Installed packages for testing: ('"$INSTALLED_PACKAGES_FOR_TESTS"$')
Installed common packages: ('"$INSTALLED_COMMON_PACKAGES"$')
Only installed packages for testing will be removed, common packages will be left untouched.
You may consider removing these packages by hand.
Type your answer (y/n): ' packages_response

    if [[ "$packages_response" == "y" ]]; then
            clean_packages=true
        fi
    fi

    if [ "$clean_temp" = true ]; then
        log "Cleaning up temporary files and VM..." $COLOR_CYAN
        # Send powerdown command to QEMU monitor
        echo "system_powerdown" | socat - UNIX-CONNECT:/tmp/qemu-monitor.sock 2>/dev/null || true

        # Wait for VM to stop (with timeout)
        for i in {1..15}; do
            if ! pgrep -f "qemu-system-.*$VM_NAME" > /dev/null; then
                log "VM stopped successfully" $COLOR_GREEN
                break
            fi
            sleep 1
        done

        # Force stop if VM is still running
        if pgrep -f "qemu-system-.*$VM_NAME" > /dev/null; then
            log "Forcing VM to stop..." $COLOR_RED
            pkill -f "qemu-system-.*$VM_NAME" || true
        fi

        if [[ "$TEST_DIR" == "$HOME/tmp/"* ]]; then
            log "Removing temporary directory..." $COLOR_CYAN
            rm -rf "$TEST_DIR"
            log "Temporary directory removed." $COLOR_GREEN
        else
            log "Error: TEST_DIR is not in $HOME/tmp. Skipping directory removal for safety." $COLOR_RED
        fi
    fi

    if [ "$clean_packages" = true ]; then
        log "Uninstalling packages..." $COLOR_CYAN
        sudo apt-get remove -y $INSTALLED_PACKAGES_FOR_TESTS
        sudo apt-get autoremove -y
        log "Packages uninstalled." $COLOR_GREEN
    fi

    log "Cleanup completed." $COLOR_GREEN
}

# Set trap to ensure cleanup on script exit (normal or abnormal)
trap 'log "Interruption has been detected." $COLOR_YELLOW; cleanup; log "Exiting script." $COLOR_GREEN;' EXIT

SCRIPT_FINISHED=0

# Execute the tests in a subshell to capture the output and exit status
(
# Install QEMU & dependencies
log "Installing QEMU..." $COLOR_CYAN
sudo apt-get update
sudo apt-get install -y $INSTALLED_PACKAGES_FOR_TESTS $INSTALLED_COMMON_PACKAGES

# Copy project files to the temporary directory
log "Copying project files to temporary directory..." $COLOR_CYAN

# Compress the project directory
log "Compressing project files..." $COLOR_CYAN
(cd .. && tar -czf "$TEST_DIR/rengine-project.tar.gz" --exclude='docker/secrets' .)

cd "$TEST_DIR"

# Download appropriate Debian 12 cloud image
log "Downloading Debian 12 cloud image for $ARCH..." $COLOR_CYAN
if [ "$ARCH" = "amd64" ]; then
    wget -q https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2 -O debian-12-generic.qcow2
elif [ "$ARCH" = "arm64" ]; then
    wget -q https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-arm64.qcow2 -O debian-12-generic.qcow2
fi

# Create a larger disk image
qemu-img create -f qcow2 -o preallocation=metadata "$TEST_DIR/large-debian.qcow2" $VM_DISK_SIZE

# Resize the downloaded image to fill the new larger disk
qemu-img resize "$TEST_DIR/debian-12-generic.qcow2" $VM_DISK_SIZE

# Combine the two images
qemu-img convert -O qcow2 -o preallocation=metadata "$TEST_DIR/debian-12-generic.qcow2" "$TEST_DIR/large-debian.qcow2"

# Create a copy of the image for testing
mv large-debian.qcow2 test-debian.qcow2

# Generate SSH key pair
log "Generating SSH key pair..." $COLOR_CYAN
ssh-keygen -t ssh-keygen -t ed25519 -f ./id_ed25519 -N ""

# Create a cloud-init configuration file
cat > cloud-init.yml <<EOF
#cloud-config
users:
  - name: rengine
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat ./id_ed25519)
EOF

# Create a cloud-init ISO
cloud-localds cloud-init.iso cloud-init.yml

# Start the VM
log "Starting the VM..." $COLOR_CYAN
if [ "$ARCH" = "amd64" ]; then
    qemu-system-x86_64 \
        -name $VM_NAME \
        -m $VM_RAM \
        -smp $VM_CPUS \
        -enable-kvm \
        -cpu host \
        -nodefaults \
        -no-fd-bootchk \
        -drive file=$VM_IMAGE,format=qcow2 \
        -drive file=cloud-init.iso,format=raw \
        -device virtio-net-pci,netdev=net0 \
        -netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::8443-:443 \
        -vga std \
        -vnc :0 \
        -display none &
elif [ "$ARCH" = "arm64" ]; then
    qemu-system-aarch64 \
        -name $VM_NAME \
        -M virt \
        -m $VM_RAM \
        -smp $VM_CPUS \
        -cpu cortex-a72 \
        -nodefaults \
        -drive file=$VM_IMAGE,format=qcow2 \
        -drive file=cloud-init.iso,format=raw \
        -device virtio-net-pci,netdev=net0 \
        -netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::8443-:443 \
        -device virtio-gpu-pci \
        -device ramfb \
        -device nec-usb-xhci,id=xhci \
        -device usb-kbd \
        -device usb-tablet \
        -vnc :0 \
        -serial mon:stdio \
        -display none &
fi

log "VM started. You can connect via VNC on localhost:5900" $COLOR_GREEN

# Wait for the VM to start
log "Waiting for the VM to start..." $COLOR_CYAN
sleep 10

# Wait for SSH to become available
log "Waiting for SSH to become available..." $COLOR_CYAN
for i in {1..30}; do
    if ssh -p 2222 $SSH_OPTIONS -i ./id_ed25519 rengine@localhost echo "SSH is up" &>/dev/null; then
        log "SSH is now available" $COLOR_GREEN
        break
    fi
    if [ $i -eq 30 ]; then
        log "Timed out waiting for SSH" $COLOR_RED
        exit 1
    fi
    sleep 10
done

# Run setup commands in the VM
log "Setting up locales in the VM..." $COLOR_CYAN
ssh -p 2222 $SSH_OPTIONS -i ./id_ed25519 rengine@localhost << EOF
    # Update and install dependencies
    sudo apt-get update
    sudo apt-get install -y locales-all
EOF

# Copy compressed project files to the VM
log "Copying compressed project files to the VM..." $COLOR_CYAN
scp -P 2222 $SSH_OPTIONS -i ./id_ed25519 "$TEST_DIR/rengine-project.tar.gz" rengine@localhost:~

log "Decompressing project files on the VM..." $COLOR_CYAN
ssh -p 2222 $SSH_OPTIONS -i ./id_ed25519 rengine@localhost << EOF
    sudo apt-get install git -y
    mkdir -p $RENGINE_ROOT
    tar -xzf ~/rengine-project.tar.gz -C $RENGINE_ROOT
    rm ~/rengine-project.tar.gz
    cd $RENGINE_ROOT
    cat > $RENGINE_ROOT/.git/config << EOG
[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallrefupdates = true
[remote "origin"]
    url = https://github.com/Security-Tools-Alliance/rengine-ng.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
    remote = origin
    merge = refs/heads/master
    vscode-merge-base = origin/master
EOG
    cp $RENGINE_ROOT/.env-dist $RENGINE_ROOT/.env
EOF

# Run setup commands in the VM
log "Setting up Docker and the application in the VM..." $COLOR_CYAN
ssh -p 2222 $SSH_OPTIONS -i ./id_ed25519 rengine@localhost << EOF
    # Update and install dependencies
    sudo apt-get install -y ca-certificates curl gnupg make htop iftop net-tools

    # Add Docker's official GPG key
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg

    # Set up Docker repository
    echo \
      "deb [arch=\$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
      \$(. /etc/os-release && echo "\$VERSION_CODENAME") stable" | \
      sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    # Install Docker Engine, Docker Compose and python libs
    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin python3-docker python3-parameterized

    # Add rengine user to docker group
    sudo usermod -aG docker rengine
    newgrp docker

    # Run tests
    cd $RENGINE_ROOT
    python3 tests/test_$TEST_FILE.py ${FORMATTED_TEST_NAMES:+--tests $FORMATTED_TEST_NAMES}
EOF

# Get the test status
TEST_STATUS=$?

# Write the test status to a temporary file
echo $TEST_STATUS > "$TEST_DIR/test_status.txt"

# Log test completion
log "Tests completed with status: $TEST_STATUS" $COLOR_GREEN
SCRIPT_FINISHED=1

) 2>&1 | tee -a "$LOG_FILE"

# Wait for the subscript to finish
while [ $SCRIPT_FINISHED -eq 0 ]; do
    sleep 1
done

# Get the test status of the subshell from the temporary file
TEST_STATUS=$(cat "$TEST_DIR/test_status.txt")

# Exit with the status
exit $TEST_STATUS