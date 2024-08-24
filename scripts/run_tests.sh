#!/bin/bash

# Exit on any error
set -e

# Import common functions
source "$(pwd)/common_functions.sh"

# Function to display help message
show_help() {
    echo "Usage: $0 [branch_name] [test_file] [test1] [test2] ..."
    echo
    echo "Run tests for the reNgine-ng project in a VM environment."
    echo
    echo "Arguments:"
    echo "  branch_name     The Git branch to test (default: master)"
    echo "  test_file       The test file to run (default: makefile)"
    echo "  test1 test2 ... Specific tests to run from the test file"
    echo
    echo "Examples:"
    echo "  $0                           # Run all tests in test_makefile.py on master branch"
    echo "  $0 feature-branch            # Run all tests in test_makefile.py on feature-branch"
    echo "  $0 master makefile certs pull # Run specific tests from test_makefile.py"
    echo "  $0 master custom_file test1  # Run test1 from test_custom_file.py"
    echo
    echo "The script will create a VM, set up the environment, and run the specified tests."
    echo "Test results and a full log of the process will be saved in the log/tests directory."
}

# Check for help flag
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
    exit 0
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

# Extract test file and test names from arguments
TEST_FILE="${2:-makefile}"  # Default to 'makefile' if not provided
TEST_NAMES="${@:3}"  # All arguments from the third onward are test names

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
LOG_DIR="$(pwd)/log/tests"
mkdir -p "$LOG_DIR"

# Generate a unique log file name
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="${LOG_DIR}/test_${TEST_FILE}_log_${TIMESTAMP}.cast"

# Start asciinema recording
#asciinema rec -c "$0 $*" "$LOG_FILE"

# Check if a branch is provided as an argument
if [ $# -eq 1 ]; then
    RELEASE_VERSION="$1"
    log "Checking for branch: $RELEASE_VERSION" $COLOR_YELLOW
    
    if branch_exists "$RELEASE_VERSION"; then
        log "Branch $RELEASE_VERSION exists." $COLOR_GREEN
    else
        log "Branch $RELEASE_VERSION does not exist. Attempting to create it." $COLOR_YELLOW
        if git fetch origin "$RELEASE_VERSION"; then
            git checkout -b "$RELEASE_VERSION" origin/"$RELEASE_VERSION"
            log "Branch $RELEASE_VERSION created and checked out." $COLOR_GREEN
        else
            log "Failed to fetch $RELEASE_VERSION. Falling back to $DEFAULT_BRANCH." $COLOR_RED
            RELEASE_VERSION="$DEFAULT_BRANCH"
        fi
    fi
else
    RELEASE_VERSION="$DEFAULT_BRANCH"
    log "No branch specified. Using default branch: $RELEASE_VERSION" $COLOR_YELLOW
fi

# When you're ready to use RELEASE_VERSION:
log "Checking out branch: $RELEASE_VERSION" $COLOR_GREEN

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install QEMU if not already installed
if ! command_exists qemu-system-x86_64; then
    echo "Installing QEMU..."
    sudo apt-get update
    sudo apt-get install -y qemu-system-x86-64 qemu-utils
fi

# Create a temporary directory for the test
mkdir -p $HOME/tmp
TEST_DIR=$(mktemp -d -p $HOME/tmp)

# Function to clean up resources
cleanup() {
    echo -e "\n\033[1;33mCleanup Confirmation\033[0m"
    echo "This will shut down the VM and remove the temporary directory."
    echo "VM Name: $VM_NAME"
    echo "Temporary Directory: $TEST_DIR"
    echo -e "\033[1;31mWarning: This action cannot be undone.\033[0m"
    read -p "Do you want to proceed with the cleanup? (yes/no): " user_input

    if [[ "$user_input" != "yes" ]]; then
        echo "Cleanup aborted by user."
        return
    fi

    echo "Proceeding with cleanup..."
    echo "Shutting down & Removing VM..."
   
    # Send powerdown command to QEMU monitor
    echo "system_powerdown" | socat - UNIX-CONNECT:/tmp/qemu-monitor.sock

    # Wait for VM to stop (with timeout)
    for i in {1..30}; do
        if ! pgrep -f "qemu-system-x86_64.*$VM_NAME" > /dev/null; then
            echo "VM stopped successfully"
            break
        fi
        sleep 1
    done

    # Force stop if VM is still running
    if pgrep -f "qemu-system-x86_64.*$VM_NAME" > /dev/null; then
        echo "Forcing VM to stop..."
        pkill -f "qemu-system-x86_64.*$VM_NAME"
    fi

    if [[ "$TEST_DIR" == "$HOME/tmp/"* ]]; then
        echo "Removing temporary directory..."
        rm -r "$TEST_DIR"
        echo "Cleanup completed."
    else
        echo "Error: TEST_DIR is not in $HOME/tmp. Skipping directory removal for safety."
    fi
}

# Set trap to ensure cleanup on script exit (normal or abnormal)
trap cleanup EXIT

# Copy project files to the temporary directory
log "Copying project files to temporary directory..." $COLOR_GREEN

# Compress the project directory
log "Compressing project files..." $COLOR_GREEN
tar -czf "$TEST_DIR/rengine-project.tar.gz" ..

cd "$TEST_DIR"

# Download Debian 12 cloud image
log "Downloading Debian 12 cloud image..." $COLOR_GREEN
wget -q https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2

# Create a larger disk image
qemu-img create -f qcow2 -o preallocation=metadata "$TEST_DIR/large-debian.qcow2" $VM_DISK_SIZE

# Resize the downloaded image to fill the new larger disk
qemu-img resize "$TEST_DIR/debian-12-generic-amd64.qcow2" $VM_DISK_SIZE

# Combine the two images
qemu-img convert -O qcow2 -o preallocation=metadata "$TEST_DIR/debian-12-generic-amd64.qcow2" "$TEST_DIR/large-debian.qcow2"

# Create a copy of the image for testing
mv large-debian.qcow2 test-debian.qcow2

# Generate SSH key pair
log "Generating SSH key pair..." $COLOR_GREEN
ssh-keygen -t rsa -b 2048 -f ./id_rsa -N ""

# Create a cloud-init configuration file
cat > cloud-init.yml <<EOF
#cloud-config
users:
  - name: rengine
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat ./id_rsa.pub)
EOF

# Create a cloud-init ISO
cloud-localds cloud-init.iso cloud-init.yml

# Start the VM
log "Starting the VM..." $COLOR_GREEN
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

# Wait for the VM to start
log "Waiting for the VM to start..." $COLOR_GREEN
sleep 10

# Wait for SSH to become available
log "Waiting for SSH to become available..." $COLOR_GREEN
for i in {1..30}; do
    if ssh -p 2222 $SSH_OPTIONS -i ./id_rsa rengine@localhost echo "SSH is up" &>/dev/null; then
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
log "Setting up locales in the VM..." $COLOR_GREEN
ssh -p 2222 $SSH_OPTIONS -i ./id_rsa rengine@localhost << EOF
    # Update and install dependencies
    sudo apt-get update
    sudo apt-get install -y locales-all
EOF

# Copy compressed project files to the VM
log "Copying compressed project files to the VM..." $COLOR_GREEN
scp -P 2222 $SSH_OPTIONS -i ./id_rsa "$TEST_DIR/rengine-project.tar.gz" rengine@localhost:~

log "Decompressing project files on the VM and git checkout branch to test..." $COLOR_GREEN
ssh -p 2222 $SSH_OPTIONS -i ./id_rsa rengine@localhost << EOF
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
    git fetch origin
    git checkout "$RELEASE_VERSION" -f
    cp $RENGINE_ROOT/.env-dist $RENGINE_ROOT/.env
EOF

# Run setup commands in the VM
log "Setting up Docker and the application in the VM..." $COLOR_GREEN
ssh -p 2222 $SSH_OPTIONS -i ./id_rsa rengine@localhost << EOF
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
    python3 tests/test_$TEST_FILE.py $FORMATTED_TEST_NAMES
EOF

# Get the test status
TEST_STATUS=$?

# Call cleanup explicitly
cleanup

# Stop asciinema recording
exit

# Exit with the test status
log "Tests completed with status: $TEST_STATUS" $COLOR_GREEN
exit $TEST_STATUS