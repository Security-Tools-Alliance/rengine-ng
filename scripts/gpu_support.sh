#!/bin/bash

# Check for GPU support and return the type
detect_gpu_type() {
    # Check for NVIDIA GPU using multiple methods
    if command -v nvidia-smi &> /dev/null; then
        # Check if nvidia-smi can actually communicate with a GPU
        if nvidia-smi --query-gpu=gpu_name --format=csv,noheader &> /dev/null; then
            echo "nvidia"
            return 0
        fi
    fi

    # Additional NVIDIA checks if nvidia-smi fails
    if [ -d "/proc/driver/nvidia" ] || [ -d "/dev/nvidia0" ]; then
        # Check for NVIDIA kernel module
        if lsmod | grep -q "^nvidia "; then
            echo "nvidia"
            return 0
        fi
    fi

    # Check for NVIDIA GPU in PCI devices
    if lspci | grep -i "NVIDIA" | grep -i "VGA\|3D\|Display" &> /dev/null; then
        # Check if the NVIDIA GPU is not disabled
        if ! lspci -k | grep -A 2 -i "NVIDIA" | grep -i "Kernel driver in use: nouveau" &> /dev/null; then
            echo "nvidia"
            return 0
        fi
    fi

    # Check for AMD GPU using multiple methods
    if command -v rocminfo &> /dev/null; then
        # Check if rocminfo can detect a GPU
        if rocminfo 2>/dev/null | grep -q "GPU agent"; then
            echo "amd"
            return 0
        fi
    fi

    # Additional AMD checks
    if lspci | grep -i "AMD" | grep -i "VGA\|3D\|Display" &> /dev/null; then
        # Check for AMD GPU driver
        if lsmod | grep -q "^amdgpu "; then
            echo "amd"
            return 0
        fi
    fi

    # No supported GPU found
    echo "none"
    return 1
}

# Log function for debugging
debug_log() {
    if [ "${DEBUG:-0}" = "1" ]; then
        echo "[DEBUG] $1" >&2
    fi
}

# If script is run directly, execute detection with optional debug info
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [ "${DEBUG:-0}" = "1" ]; then
        debug_log "Checking PCI devices:"
        lspci | grep -i "VGA\|3D\|Display" >&2
        debug_log "Loaded kernel modules:"
        lsmod | grep -E "nvidia|amdgpu" >&2
    fi
    detect_gpu_type
fi