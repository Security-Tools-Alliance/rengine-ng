#!/bin/bash


# GPU Detection Script for reNgine-ng
# Supports both macOS and Linux systems
# Detects NVIDIA and AMD GPUs where Docker GPU acceleration is available

# Detect operating system
detect_os() {
    case "${UNAME_S:-$(uname -s)}" in
        Darwin)
            echo "macos"
            ;;
        Linux)
            echo "linux"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# Check for GPU support and return the type
detect_gpu_type() {
    local os_type
    os_type=$(detect_os)
    
    case "$os_type" in
        macos)
            detect_gpu_macos
            ;;
        linux)
            detect_gpu_linux
            ;;
        *)
            echo "none"
            return 1
            ;;
    esac
}

# macOS GPU detection
detect_gpu_macos() {
    # On macOS, check system profiler for GPU information
    if command -v system_profiler &> /dev/null; then
        # Check for NVIDIA GPU (less common on modern Macs)
        if system_profiler SPDisplaysDataType 2>/dev/null | grep -i "nvidia" &> /dev/null; then
            # Check if CUDA is available (indicates NVIDIA GPU support)
            if command -v nvidia-smi &> /dev/null && nvidia-smi --query-gpu=gpu_name --format=csv,noheader &> /dev/null; then
                echo "nvidia"
                return 0
            fi
        fi
        
        # Check for AMD GPU (common in Mac Pro, iMac Pro)
        if system_profiler SPDisplaysDataType 2>/dev/null | grep -i -E "radeon|amd" &> /dev/null; then
            # For macOS, we'll consider AMD GPUs as supported if ROCm tools are available
            if command -v rocminfo &> /dev/null && rocminfo 2>/dev/null | grep -q "GPU agent"; then
                echo "amd"
                return 0
            fi
        fi
        
        # Check for Apple Silicon GPU (M1/M2/M3)
        if system_profiler SPDisplaysDataType 2>/dev/null | grep -i -E "apple m[0-9]|apple silicon" &> /dev/null; then
            # Apple Silicon GPUs don't support NVIDIA CUDA or AMD ROCm
            # For now, we don't enable GPU acceleration on Apple Silicon
            debug_log "Apple Silicon GPU detected, but GPU acceleration not supported in containers"
            echo "none"
            return 1
        fi
    fi
    
    echo "none"
    return 1
}

# Linux GPU detection (original logic)
detect_gpu_linux() {
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
    if command -v lspci &> /dev/null && lspci | grep -i "NVIDIA" | grep -i "VGA\|3D\|Display" &> /dev/null; then
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
    if command -v lspci &> /dev/null && lspci | grep -i "AMD" | grep -i "VGA\|3D\|Display" &> /dev/null; then
        # Check for AMD GPU driver
        if command -v lsmod &> /dev/null && lsmod | grep -q "^amdgpu "; then
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
        os_type=$(detect_os)
        debug_log "Operating system: $os_type"
        
        case "$os_type" in
            macos)
                debug_log "macOS GPU information:"
                if command -v system_profiler &> /dev/null; then
                    system_profiler SPDisplaysDataType 2>/dev/null | grep -E "Chipset Model|VRAM" >&2
                fi
                ;;
            linux)
                debug_log "Linux GPU information:"
                if command -v lspci &> /dev/null; then
                    debug_log "PCI devices:"
                    lspci | grep -i "VGA\|3D\|Display" >&2
                fi
                if command -v lsmod &> /dev/null; then
                    debug_log "Loaded kernel modules:"
                    lsmod | grep -E "nvidia|amdgpu" >&2
                fi
                ;;
        esac
    fi
    detect_gpu_type
fi