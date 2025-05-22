FROM ollama/ollama:0.3.6

# Enable NVIDIA GPU support
ENV NVIDIA_VISIBLE_DEVICES all
ENV NVIDIA_DRIVER_CAPABILITIES compute,utility

# Add labels for GPU support information
LABEL com.rengine.gpu-support="enabled-nvidia"
LABEL com.rengine.gpu-description="NVIDIA GPU support is enabled in this image"
