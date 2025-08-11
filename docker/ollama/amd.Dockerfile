FROM ollama/ollama:0.3.6

# Enable ROCm support
ENV HSA_OVERRIDE_GFX_VERSION=9.0.0
ENV ROCR_VISIBLE_DEVICES=all

# Add labels for GPU support information
LABEL com.rengine.gpu-support="enabled-amd"
LABEL com.rengine.gpu-description="AMD GPU support is enabled in this image"
