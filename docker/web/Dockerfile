FROM --platform=$BUILDPLATFORM python:3.12-slim

# Labels and Credits
LABEL \
    name="reNgine-ng" \
    author="Security-Tools-Alliance (https://github.com/Security-Tools-Alliance) & Yogesh Ojha <yogesh.ojha11@gmail.com>" \
    description="reNgine-ng is a automated pipeline of recon process, useful for information gathering during web application penetration testing."

# Environment Variables
ENV DEBIAN_FRONTEND="noninteractive" \
    DATABASE="postgres"
ENV USERNAME="rengine"
ARG HOST_UID
ARG HOST_GID

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    cron \
    curl \
    openssh-client \
    fontconfig \
    fonts-freefont-ttf \
    fonts-noto \
    fonts-terminus \
    net-tools \
    htop \
    vim \
    build-essential \
    gcc \
    python3-dev \
    libpango1.0-dev \
    zlib1g-dev \
    libjpeg-dev \
    libopenjp2-7-dev \
    g++ \
    libffi-dev \
    libpq-dev \
    postgresql-client \
    pipx \
    python3-watchdog \
    && fc-cache -f \
    && fc-list | sort \
    && groupadd --gid $HOST_GID $USERNAME \
    && useradd --uid $HOST_UID --gid $HOST_GID --shell /bin/bash --create-home $USERNAME \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

USER $USERNAME
WORKDIR /home/$USERNAME

ENV TOOLPATH="/home/${USERNAME}/tools"
ENV BINPATH="/home/${USERNAME}/.local/bin"
ENV PIPX_BIN_DIR="${TOOLPATH}/pipx"
ENV PATH="${PATH}:${BINPATH}:${PIPX_BIN_DIR}"

RUN mkdir -p $TOOLPATH && \
    mkdir -p $BINPATH && \
    mkdir -p /home/$USERNAME/.ssh && \
    mkdir -p /home/$USERNAME/docker

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install poetry via pipx
RUN pipx install poetry

# Copy poetry config files
COPY --chown=$USERNAME:$USERNAME ./pyproject.toml /home/$USERNAME/pyproject.toml

# Install reNgine dependencies
RUN poetry install --without dev

EXPOSE 8000
RUN mkdir -p /home/$USERNAME/rengine
VOLUME /home/$USERNAME/rengine
WORKDIR /home/$USERNAME/rengine
ENTRYPOINT ["/entrypoint.sh"]
