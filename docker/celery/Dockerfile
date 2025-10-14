FROM debian:13

# Labels and Credits
LABEL \
    name="reNgine-ng" \
    author="Security-Tools-Alliance (https://github.com/Security-Tools-Alliance) & Yogesh Ojha <yogesh.ojha11@gmail.com>" \
    description="reNgine-ng is an automated pipeline of recon process, useful for information gathering during web application penetration testing."

# Environment Variables
ENV DEBIAN_FRONTEND="noninteractive" \
    DATABASE="postgres"
ENV USERNAME="rengine"
ARG HOST_UID
ARG HOST_GID

# Install nala for faster package management
RUN apt update -y && apt install -y nala

# Modify existing debian.sources to remove trixie from Suites (keep only trixie-updates and trixie-security)
RUN sed -i 's/Suites: trixie trixie-updates/Suites: trixie-updates/' /etc/apt/sources.list.d/debian.sources && \
    echo "Modified debian.sources:" && \
    cat /etc/apt/sources.list.d/debian.sources

# Use nala to fetch fast mirrors and update package lists
RUN nala fetch --auto --debian trixie --non-free

# Update package lists with nala and install all required packages
RUN nala update && nala upgrade -y
RUN nala install -y     \
    gcc g++ make        \
    openssl unzip   \
    tar git             \
    build-essential     \
    zlib1g-dev          \
    libncurses5-dev     \
    libgdbm-dev         \
    libnss3-dev         \
    libssl-dev          \
    libreadline-dev     \
    libffi-dev          \
    libsqlite3-dev      \
    libbz2-dev          \
    wget                \
    libpcap-dev         \
    libpq-dev           \
    libxml2-dev         \
    libxslt1-dev        \
    file                \
    vim                 \
    xvfb                \
    iputils-ping        \
    curl                \
    dnsutils            \
    gettext             \
    nmap                \
    net-tools           \
    geoip-bin           \
    htop                \
    sudo                \
    chromium fping      \
    fontconfig          \
    fonts-freefont-ttf  \
    fonts-noto          \
    fonts-terminus      \
    # Install python 3 and development tools
    python3 python3-venv \
    python3-dev pipx python3-watchdog

# Secator tools dependencies
RUN nala install -y     \
    # Install go
    golang              \
    # Install rust
    rustc cargo         \
    # Install ruby
    ruby-full rubygems  \
    # For maigret - Cairo development libraries
    libcairo2-dev       \
    libgirepository1.0-dev \
    libpango1.0-dev     \
    python3-gi-cairo

RUN fc-cache -f && \ 
    fc-list | sort

ENV USERNAME="rengine"
RUN addgroup --gid $HOST_GID --system $USERNAME && \
    mkdir -p /home/$USERNAME && \
    adduser --gid $HOST_GID --system --shell /bin/false --disabled-password --uid $HOST_UID --home /home/$USERNAME $USERNAME && \
    chown $USERNAME:$USERNAME /home/$USERNAME

USER $USERNAME
WORKDIR /home/$USERNAME

ENV TOOLPATH="/home/${USERNAME}/tools"
ENV BINPATH="/home/${USERNAME}/.local/bin"
ENV WORDLISTPATH="/home/${USERNAME}/wordlists"
ENV PIPX_BIN_DIR="${TOOLPATH}/pipx"
ENV GOPATH="${TOOLPATH}/go"
ENV PATH="${PATH}:${GOROOT}/bin:${GOPATH}/bin:${PIPX_BIN_DIR}"

RUN mkdir -p $TOOLPATH/.github && \
    mkdir -p $BINPATH

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="${PATH}:${BINPATH}"

# Install Secator and all its supported tools
RUN pipx install secator && \
    pipx install watchdog

# Install python tools
RUN pipx install poetry --verbose

# Copy poetry config files
COPY --chown=$USERNAME:$USERNAME ./*.toml /home/$USERNAME

# Install reNgine dependencies
RUN cd /home/$USERNAME && poetry install

# Switch to root to configure sudoers for secator install
USER root

# Temporarily give rengine user full sudo access for secator tools installation
RUN mkdir -p /etc/sudoers.d && \
    echo "$USERNAME ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/secator_temp && \
    chmod 440 /etc/sudoers.d/secator_temp && \
    usermod -aG sudo $USERNAME

# Switch to rengine user for secator tools installation
USER $USERNAME

# Install secator tools
RUN secator install tools

# Install secator addons
RUN secator install addons redis && \
    secator install addons worker

# Switch back to root to remove sudo access
USER root

# Remove temporary sudo access for security
RUN rm -f /etc/sudoers.d/secator_temp && \
    gpasswd -d $USERNAME sudo

USER $USERNAME

# Create directories for results and wordlists
RUN mkdir -p $WORDLISTPATH && \
    mkdir -p /home/$USERNAME/results && \
    mkdir -p /home/$USERNAME/nuclei-templates

# Initialize Secator tools
RUN secator --version && \
    ln -s /home/$USERNAME/.local/share/pipx/venvs/secator/bin/celery /home/$USERNAME/.local/bin/celery
COPY ./entrypoint.sh /entrypoint.sh
COPY ./smart_reload.py /home/$USERNAME/smart_reload.py
RUN mkdir -p /home/$USERNAME/rengine /home/$USERNAME/scan_results \
    && chown -R $USERNAME:$USERNAME /home/$USERNAME/rengine \
    && chown -R $USERNAME:$USERNAME /home/$USERNAME/scan_results
VOLUME /home/$USERNAME/rengine
VOLUME /home/$USERNAME/scan_results
WORKDIR /home/$USERNAME/rengine
ENTRYPOINT ["/entrypoint.sh"]
