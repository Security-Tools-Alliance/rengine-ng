# Base image
FROM ubuntu:22.04

ARG version=0.33.0
ARG geckodriver_amd=geckodriver-v${version}-linux64.tar.gz
ARG geckodriver_arm=geckodriver-v${version}-linux-aarch64.tar.gz

ARG go_version=1.21.5
ARG go_amd=go${go_version}.linux-amd64.tar.gz
ARG go_arm=go${go_version}.linux-arm64.tar.gz

# Labels and Credits
LABEL \
    name="reNGine" \
    author="Security-Tools-Alliance (https://github.com/Security-Tools-Alliance) & Yogesh Ojha <yogesh.ojha11@gmail.com>" \
    description="reNGine is a automated pipeline of recon process, useful for information gathering during web application penetration testing."

# Environment Variables
ENV DEBIAN_FRONTEND="noninteractive" \
    DATABASE="postgres"
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV GOROOT="/usr/local/go"
ENV GOPATH=$HOME/go
ENV PATH="${PATH}:${GOROOT}/bin:${GOPATH}/bin"

# Install Python
RUN apt update && \
    apt install -y \
    python3.10 \
    python3-dev \
    python3-pip 

# Install essential packages
RUN apt install -y --no-install-recommends \
    build-essential \
    cmake \
    geoip-bin \
    geoip-database \
    gcc \
    git \
    libpq-dev \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libpcap-dev \
    netcat \
    nmap \
    x11-utils \
    xvfb \
    wget \
    curl \
    python3-netaddr \
    software-properties-common

RUN add-apt-repository ppa:mozillateam/ppa

# Download and install go
RUN  ARCH=$(dpkg --print-architecture) \
    && if [ "${ARCH}" = "arm64" ]; then \
        wget https://go.dev/dl/${go_arm} && \
        tar -xvf ${go_arm} -C /usr/local/ && \
        rm ${go_arm}; \
      elif [ "${ARCH}" = "amd64" ]; then \
        wget https://go.dev/dl/${go_amd} && \
        tar -xvf ${go_amd} -C /usr/local/ && \
        rm ${go_amd}; \
      else \
        echo "Unknown architecture: $ARCH" ; \
        exit 1; \
      fi

# Download and install geckodriver
RUN ARCH=$(dpkg --print-architecture) \
    && if [ "${ARCH}" = "arm64" ]; then \
      wget https://github.com/mozilla/geckodriver/releases/download/v${version}/${geckodriver_arm} && \
      tar -xvf ${geckodriver_arm} -C /usr/bin/ && \
      rm ${geckodriver_arm}; \
    elif [ "${ARCH}" = "amd64" ]; then \
      wget https://github.com/mozilla/geckodriver/releases/download/v${version}/${geckodriver_amd} && \
      tar -xvf ${geckodriver_amd} -C /usr/bin/ && \
      rm ${geckodriver_amd}; \
    else \
      echo "Unknown architecture: $ARCH" ; \
    exit 1; \
  fi

# Make directory for app
WORKDIR /usr/src/app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Download Go packages
ENV GO111MODULE=on 
RUN ARCH=$(dpkg --print-architecture) \
&& if [[ "$ARCH" = "arm64" || "$ARCH" = "amd64" ]]; then \
    export GOARCH=$ARCH && \
    printf "\
    github.com/jaeles-project/gospider@latest\n\
    github.com/tomnomnom/gf@latest\n\
    github.com/tomnomnom/unfurl@latest\n\
    github.com/tomnomnom/waybackurls@latest\n\
    github.com/projectdiscovery/httpx/cmd/httpx@latest\n\
    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n\
    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n\
    github.com/projectdiscovery/naabu/v2/cmd/naabu@latest\n\
    github.com/hakluke/hakrawler@latest\n\
    github.com/lc/gau/v2/cmd/gau@latest\n\
    github.com/jaeles-project/gospider@latest\n\
    github.com/owasp-amass/amass/v3/...@latest\n\
    github.com/ffuf/ffuf@latest\n\
    github.com/projectdiscovery/tlsx/cmd/tlsx@latest\n\
    github.com/hahwul/dalfox/v2@latest\n\
    github.com/projectdiscovery/katana/cmd/katana@latest\n\
    github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest\n\
    github.com/sa7mon/s3scanner@latest\n" | \
    xargs -L1 go install -ldflags="-s -w" -v && \
    rm -rf /go/pkg/* && rm -rf /root/.cache/go-build

# Update Nuclei-Templates
RUN nuclei -update-templates

# Copy requirements
COPY ./requirements.txt /tmp/requirements.txt
RUN pip3 install --upgrade setuptools pip && \
    pip3 install -r /tmp/requirements.txt --no-cache-dir

# install eyewitness

RUN python3 -m pip install --no-cache-dir fuzzywuzzy \
    selenium==4.9.1 \
    python-Levenshtein \
    pyvirtualdisplay \
    netaddr

# Copy source code
COPY . /usr/src/app/
