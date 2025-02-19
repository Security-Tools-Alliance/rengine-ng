FROM debian:12

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

RUN apt update -y && apt install -y      \
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
    vim                 \
    xvfb                \
    git                 \
    unzip               \
    curl                \
    gettext             \
    nmap                \
    net-tools           \
    geoip-bin           \
    htop                \
    firefox-esr         \
    fontconfig fonts-freefont-ttf fonts-noto fonts-terminus

RUN fc-cache -f && \ 
    fc-list | sort

ENV USERNAME="rengine"
RUN addgroup --gid $HOST_GID --system $USERNAME && \
    mkdir -p /home/$USERNAME && \
    adduser --gid $HOST_GID --system --shell /bin/false --disabled-password --uid $HOST_UID --home /home/$USERNAME $USERNAME && \
    chown $USERNAME:$USERNAME /home/$USERNAME

# Download and install geckodriver
RUN ARCH=$(dpkg --print-architecture) && \
    version=0.35.0 && \
    geckodriver_arm="geckodriver-v${version}-linux-aarch64.tar.gz" && \
    geckodriver_amd="geckodriver-v${version}-linux64.tar.gz" && \
    if [ "${ARCH}" = "arm64" ]; then \
        wget "https://github.com/mozilla/geckodriver/releases/download/v${version}/${geckodriver_arm}" && \
        tar -xvf "${geckodriver_arm}" -C /usr/local/bin/ && \
        rm "${geckodriver_arm}"; \
    elif [ "${ARCH}" = "amd64" ]; then \
        wget "https://github.com/mozilla/geckodriver/releases/download/v${version}/${geckodriver_amd}" && \
        tar -xvf "${geckodriver_amd}" -C /usr/local/bin/ && \
        rm "${geckodriver_amd}"; \
    else \
        echo "Unknown architecture: $ARCH" && \
        exit 1; \
    fi

# Download and install go
RUN ARCH=$(dpkg --print-architecture) && \
    #GO_VERSION=$(curl -s https://go.dev/VERSION?m=text) && \
    GO_VERSION=1.23.0 && \
    if [ "${ARCH}" = "arm64" ]; then \
      wget https://go.dev/dl/go${GO_VERSION}.linux-arm64.tar.gz && \
      tar -xvf go${GO_VERSION}.linux-arm64.tar.gz -C /usr/local/ && \
      rm go${GO_VERSION}.linux-arm64.tar.gz; \
    elif [ "${ARCH}" = "amd64" ]; then \
      wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
      tar -xvf go${GO_VERSION}.linux-amd64.tar.gz -C /usr/local/ && \
      rm go${GO_VERSION}.linux-amd64.tar.gz; \
    else \
      echo "Unknown architecture: $ARCH" ; \
      exit 1; \
    fi

# Install python 3.10
RUN cd /root && wget https://www.python.org/ftp/python/3.10.0/Python-3.10.0.tgz && \
    tar -xvf Python-3.10.0.tgz && \
    rm Python-3.10.0.tgz && \
    cd Python-3.10.0 && \
    ./configure --enable-optimizations && \
    make -j4 && \
    make altinstall

USER $USERNAME
WORKDIR /home/$USERNAME

ENV TOOLPATH="/home/${USERNAME}/tools"
ENV BINPATH="/home/${USERNAME}/.local/bin"
ENV WORDLISTPATH="/home/${USERNAME}/wordlists"
ENV PIPX_BIN_DIR="${TOOLPATH}/pipx"
ENV GOROOT="/usr/local/go"
ENV GOPATH="${TOOLPATH}/go"
ENV PATH="${PATH}:${GOROOT}/bin:${GOPATH}/bin:${PIPX_BIN_DIR}"

RUN mkdir -p $TOOLPATH/.github && \
    mkdir -p $BINPATH


# Download Go packages
RUN ARCH=$(dpkg --print-architecture) \
    && if [ "$ARCH" = "arm64" ] || [ "$ARCH" = "amd64" ]; then \
        GOARCH=$ARCH go install -v github.com/jaeles-project/gospider@v1.1.6 \
        && GOARCH=$ARCH go install -ldflags="-s -w" -v github.com/tomnomnom/gf@dcd4c361f9f5ba302294ed38b8ce278e8ba69006 \
        && GOARCH=$ARCH go install -ldflags="-s -w" -v github.com/tomnomnom/unfurl@v0.4.3 \
        && GOARCH=$ARCH go install -ldflags="-s -w" -v github.com/tomnomnom/waybackurls@v0.1.0 \
        && GOARCH=$ARCH go install -ldflags="-s -w" -v github.com/projectdiscovery/httpx/cmd/httpx@v1.6.9 \
        && GOARCH=$ARCH go install -ldflags="-s -w" -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.7 \
        && GOARCH=$ARCH go install -ldflags="-s -w" -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.5 \
        && GOARCH=$ARCH go install -ldflags="-s -w" -v github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.2 \
        && GOARCH=$ARCH go install -ldflags="-s -w" -v github.com/hakluke/hakrawler@latest \
        && GOARCH=$ARCH go install -ldflags="-s -w" -v github.com/lc/gau/v2/cmd/gau@v2.2.4 \
        && GOARCH=$ARCH go install -ldflags="-s -w" -v github.com/owasp-amass/amass/v4/...@v4.2.0 \
        && GOARCH=$ARCH go install -ldflags="-s -w" -v github.com/ffuf/ffuf/v2@v2.1.0 \
        && GOARCH=$ARCH go install -ldflags="-s -w" -v github.com/projectdiscovery/tlsx/cmd/tlsx@v1.1.8 \
        && GOARCH=$ARCH go install -ldflags="-s -w" -v github.com/hahwul/dalfox/v2@v2.9.3 \
        && GOARCH=$ARCH go install -ldflags="-s -w" -v github.com/projectdiscovery/katana/cmd/katana@v1.1.1 \
        && GOARCH=$ARCH go install -ldflags="-s -w" -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@v1.4.1 \
        && GOARCH=$ARCH go install -ldflags="-s -w" -v github.com/sa7mon/s3scanner@c544f1cf00f70cae3f2155b24d336f515b7c598b \
        && chmod 700 -R $GOPATH/pkg/* \
        && rm -rf $GOPATH/pkg/* \
        && rm -rf /home/$USERNAME/.cache/go-build/*; \
    else \
        echo "Unknown architecture: $ARCH" ; \
        exit 1; \
    fi

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="${PATH}:${BINPATH}"

# Install python tools
RUN python3.10 -m pip install pipx && pipx ensurepath && printf "poetry\n\
    watchdog\n\
    https://github.com/aboul3la/Sublist3r/archive/refs/tags/1.1.zip\n\
    https://github.com/laramies/theHarvester/archive/refs/tags/4.6.0.zip\n\
    git+https://github.com/ncrocfer/whatportis@59a1718bf7c531f2a5a4e213cad0c047ce9c1c94\n\
    git+https://github.com/EnableSecurity/wafw00f@914dbf4feab7e2529f064f4300b5fde84ea1cce3\n\
    h8mail\n" | xargs -L1 pipx install || true

# Install tools
RUN ln -s /usr/local/bin/geckodriver $BINPATH/geckodriver && \
    cd $TOOLPATH/.github && git clone https://github.com/shmilylty/OneForAll.git && cd OneForAll && git reset --hard 9ecfda229199ebf30d9338f4c88cbeb7c40e16c2 && \
    cd $TOOLPATH/.github && git clone https://github.com/FortyNorthSecurity/EyeWitness.git && cd EyeWitness && git reset --hard cb09a842f93109836219b2aa2f9f25c58a34bc8c && \
    cd $TOOLPATH/.github && git clone https://github.com/UnaPibaGeek/ctfr.git && cd ctfr && git reset --hard 6c7fecdc6346c4f5322049e38f415d5bddaa420d && \
    cd $TOOLPATH/.github && git clone https://github.com/Tuhinshubhra/CMSeeK.git && cd CMSeeK && git reset --hard 20f9780d2e682874be959cfd487045c92e3c73f4 && \
    cd $TOOLPATH/.github && git clone https://github.com/Security-Tools-Alliance/Infoga.git && cd Infoga && git reset --hard 6834c6f863c2bdc92cc808934bb293571d1939c1 && \
    cd $TOOLPATH/.github && wget https://github.com/m3n0sd0n4ld/GooFuzz/releases/download/1.2.5/GooFuzz.v.1.2.5.zip && unzip GooFuzz.v.1.2.5.zip && rm GooFuzz.v.1.2.5.zip && mv GooFuzz* GooFuzz && echo "#!/bin/bash\n\nbash $TOOLPATH/.github/GooFuzz/GooFuzz \"\$@\"" > $BINPATH/GooFuzz && chmod +x $BINPATH/GooFuzz && \
    cd $TOOLPATH/.github && git clone https://github.com/1ndianl33t/Gf-Patterns && cd Gf-Patterns && git reset --hard 565382db80f001af288b8d71c525a7ce7f17e80d && mkdir -p /home/$USERNAME/.gf/ && cp -r *.json /home/$USERNAME/.gf/ && \
    cd $TOOLPATH/.github && git clone https://github.com/tomnomnom/gf.git && cd gf && git reset --hard dcd4c361f9f5ba302294ed38b8ce278e8ba69006 && cp -r examples/*.json /home/$USERNAME/.gf/ && \ 
    mkdir -p /home/$USERNAME/.nmap/ && cd /home/$USERNAME/.nmap/ && git clone https://github.com/scipag/vulscan.git && cd vulscan && git reset --hard 2640d62400e9953fb9a33e6033dc59a9dc9606ba && ln -s $TOOLPATH/.github/vulscan /home/$USERNAME/.nmap/vulscan && \
    mkdir -p $WORDLISTPATH && \
    wget https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt -O $WORDLISTPATH/dicc.txt && \
    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/fuzz-Bo0oM.txt -O $WORDLISTPATH/fuzz-Bo0oM.txt && \
    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt -O $WORDLISTPATH/deepmagic.com-prefixes-top50000.txt && \
    mkdir -p /home/$USERNAME/nuclei-templates && wget https://raw.githubusercontent.com/NagliNagli/Shockwave-OSS/bd7445cd320a174d3073f0a61867a40849d28436/ssrf.yaml -O /home/$USERNAME/nuclei-templates/ssrf_nagli.yaml && \
    mkdir -p /home/$USERNAME/results

# Copy poetry config files
COPY --chown=$USERNAME:$USERNAME ./*.toml /home/$USERNAME

# Install aliases for tools needing a pyproject.toml
RUN cd $TOOLPATH/.github/OneForAll && mv /home/$USERNAME/oneforall-pyproject.toml pyproject.toml && poetry env use python3.10 && poetry install --no-cache && echo "#!/bin/bash\n\npoetry -C $TOOLPATH/.github/OneForAll/ run python $TOOLPATH/.github/OneForAll/oneforall.py \"\$@\"" > $BINPATH/oneforall && chmod +x $BINPATH/oneforall && \
    cd $TOOLPATH/.github/ctfr && mv /home/$USERNAME/ctfr-pyproject.toml pyproject.toml && poetry env use python3.10 && poetry install --no-cache && echo "#!/bin/bash\n\npoetry -C $TOOLPATH/.github/ctfr/ run python $TOOLPATH/.github/ctfr/ctfr.py \"\$@\"" > $BINPATH/ctfr && chmod +x $BINPATH/ctfr && \
    cd $TOOLPATH/.github/EyeWitness/Python && mv /home/$USERNAME/eyewitness-pyproject.toml pyproject.toml && poetry env use python3.10 && poetry install --no-cache && echo "#!/bin/bash\n\npoetry -C $TOOLPATH/.github/EyeWitness/Python run python $TOOLPATH/.github/EyeWitness/Python/EyeWitness.py \"\$@\"" > $BINPATH/EyeWitness && chmod +x $BINPATH/EyeWitness && \
    cd $TOOLPATH/.github/CMSeeK && mv /home/$USERNAME/cmseek-pyproject.toml pyproject.toml && poetry env use python3.10 && poetry install --no-cache && echo "#!/bin/bash\n\npoetry -C $TOOLPATH/.github/CMSeeK/ run python $TOOLPATH/.github/CMSeeK/cmseek.py \"\$@\"" > $BINPATH/cmseek && chmod +x $BINPATH/cmseek && \
    cd $TOOLPATH/.github/Infoga && mv /home/$USERNAME/infoga-pyproject.toml pyproject.toml && poetry env use python3.10 && poetry install --no-cache && echo "#!/bin/bash\n\npoetry -C $TOOLPATH/.github/Infoga/ run python $TOOLPATH/.github/Infoga/infoga.py \"\$@\"" > $BINPATH/infoga && chmod +x $BINPATH/infoga && \
    cd /home/$USERNAME && poetry install

# Create tools config files
RUN nuclei -silent && naabu -version && subfinder -version && \
    mkdir -p /home/$USERNAME/.config/theHarvester && \
    mkdir -p /home/$USERNAME/.config/amass && \
    mkdir -p /home/$USERNAME/.config/gau
COPY --chown=$USERNAME:$USERNAME ./config/the-harvester-api-keys.yaml /home/$USERNAME/.config/theHarvester/api-keys.yaml
COPY --chown=$USERNAME:$USERNAME ./config/amass.ini /home/$USERNAME/.config/amass/config.ini
COPY --chown=$USERNAME:$USERNAME ./config/gau.toml /home/$USERNAME/.config/gau/config.toml
RUN ln -s /home/$USERNAME/.config/theHarvester /home/$USERNAME/.theHarvester
COPY ./entrypoint.sh /entrypoint.sh
RUN mkdir -p /home/$USERNAME/rengine /home/$USERNAME/scan_results \
    && chown -R $USERNAME:$USERNAME /home/$USERNAME/rengine \
    && chown -R $USERNAME:$USERNAME /home/$USERNAME/scan_results
VOLUME /home/$USERNAME/rengine
VOLUME /home/$USERNAME/scan_results
WORKDIR /home/$USERNAME/rengine
ENTRYPOINT ["/entrypoint.sh"]
