FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      git \
      curl \
      ca-certificates \
 && install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://download.docker.com/linux/debian/gpg \
      -o /etc/apt/keyrings/docker.asc \
 && chmod a+r /etc/apt/keyrings/docker.asc \
 && . /etc/os-release \
 && echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
       https://download.docker.com/linux/debian ${VERSION_CODENAME} stable" \
      | tee /etc/apt/sources.list.d/docker.list > /dev/null \
 && apt-get update \
 && apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "channels-redis==4.3.0"

# Allow git to operate on /repo regardless of file ownership
RUN git config --global --add safe.directory /repo

WORKDIR /app
COPY entrypoint.py .

CMD ["python", "-u", "entrypoint.py"]
