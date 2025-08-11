FROM --platform=$BUILDPLATFORM python:3.10-alpine

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

RUN apk add --no-cache bash postgresql-libs curl fontconfig ttf-freefont font-noto terminus-font net-tools htop vim && \
    apk add --no-cache py3-pip gcc musl-dev python3-dev pango zlib-dev jpeg-dev openjpeg-dev g++ libffi-dev && \
    apk add --no-cache --virtual .build-deps gcc python3-dev musl-dev postgresql-dev && \
    fc-cache -f && \ 
    fc-list | sort && \
    addgroup --gid $HOST_GID -S $USERNAME && \
    adduser -g $HOST_GID -u $HOST_UID -S --shell /bin/bash --ingroup $USERNAME $USERNAME

USER $USERNAME
ENV PATH=/home/$USERNAME/.local/bin:${PATH}

COPY --chown=$USERNAME:$USERNAME ./pyproject.toml /home/$USERNAME/pyproject.toml
WORKDIR /home/$USERNAME
RUN echo 'PATH="$HOME/.local/bin:${PATH}"' >> $HOME/.bashrc && \
    pip install pipx && pipx install poetry && poetry install

EXPOSE 8000
USER $USERNAME
RUN mkdir -p /home/$USERNAME/rengine
VOLUME /home/$USERNAME/rengine
WORKDIR /home/$USERNAME/rengine
ENTRYPOINT ["/entrypoint.sh"]