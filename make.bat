@echo off

:: Credits: https://github.com/ninjhacks

set COMPOSE_FILE       = -f docker/docker-compose.yml
set COMPOSE_DEV_FILE   = -f docker/docker-compose.dev.yml
set COMPOSE_BUILD_FILE = -f docker/docker-compose.build.yml
set SERVICES           = db web proxy redis celery celery-beat

:: Generate certificates.
if "%1" == "certs" docker compose -f docker/docker-compose.setup.yml run --rm certs
:: Generate certificates.
if "%1" == "setup" docker compose -f docker/docker-compose.setup.yml run --rm certs
:: Build and start all services.
if "%1" == "up" docker compose %COMPOSE_FILE% up -d %SERVICES%
:: Build all services.
if "%1" == "build" docker compose %COMPOSE_FILE% %COMPOSE_BUILD_FILE% build %SERVICES%
:: Build and start all services.
if "%1" == "build_up" (
    docker compose %COMPOSE_FILE% %COMPOSE_BUILD_FILE% build %SERVICES%
    docker compose %COMPOSE_FILE% up -d %SERVICES%
)
:: Pull and start all services.
if "%1" == "pull_up" (
    docker compose %COMPOSE_FILE% pull %SERVICES%
    docker compose %COMPOSE_FILE% up -d %SERVICES%
)
:: Generate Username (use only after make up).
if "%1" == "username" docker compose %COMPOSE_FILE% exec web python3 manage.py createsuperuser
:: Change password for user
if "%1" == "changepassword" docker compose %COMPOSE_FILE% exec web python3 manage.py changepassword
:: Apply migrations
if "%1" == "migrate" docker compose %COMPOSE_FILE% exec web python3 manage.py migrate
:: Pull Docker images.
if "%1" == "pull" docker login docker.pkg.github.com & docker compose %COMPOSE_FILE% pull
:: Down all services.
if "%1" == "down" docker compose %COMPOSE_FILE% down
:: Stop all services.
if "%1" == "stop" docker compose %COMPOSE_FILE% stop %SERVICES%
:: Restart all services.
if "%1" == "restart" docker compose %COMPOSE_FILE% restart %SERVICES%
:: Remove all services containers.
if "%1" == "rm" docker compose %COMPOSE_FILE% rm -f %SERVICES%
:: Tail all logs with -n 1000.
if "%1" == "logs" docker compose %COMPOSE_FILE% logs --follow --tail=1000 %SERVICES%
:: Show all Docker images.
if "%1" == "images" docker compose %COMPOSE_FILE% images %SERVICES%
:: Remove containers and delete volume data.
if "%1" == "prune" docker compose %COMPOSE_FILE% stop %SERVICES% & docker compose %COMPOSE_FILE% rm -f %SERVICES% & docker volume prune -f
:: Show this help.
if "%1" == "help" @echo Make application Docker images and manage containers using Docker Compose files only for Windows.
