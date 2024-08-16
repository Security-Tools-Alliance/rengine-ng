include .env
.DEFAULT_GOAL:=help

# Define RENGINE_VERSION
RENGINE_VERSION := $(shell cat web/reNgine/version.txt)
export RENGINE_VERSION

# Credits: https://github.com/sherifabdlnaby/elastdocker/

# This for future release of Compose that will use Docker Buildkit, which is much efficient.
COMPOSE_PREFIX_CMD	  := COMPOSE_DOCKER_CLI_BUILD=1
COMPOSE_CMD 		  := docker compose
COMPOSE_FILE	      := -f docker/docker-compose.yml
COMPOSE_FILE_BUILD	  := -f docker/docker-compose.yml -f docker/docker-compose.build.yml
COMPOSE_DEV_FILE      := -f docker/docker-compose.yml -f docker/docker-compose.dev.yml
SERVICES              := db web proxy redis celery celery-beat ollama

# Check if 'docker compose' command is available, otherwise use 'docker-compose'
DOCKER_COMPOSE := $(shell if command -v docker > /dev/null && docker compose version > /dev/null 2>&1; then echo "docker compose"; else echo "docker-compose"; fi)
$(info Using: $(shell echo "$(DOCKER_COMPOSE)"))

# --------------------------

.PHONY: setup certs up build username pull down stop restart rm logs

certs:		    ## Generate certificates.
	@${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} -f docker/docker-compose.setup.yml run --rm certs

setup:			## Generate certificates.
	@make certs

up:				## Build and start all services.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_FILE} up -d ${SERVICES}

pull_up:			## Pull Docker images.
	@make pull
	@make up

build_up:		## Build and start all services.
	@make build
	@make up

build:			## Build all services.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_FILE_BUILD} build ${SERVICES}

username:		## Generate Username (Use only after make up).
ifeq ($(isNonInteractive), true)
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_FILE} exec web poetry -C /home/rengine run python3 manage.py createsuperuser --username ${DJANGO_SUPERUSER_USERNAME} --email ${DJANGO_SUPERUSER_EMAIL} --noinput
else
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_FILE} exec web poetry -C /home/rengine run python3 manage.py createsuperuser
endif

changepassword:	## Change password for user
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_FILE} exec web poetry -C /home/rengine run python3 manage.py changepassword

migrate:		## Apply migrations
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_FILE} exec web poetry -C /home/rengine run python3 manage.py migrate

pull:			## Pull Docker images.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_FILE} pull

down:			## Down all services.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_FILE} down

stop:			## Stop all services.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_FILE} stop ${SERVICES}

restart:		## Restart all services.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_FILE} restart ${SERVICES}

rm:				## Remove all services containers.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} $(COMPOSE_FILE) rm -f ${SERVICES}

test:
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} $(COMPOSE_FILE) exec celery poetry -C /home/rengine run python3 -m unittest tests/test_scan.py

logs:			## Tail all logs with -n 1000.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} $(COMPOSE_FILE) logs --follow --tail=1000 ${SERVICES}

images:			## Show all Docker images.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} $(COMPOSE_FILE) images ${SERVICES}

prune:			## Remove containers and delete volume data.
	@make stop && make rm && docker volume prune -f

help:			## Show this help.
	@echo "Make application Docker images and manage containers using Docker Compose files."
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m (default: help)\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

dev_build:			## Build all services.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_DEV_FILE} build ${SERVICES_DEV}

dev_up:				## Build and start all services.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_DEV_FILE} up -d ${SERVICES_DEV}

dev_down:			## Down all services.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} ${COMPOSE_DEV_FILE} down

dev_logs:			## Tail all logs with -n 1000.
	${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE} $(COMPOSE_DEV_FILE) logs --follow --tail=1000 ${SERVICES_DEV}