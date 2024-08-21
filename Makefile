include .env
.DEFAULT_GOAL:=help

# Define RENGINE_VERSION
RENGINE_VERSION := $(shell cat web/reNgine/version.txt)
export RENGINE_VERSION

# Credits: https://github.com/sherifabdlnaby/elastdocker/

# This for future release of Compose that will use Docker Buildkit, which is much efficient.
COMPOSE_PREFIX_CMD	  := COMPOSE_DOCKER_CLI_BUILD=1
COMPOSE_CMD 		  := docker compose
COMPOSE_FILE	      := docker/docker-compose.yml
COMPOSE_FILE_BUILD	  := docker/docker-compose.build.yml
COMPOSE_FILE_DEV      := docker/docker-compose.dev.yml
COMPOSE_FILE_SETUP    := docker/docker-compose.setup.yml
SERVICES              := db web proxy redis celery celery-beat ollama

# Check if 'docker compose' command is available, otherwise use 'docker-compose'
DOCKER_COMPOSE := $(shell if command -v docker > /dev/null && docker compose version > /dev/null 2>&1; then echo "docker compose"; else echo "docker-compose"; fi)
$(info Using: $(shell echo "$(DOCKER_COMPOSE)"))

# Define common commands
DOCKER_COMPOSE_CMD      := ${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE}
DOCKER_COMPOSE_FILE_CMD := ${DOCKER_COMPOSE_CMD} -f ${COMPOSE_FILE}

# --------------------------

.PHONY: setup certs up build username pull down stop restart rm logs

certs:		    ## Generate certificates.
	@${DOCKER_COMPOSE_CMD} -f ${COMPOSE_FILE_SETUP} run --rm certs

up:				## Pull and start all services.
	${DOCKER_COMPOSE_FILE_CMD} up -d ${SERVICES}

dev_up:			## Pull and start all services with development configuration (more debug logs and Django Toolbar in UI).
	${DOCKER_COMPOSE_FILE_CMD} -f ${COMPOSE_FILE_DEV} up -d ${SERVICES}

build_up:		## Build and start all services.
	@make build
	@make up

build:			## Build all Docker images locally.
	${DOCKER_COMPOSE_FILE_CMD} -f ${COMPOSE_FILE_BUILD} build ${SERVICES}

pull:			## Pull prebuilt Docker images from repository.
	${DOCKER_COMPOSE_FILE_CMD} pull

username:		## Generate Username (Use only after make up).
ifeq ($(isNonInteractive), true)
	${DOCKER_COMPOSE_FILE_CMD} exec web poetry -C /home/rengine run python3 manage.py createsuperuser --username ${DJANGO_SUPERUSER_USERNAME} --email ${DJANGO_SUPERUSER_EMAIL} --noinput
else
	${DOCKER_COMPOSE_FILE_CMD} exec web poetry -C /home/rengine run python3 manage.py createsuperuser
endif

changepassword:	## Change password for user (Use only after make up & make username).
	${DOCKER_COMPOSE_FILE_CMD} exec web poetry -C /home/rengine run python3 manage.py changepassword

migrate:		## Apply Django migrations
	${DOCKER_COMPOSE_FILE_CMD} exec web poetry -C /home/rengine run python3 manage.py migrate

down:			## Down all services and remove containers.
	${DOCKER_COMPOSE_FILE_CMD} down

stop:			## Stop all services.
	${DOCKER_COMPOSE_FILE_CMD} stop ${SERVICES}

restart:		## Restart specified services or all if not specified. Use DEV=1 for development mode, COLD=1 for down and up instead of restart.
	@if [ "$(COLD)" = "1" ]; then \
		if [ "$(DEV)" = "1" ]; then \
			if [ -n "$(filter-out $@,$(MAKECMDGOALS))" ]; then \
				echo "Cold restart $(filter-out $@,$(MAKECMDGOALS)) in dev mode"; \
				${DOCKER_COMPOSE_FILE_CMD} -f ${COMPOSE_FILE_DEV} down $(filter-out $@,$(MAKECMDGOALS)); \
				${DOCKER_COMPOSE_FILE_CMD} -f ${COMPOSE_FILE_DEV} up -d $(filter-out $@,$(MAKECMDGOALS)); \
			else \
				echo "Cold restart ${SERVICES} in dev mode"; \
				${DOCKER_COMPOSE_FILE_CMD} -f ${COMPOSE_FILE_DEV} down; \
				${DOCKER_COMPOSE_FILE_CMD} -f ${COMPOSE_FILE_DEV} up -d ${SERVICES}; \
			fi \
		else \
			if [ -n "$(filter-out $@,$(MAKECMDGOALS))" ]; then \
				echo "Cold restart $(filter-out $@,$(MAKECMDGOALS)) in production mode"; \
				${DOCKER_COMPOSE_FILE_CMD} down $(filter-out $@,$(MAKECMDGOALS)); \
				${DOCKER_COMPOSE_FILE_CMD} up -d $(filter-out $@,$(MAKECMDGOALS)); \
			else \
				echo "Cold restart ${SERVICES} in production mode"; \
				${DOCKER_COMPOSE_FILE_CMD} down; \
				${DOCKER_COMPOSE_FILE_CMD} up -d ${SERVICES}; \
			fi \
		fi \
	else \
		if [ "$(DEV)" = "1" ]; then \
			if [ -n "$(filter-out $@,$(MAKECMDGOALS))" ]; then \
				echo "Restart $(filter-out $@,$(MAKECMDGOALS)) in dev mode"; \
				${DOCKER_COMPOSE_FILE_CMD} -f ${COMPOSE_FILE_DEV} restart $(filter-out $@,$(MAKECMDGOALS)); \
			else \
				echo "Restart ${SERVICES} in dev mode"; \
				${DOCKER_COMPOSE_FILE_CMD} -f ${COMPOSE_FILE_DEV} restart ${SERVICES}; \
			fi \
		else \
			if [ -n "$(filter-out $@,$(MAKECMDGOALS))" ]; then \
				echo "Restart $(filter-out $@,$(MAKECMDGOALS)) in production mode"; \
				${DOCKER_COMPOSE_FILE_CMD} restart $(filter-out $@,$(MAKECMDGOALS)); \
			else \
				echo "Restart ${SERVICES} in production mode"; \
				${DOCKER_COMPOSE_FILE_CMD} restart ${SERVICES}; \
			fi \
		fi \
	fi

rm:				## Remove all services containers.
	${DOCKER_COMPOSE_FILE_CMD} rm -f ${SERVICES}

test:
	${DOCKER_COMPOSE_FILE_CMD} exec celery poetry -C /home/rengine run python3 -m unittest tests/test_scan.py

logs:			## Tail all containers logs with -n 1000 (useful for debug).
	${DOCKER_COMPOSE_FILE_CMD} logs --follow --tail=1000 ${SERVICES}

images:			## Show all Docker images.
	${DOCKER_COMPOSE_FILE_CMD} images ${SERVICES}

prune:			## Remove containers and delete volume data.
	@make stop && make rm && docker volume prune -f

help:			## Show this help.
	@echo "Manage Docker images, containers and Django commands using Docker Compose files."
	@echo ""
	@echo "Usage:"
	@echo "  make <target> (default: help)"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*##"; printf "  \033[36m%-15s\033[0m %s\n", "Target", "Description"}' $(MAKEFILE_LIST)
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo ""
	@echo "Special commands:"
	@echo "  make restart [service1] [service2] ...  				Restart specific services in production mode"
	@echo "  make restart DEV=1 [service1] [service2] ...  			Restart specific services in development mode"
	@echo "  make restart                            				Restart all services in production mode"
	@echo "  make restart DEV=1                     				Restart all services in development mode"
	@echo "  make restart COLD=1 [service1] [service2] ... 			Cold restart (recreate containers) specific services in production mode"
	@echo "  make restart DEV=1 COLD=1 [service1] [service2] ...  	Cold restart (recreate containers) specific services in development mode"
	@echo "  make restart COLD=1                     				Cold restart (recreate containers) all services in production mode"
	@echo "  make restart DEV=1 COLD=1               				Cold restart (recreate containers) all services in development mode"

%:
