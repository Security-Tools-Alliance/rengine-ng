include .env
.DEFAULT_GOAL:=help

# Export host UID & GID
export HOST_UID=$(if $(SUDO_USER),$(shell id -u $(SUDO_USER)),$(shell id -u))
export HOST_GID=$(if $(SUDO_USER),$(shell id -g $(SUDO_USER)),$(shell id -g))


# Define RENGINE_VERSION
RENGINE_VERSION := $(shell cat web/reNgine/version.txt)
export RENGINE_VERSION

# Define RENGINE_FOLDER
RENGINE_FOLDER := /home/rengine/rengine
export RENGINE_FOLDER

# Credits: https://github.com/sherifabdlnaby/elastdocker/

# This for future release of Compose that will use Docker Buildkit, which is much efficient.
COMPOSE_PREFIX_CMD	  := COMPOSE_DOCKER_CLI_BUILD=1
COMPOSE_CMD 		  := docker compose
COMPOSE_FILE	      := docker/docker-compose.yml
COMPOSE_FILE_BUILD	  := docker/docker-compose.build.yml
COMPOSE_FILE_DEV      := docker/docker-compose.dev.yml
COMPOSE_FILE_SETUP    := docker/docker-compose.setup.yml
SERVICES              := db web proxy redis celery celery-beat ollama

# Check if 'docker compose' command is available, otherwise check for 'docker-compose'
DOCKER_COMPOSE := $(shell if command -v docker > /dev/null && docker compose version > /dev/null 2>&1; then echo "docker compose"; elif command -v docker-compose > /dev/null; then echo "docker-compose"; else echo ""; fi)

ifeq ($(DOCKER_COMPOSE),)
$(error Docker Compose not found. Please install Docker Compose)
endif

# Check if user is in docker group or is root
DOCKER_GROUP_CHECK := $(shell if [ -n "$$(getent group docker)" ]; then echo "yes"; else echo "no"; fi)

ifeq ($(DOCKER_GROUP_CHECK),no)
$(error This command must be run with sudo or by a user in the docker group)
endif

$(info Using: $(DOCKER_COMPOSE))

# Define common commands
DOCKER_COMPOSE_CMD      := ${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE}
DOCKER_COMPOSE_FILE_CMD := ${DOCKER_COMPOSE_CMD} -f ${COMPOSE_FILE}

# --------------------------

.PHONY: certs up dev_up build_up build pull superuser_create superuser_delete superuser_changepassword migrate down stop restart remove_images test logs images prune help

pull:			## Pull pre-built Docker images from repository.
	${DOCKER_COMPOSE_FILE_CMD} pull

images:			## Show all Docker images for reNgine services.
	@docker images --filter=reference='ghcr.io/security-tools-alliance/rengine-ng:*' --format "table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}"

build:			## Build all Docker images locally.
	@make remove_images
	${DOCKER_COMPOSE_FILE_CMD} -f ${COMPOSE_FILE_BUILD} build --build-arg HOST_UID=$(HOST_UID) --build-arg HOST_GID=$(HOST_GID) ${SERVICES}

build_up:		## Build and start all services.
	@make down
	@make build
	@make up

certs:		    ## Generate certificates.
	@${DOCKER_COMPOSE_CMD} -f ${COMPOSE_FILE_SETUP} run --rm certs

up:				## Pull and start all services.
	${DOCKER_COMPOSE_FILE_CMD} up -d ${SERVICES}

dev_up:			## Pull and start all services with development configuration (more debug logs and Django Toolbar in UI).
	@make down
	${DOCKER_COMPOSE_FILE_CMD} -f ${COMPOSE_FILE_DEV} up -d ${SERVICES}

superuser_create:		## Generate username (use only after `make up`).
ifeq ($(isNonInteractive), true)
	${DOCKER_COMPOSE_FILE_CMD} exec web poetry -C ${RENGINE_FOLDER} run python3 manage.py createsuperuser --username ${DJANGO_SUPERUSER_USERNAME} --email ${DJANGO_SUPERUSER_EMAIL} --noinput
else
	${DOCKER_COMPOSE_FILE_CMD} exec web poetry -C ${RENGINE_FOLDER} run python3 manage.py createsuperuser
endif

superuser_delete:		## Delete username (use only after `make up`).
	${DOCKER_COMPOSE_FILE_CMD} exec -T web poetry -C ${RENGINE_FOLDER} run python3 manage.py shell -c "from django.contrib.auth import get_user_model; User = get_user_model(); User.objects.filter(username='${DJANGO_SUPERUSER_USERNAME}').delete()"

superuser_changepassword:	## Change password for user (use only after `make up` & `make username`).
ifeq ($(isNonInteractive), true)
	${DOCKER_COMPOSE_FILE_CMD} exec -T web poetry -C ${RENGINE_FOLDER} run python3 manage.py shell -c "from django.contrib.auth import get_user_model; User = get_user_model(); u = User.objects.get(username='${DJANGO_SUPERUSER_USERNAME}'); u.set_password('${DJANGO_SUPERUSER_PASSWORD}'); u.save()"
else
	${DOCKER_COMPOSE_FILE_CMD} exec web poetry -C ${RENGINE_FOLDER} run python3 manage.py changepassword
endif

migrate:		## Apply Django migrations
	${DOCKER_COMPOSE_FILE_CMD} exec web poetry -C ${RENGINE_FOLDER} run python3 manage.py migrate

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

remove_images:	## Remove all Docker images for reNgine-ng services.
	@images=$$(docker images --filter=reference='ghcr.io/security-tools-alliance/rengine-ng:*' --format "{{.ID}}"); \
	if [ -n "$$images" ]; then \
		echo "Removing images: $$images"; \
		docker rmi -f $$images; \
	else \
		echo "No images found for ghcr.io/security-tools-alliance/rengine-ng"; \
	fi

test:
	${DOCKER_COMPOSE_FILE_CMD} exec celery poetry -C ${RENGINE_FOLDER} run python3 -m unittest tests/test_scan.py

logs:			## Tail all containers logs with -n 1000 (useful for debug).
	${DOCKER_COMPOSE_FILE_CMD} logs --follow --tail=1000 ${SERVICES}

prune:			## Remove containers, delete volume data, and prune Docker system.
	@make down
	@make remove_images
	@docker volume rm $$(docker volume ls -q --filter name=rengine_) 2>/dev/null || true
	@docker system prune -af --volumes

help:			## Show this help.
	@echo "Manage Docker images, containers and Django commands using Docker Compose files."
	@echo ""
	@echo "Usage:"
	@echo "  make <target> (default: help)"
	@echo ""
	@echo "Targets:"
	@echo "  make restart [service1] [service2] ...  				Restart specific services in production mode"
	@echo "  make restart DEV=1 [service1] [service2] ...  			Restart specific services in development mode"
	@echo "  make restart                            				Restart all services in production mode"
	@echo "  make restart DEV=1                     				Restart all services in development mode"
	@echo "  make restart COLD=1 [service1] [service2] ... 			Cold restart (recreate containers) specific services in production mode"
	@echo "  make restart DEV=1 COLD=1 [service1] [service2] ...  	Cold restart (recreate containers) specific services in development mode"
	@echo "  make restart COLD=1                     				Cold restart (recreate containers) all services in production mode"
	@echo "  make restart DEV=1 COLD=1               				Cold restart (recreate containers) all services in development mode"

%:
	@:
