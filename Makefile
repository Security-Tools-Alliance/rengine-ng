include .env
.DEFAULT_GOAL:=help

# Operating system detection (must be early to use in conditional exports)
UNAME_S := $(shell uname -s)
IS_MACOS := $(shell if [ "$(UNAME_S)" = "Darwin" ]; then echo "yes"; else echo "no"; fi)

# Export host UID & GID (cross-platform handling)
ifeq ($(IS_MACOS),yes)
# On macOS, use safe defaults to avoid conflicts with system groups (GID 20 = staff)
# Docker Desktop handles file permission mapping automatically
export HOST_UID=1000
export HOST_GID=1000
else
# On Linux, respect sudo context for proper permissions
export HOST_UID=$(if $(SUDO_USER),$(shell id -u $(SUDO_USER)),$(shell id -u))
export HOST_GID=$(if $(SUDO_USER),$(shell id -g $(SUDO_USER)),$(shell id -g))
endif


# Define RENGINE_VERSION
RENGINE_VERSION := $(shell cat web/reNgine/version.txt)
export RENGINE_VERSION

# Define RENGINE_FOLDER
RENGINE_HOME_FOLDER := /home/rengine
RENGINE_FOLDER := ${RENGINE_HOME_FOLDER}/rengine
export RENGINE_FOLDER

# Export Postgres vars from .env for docker compose substitution (e.g. pgbouncer service)
export POSTGRES_USER
export POSTGRES_PASSWORD
export POSTGRES_DB

# Direct DB host/port for migrate (bypass PgBouncer to avoid transaction-pool issues).
export POSTGRES_DIRECT_HOST ?= db
export POSTGRES_DIRECT_PORT ?= 5432

# Database backup/restore (host path for postgres volume data).
# Override with: make db-backup PG_VOLUME=/path/to/volume or export PG_VOLUME=...
BACKUP_DIR     := backup
PG_VOLUME      ?= /var/lib/docker/volumes/rengine_postgres_data
PG_VOLUME_DATA := $(PG_VOLUME)/_data

# Credits: https://github.com/sherifabdlnaby/elastdocker/

# This for future release of Compose that will use Docker Buildkit, which is much efficient.
COMPOSE_PREFIX_CMD	  := COMPOSE_DOCKER_CLI_BUILD=1
COMPOSE_CMD 		  := docker compose
COMPOSE_FILE	      := docker/docker-compose.yml
COMPOSE_FILE_BUILD	  := docker/docker-compose.build.yml
COMPOSE_FILE_DEV      := docker/docker-compose.dev.yml
COMPOSE_FILE_SETUP    := docker/docker-compose.setup.yml
COMPOSE_FILE_GPU      := docker/docker-compose.gpu.yml
SERVICES              := db pgbouncer web proxy redis worker ollama

# Check if 'docker compose' command is available, otherwise check for 'docker-compose'
DOCKER_COMPOSE := $(shell if command -v docker > /dev/null && docker compose version > /dev/null 2>&1; then echo "docker compose"; elif command -v docker-compose > /dev/null; then echo "docker-compose"; else echo ""; fi)

ifeq ($(DOCKER_COMPOSE),)
$(error Docker Compose not found. Please install Docker Compose)
endif

# Check if user has Docker access (different on macOS vs Linux)
ifeq ($(IS_MACOS),yes)
# On macOS, Docker Desktop handles permissions differently
DOCKER_ACCESS_CHECK := $(shell if docker version > /dev/null 2>&1; then echo "yes"; else echo "no"; fi)
ifeq ($(DOCKER_ACCESS_CHECK),no)
$(error Docker is not accessible. Please ensure Docker Desktop is running)
endif
else
# On Linux, check if user is in docker group or is root
DOCKER_GROUP_CHECK := $(shell if [ -n "$$(getent group docker 2>/dev/null)" ]; then echo "yes"; else echo "no"; fi)
ifeq ($(DOCKER_GROUP_CHECK),no)
$(error This command must be run with sudo or by a user in the docker group)
endif
endif

$(info Using: $(DOCKER_COMPOSE))

# Define common commands
DOCKER_COMPOSE_CMD      := ${COMPOSE_PREFIX_CMD} ${DOCKER_COMPOSE}
DOCKER_COMPOSE_FILE_CMD := ${DOCKER_COMPOSE_CMD} -f ${COMPOSE_FILE}

# Add GPU variable with default value
GPU ?= 0

# Function to handle GPU configuration
define gpu_config
	$(info Checking GPU configuration...)
	$(if $(filter 1,$(GPU)), \
		$(info GPU=1, detecting GPU type...) \
		$(eval GPU_TYPE := $(shell ./scripts/gpu_support.sh)) \
		$(if $(filter nvidia,$(GPU_TYPE)), \
			$(info Configuring for NVIDIA GPU) \
			$(eval DOCKER_RUNTIME := nvidia) \
			$(eval COMPOSE_GPU_FILE := -f ${COMPOSE_FILE_GPU} --profile gpu), \
			$(if $(filter amd,$(GPU_TYPE)), \
				$(info Configuring for AMD GPU) \
				$(eval DOCKER_RUNTIME := amd) \
				$(eval COMPOSE_GPU_FILE := -f ${COMPOSE_FILE_GPU} --profile gpu), \
				$(info No supported GPU detected) \
				$(eval COMPOSE_GPU_FILE :=) \
			) \
		), \
		$(info GPU support disabled) \
		$(eval COMPOSE_GPU_FILE :=) \
	)
	$(eval export GPU_TYPE) \
	$(eval export DOCKER_RUNTIME)
endef

.PHONY: certs up dev_up build_up build build-service pull superuser_create superuser_delete superuser_changepassword makemigrations migrate down stop restart remove_images test test-app test-verbose test-app-verbose ruff-format ruff-check ruff-fix ruff-unsafe-fix logs images prune help db-backup db-restore db-list secator-init secator-key secator-load secator-check secator-health update-check

pull:			## Pull pre-built Docker images from repository.
	${DOCKER_COMPOSE_FILE_CMD} pull

images:			## Show all Docker images for reNgine services.
	@docker images --filter=reference='ghcr.io/security-tools-alliance/rengine-ng:*' --format "table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}"

build:			## Build all Docker images locally. Use GPU=1 to enable GPU support.
	@make remove_images
	$(call gpu_config)
	${DOCKER_COMPOSE_FILE_CMD} -f ${COMPOSE_FILE_BUILD} ${COMPOSE_GPU_FILE} build --build-arg HOST_UID=$(HOST_UID) --build-arg HOST_GID=$(HOST_GID) ${SERVICES}

build-service:		## Build a specific Docker service without removing images. Usage: make build-service SERVICE=<service_name> [GPU=1] [REBUILD=1]
	@if [ -z "$(SERVICE)" ]; then \
		echo "Error: SERVICE parameter is required. Usage: make build-service SERVICE=<service_name>"; \
		echo "Available services: ${SERVICES}"; \
		exit 1; \
	fi
	@if ! echo "${SERVICES}" | grep -wq "$(SERVICE)"; then \
		echo "Error: Service '$(SERVICE)' is not valid. Available services: ${SERVICES}"; \
		exit 1; \
	fi
	@if [ "$(REBUILD)" = "1" ]; then \
		echo "REBUILD=1 detected, removing $(SERVICE) image before build..."; \
		# Map service names to image names \
		case "$(SERVICE)" in \
			"db") IMAGE_NAME="postgres" ;; \
			*) IMAGE_NAME="$(SERVICE)" ;; \
		esac; \
		image_id=$$(docker images --filter=reference="ghcr.io/security-tools-alliance/rengine-ng:rengine-$$IMAGE_NAME-v$(RENGINE_VERSION)" --format "{{.ID}}" | head -1); \
		if [ -n "$$image_id" ]; then \
			echo "Removing image: ghcr.io/security-tools-alliance/rengine-ng:rengine-$$IMAGE_NAME-v$(RENGINE_VERSION) ($$image_id)"; \
			docker rmi -f "$$image_id" || true; \
		else \
			echo "No existing image found for ghcr.io/security-tools-alliance/rengine-ng:rengine-$$IMAGE_NAME-v$(RENGINE_VERSION)"; \
		fi \
	fi
	$(call gpu_config)
	@if [ "$(REBUILD)" = "1" ]; then \
		${DOCKER_COMPOSE_FILE_CMD} -f ${COMPOSE_FILE_BUILD} ${COMPOSE_GPU_FILE} build --no-cache --build-arg HOST_UID=$(HOST_UID) --build-arg HOST_GID=$(HOST_GID) $(SERVICE) --progress=plain; \
	else \
		${DOCKER_COMPOSE_FILE_CMD} -f ${COMPOSE_FILE_BUILD} ${COMPOSE_GPU_FILE} build --build-arg HOST_UID=$(HOST_UID) --build-arg HOST_GID=$(HOST_GID) $(SERVICE) --progress=plain; \
	fi

build_up:		## Build and start all services.
	@make down
	@make build
	@make up

certs:		    ## Generate certificates.
	@${DOCKER_COMPOSE_CMD} -f ${COMPOSE_FILE_SETUP} run --rm certs

up:				## Pull and start all services. Use GPU=1 to enable GPU support.
	$(call gpu_config)
	${DOCKER_COMPOSE_FILE_CMD} ${COMPOSE_GPU_FILE} up -d ${SERVICES}

dev_up:			## Pull and start all services with development configuration. Use GPU=1 to enable GPU support.
	@make down
	$(call gpu_config)
	${DOCKER_COMPOSE_FILE_CMD} -f ${COMPOSE_FILE_DEV} ${COMPOSE_GPU_FILE} up -d ${SERVICES}

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

makemigrations:		## Create Django migrations (connects to PostgreSQL directly, not via PgBouncer).
	${DOCKER_COMPOSE_FILE_CMD} exec -e POSTGRES_HOST=$(POSTGRES_DIRECT_HOST) -e POSTGRES_PORT=$(POSTGRES_DIRECT_PORT) web poetry -C ${RENGINE_FOLDER} run python3 manage.py makemigrations

migrate:		## Apply Django migrations (connects to PostgreSQL directly, not via PgBouncer).
	${DOCKER_COMPOSE_FILE_CMD} exec -e POSTGRES_HOST=$(POSTGRES_DIRECT_HOST) -e POSTGRES_PORT=$(POSTGRES_DIRECT_PORT) web poetry -C ${RENGINE_FOLDER} run python3 manage.py migrate

db-list:		## List available database backups in $(BACKUP_DIR).
	@mkdir -p $(BACKUP_DIR)
	@list=$$(ls -1 $(BACKUP_DIR)/postgres_*.tar.gz 2>/dev/null | sort -r); \
	if [ -z "$$list" ]; then \
		echo "No backups in $(BACKUP_DIR)/"; \
		exit 0; \
	fi; \
	echo "Available backups:"; \
	n=1; for f in $$list; do echo "  $$n) $$(basename $$f .tar.gz)"; n=$$((n+1)); done

db-backup:		## Create a timestamped database backup in $(BACKUP_DIR). Stops db briefly for consistency.
	@mkdir -p $(BACKUP_DIR)
	@backup_name="postgres_$$(date +%Y-%m-%d_%H%M%S)"; \
	echo "Stopping db..."; ${DOCKER_COMPOSE_FILE_CMD} stop db; \
	echo "Creating $$backup_name.tar.gz..."; \
	if sudo tar czf $(BACKUP_DIR)/$$backup_name.tar.gz.tmp -C $(PG_VOLUME) _data; then \
		mv $(BACKUP_DIR)/$$backup_name.tar.gz.tmp $(BACKUP_DIR)/$$backup_name.tar.gz; \
	else \
		rm -f $(BACKUP_DIR)/$$backup_name.tar.gz.tmp; \
		echo "Backup failed (tar error)."; \
		${DOCKER_COMPOSE_FILE_CMD} start db; \
		exit 1; \
	fi; \
	echo "Starting db..."; ${DOCKER_COMPOSE_FILE_CMD} start db; \
	echo "Done. Backup: $(BACKUP_DIR)/$$backup_name.tar.gz"

db-restore:		## Restore database from backup. Use BACKUP=name (without .tar.gz) or run without BACKUP to choose by number.
	@backup_arg="$(BACKUP)"; \
	if [ -z "$$backup_arg" ]; then \
		list=$$(ls -1 $(BACKUP_DIR)/postgres_*.tar.gz 2>/dev/null | sort -r); \
		if [ -z "$$list" ]; then echo "No backups in $(BACKUP_DIR)/. Run make db-backup first."; exit 1; fi; \
		echo "Available backups:"; \
		n=1; for f in $$list; do echo "  $$n) $$(basename $$f .tar.gz)"; n=$$((n+1)); done; \
		n_max=$$((n-1)); \
		echo -n "Enter number (1-$$n_max): "; read choice; \
		if [ -z "$$choice" ]; then echo "Invalid selection: empty choice."; exit 1; fi; \
		case "$$choice" in *[!0-9]*) echo "Invalid selection: '$$choice' is not a positive integer."; exit 1 ;; esac; \
		if [ "$$choice" -lt 1 ] || [ "$$choice" -gt "$$n_max" ]; then echo "Invalid selection: '$$choice' is out of range (1-$$n_max)."; exit 1; fi; \
		backup_file=$$(echo "$$list" | sed -n "$${choice}p"); \
		backup_arg=$$(basename $$backup_file .tar.gz); \
	fi; \
	if [ ! -f "$(BACKUP_DIR)/$$backup_arg.tar.gz" ]; then echo "Backup not found: $(BACKUP_DIR)/$$backup_arg.tar.gz"; exit 1; fi; \
	echo "Stopping db..."; ${DOCKER_COMPOSE_FILE_CMD} stop db; \
	pg_data="$(PG_VOLUME_DATA)"; \
	if [ -z "$$pg_data" ]; then echo "Error: PG_VOLUME_DATA is empty. Aborting restore."; ${DOCKER_COMPOSE_FILE_CMD} start db; exit 1; fi; \
	if [ "$$pg_data" = "/" ] || [ "$$pg_data" = "/_data" ]; then echo "Error: PG_VOLUME_DATA must not be / or /_data. Aborting restore."; ${DOCKER_COMPOSE_FILE_CMD} start db; exit 1; fi; \
	if [ -d "$$pg_data" ] && [ -n "$$(ls -A $$pg_data 2>/dev/null)" ] && [ ! -f "$$pg_data/PG_VERSION" ] && [ ! -d "$$pg_data/base" ]; then echo "Error: $$pg_data does not look like a Postgres data directory (missing PG_VERSION or base/). Aborting restore."; ${DOCKER_COMPOSE_FILE_CMD} start db; exit 1; fi; \
	echo "Restoring from $$backup_arg.tar.gz..."; \
	sudo rm -rf $$pg_data/*; \
	sudo tar xvzf $(BACKUP_DIR)/$$backup_arg.tar.gz -C $(PG_VOLUME); \
	echo "Starting db..."; ${DOCKER_COMPOSE_FILE_CMD} start db; \
	echo "Done."

# Secator Initialization Targets
secator-init:		## Initialize Secator (generate API key + load all from Secator)
	@echo "=== Secator Initialization ==="
	@make secator-key
	@make secator-load

secator-key:		## Generate Secator API key only if none exists (use --recreate in manage.py for regeneration)
	@echo "=== Generating Secator API Key (if missing) ==="
	${DOCKER_COMPOSE_FILE_CMD} exec web poetry -C ${RENGINE_FOLDER} run python3 manage.py generate_secator_api_key --show-key

secator-load:		## Load Secator components (tasks, workflows, scans)
	@echo "=== Loading Secator Components ==="
	${DOCKER_COMPOSE_FILE_CMD} exec web poetry -C ${RENGINE_FOLDER} run python3 manage.py load_secator_all

update-check:		## Check if a reNgine-ng update is available (current vs GitHub latest release)
	${DOCKER_COMPOSE_FILE_CMD} exec web poetry -C ${RENGINE_FOLDER} run python3 manage.py rengine_update_check

secator-check:		## Check Secator configuration and status
	@echo "=== Checking Secator Configuration ==="
	@echo "Checking API key..."
	${DOCKER_COMPOSE_FILE_CMD} exec web poetry -C ${RENGINE_FOLDER} run python3 manage.py generate_secator_api_key
	@echo ""
	@echo "Checking loaded tasks..."
	${DOCKER_COMPOSE_FILE_CMD} exec web poetry -C ${RENGINE_FOLDER} run python3 manage.py shell -c "from scanEngine.models import Task; print(f'Tasks loaded: {Task.objects.count()}')"
	@echo "Checking loaded workflows..."
	${DOCKER_COMPOSE_FILE_CMD} exec web poetry -C ${RENGINE_FOLDER} run python3 manage.py shell -c "from scanEngine.models import Workflow; print(f'Workflows loaded: {Workflow.objects.count()}')"
	@echo "Checking loaded scans..."
	${DOCKER_COMPOSE_FILE_CMD} exec web poetry -C ${RENGINE_FOLDER} run python3 manage.py shell -c "from scanEngine.models import Scan; print(f'Scans loaded: {Scan.objects.count()}')"

# SECATOR_HEALTH_URL defaults to local reNgine instance; override for remote (e.g. SECATOR_HEALTH_URL=https://rengine.example.com/api/secator/health/)
SECATOR_HEALTH_URL ?= https://127.0.0.1/api/secator/health/
secator-health:		## Test Secator API health (findings endpoint). Uses SECATOR_ADDONS_API_KEY from .env; override URL with SECATOR_HEALTH_URL=...
	@if [ -z "$(SECATOR_ADDONS_API_KEY)" ]; then \
		echo "Error: SECATOR_ADDONS_API_KEY is not set in .env. Run 'make secator-key' or set it in .env."; \
		exit 1; \
	fi
	@echo "Testing Secator API health at $(SECATOR_HEALTH_URL)..."
	@code=$$(curl -k -s -o /dev/null -w "%{http_code}" -I "$(SECATOR_HEALTH_URL)" -H "Authorization: Api-Key $(SECATOR_ADDONS_API_KEY)"); \
	if [ "$$code" = "200" ]; then echo "Secator API health check OK (HTTP $$code)"; else echo "Secator API health check failed (HTTP $$code)"; exit 1; fi

down:			## Down all services and remove containers.
	${DOCKER_COMPOSE_FILE_CMD} down

stop:			## Stop all services.
	${DOCKER_COMPOSE_FILE_CMD} stop ${SERVICES}

restart:		## Restart specified services or all if not specified. Use DEV=1 for development mode, COLD=1 for down and up instead of restart.
	$(call gpu_config)
	@if [ "$(COLD)" = "1" ]; then \
		if [ "$(DEV)" = "1" ]; then \
			if [ -n "$(filter-out $@,$(MAKECMDGOALS))" ]; then \
				echo "Cold restart $(filter-out $@,$(MAKECMDGOALS)) in dev mode"; \
				${DOCKER_COMPOSE_FILE_CMD} -f ${COMPOSE_FILE_DEV} ${COMPOSE_GPU_FILE} down $(filter-out $@,$(MAKECMDGOALS)); \
				${DOCKER_COMPOSE_FILE_CMD} -f ${COMPOSE_FILE_DEV} ${COMPOSE_GPU_FILE} up -d $(filter-out $@,$(MAKECMDGOALS)); \
			else \
				echo "Cold restart ${SERVICES} in dev mode"; \
				${DOCKER_COMPOSE_FILE_CMD} -f ${COMPOSE_FILE_DEV} ${COMPOSE_GPU_FILE} down; \
				${DOCKER_COMPOSE_FILE_CMD} -f ${COMPOSE_FILE_DEV} ${COMPOSE_GPU_FILE} up -d ${SERVICES}; \
			fi \
		else \
			if [ -n "$(filter-out $@,$(MAKECMDGOALS))" ]; then \
				echo "Cold restart $(filter-out $@,$(MAKECMDGOALS)) in production mode"; \
				${DOCKER_COMPOSE_FILE_CMD} ${COMPOSE_GPU_FILE} down $(filter-out $@,$(MAKECMDGOALS)); \
				${DOCKER_COMPOSE_FILE_CMD} ${COMPOSE_GPU_FILE} up -d $(filter-out $@,$(MAKECMDGOALS)); \
			else \
				echo "Cold restart ${SERVICES} in production mode"; \
				${DOCKER_COMPOSE_FILE_CMD} ${COMPOSE_GPU_FILE} down; \
				${DOCKER_COMPOSE_FILE_CMD} ${COMPOSE_GPU_FILE} up -d ${SERVICES}; \
			fi \
		fi \
	else \
		if [ "$(DEV)" = "1" ]; then \
			if [ -n "$(filter-out $@,$(MAKECMDGOALS))" ]; then \
				echo "Restart $(filter-out $@,$(MAKECMDGOALS)) in dev mode"; \
				${DOCKER_COMPOSE_FILE_CMD} -f ${COMPOSE_FILE_DEV} ${COMPOSE_GPU_FILE} restart $(filter-out $@,$(MAKECMDGOALS)); \
			else \
				echo "Restart ${SERVICES} in dev mode"; \
				${DOCKER_COMPOSE_FILE_CMD} -f ${COMPOSE_FILE_DEV} ${COMPOSE_GPU_FILE} restart ${SERVICES}; \
			fi \
		else \
			if [ -n "$(filter-out $@,$(MAKECMDGOALS))" ]; then \
				echo "Restart $(filter-out $@,$(MAKECMDGOALS)) in production mode"; \
				${DOCKER_COMPOSE_FILE_CMD} ${COMPOSE_GPU_FILE} restart $(filter-out $@,$(MAKECMDGOALS)); \
			else \
				echo "Restart ${SERVICES} in production mode"; \
				${DOCKER_COMPOSE_FILE_CMD} ${COMPOSE_GPU_FILE} restart ${SERVICES}; \
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

# Ruff commands for code quality
ruff-format:		## Format code using ruff formatter.
	${DOCKER_COMPOSE_FILE_CMD} exec web poetry -C ${RENGINE_FOLDER} run ruff format --config ${RENGINE_HOME_FOLDER}/pyproject.toml ${RENGINE_FOLDER}

ruff-check:		## Check code quality using ruff linter.
	${DOCKER_COMPOSE_FILE_CMD} exec web poetry -C ${RENGINE_FOLDER} run ruff check --config ${RENGINE_HOME_FOLDER}/pyproject.toml ${RENGINE_FOLDER}

ruff-fix:		## Fix code issues using ruff linter.
	${DOCKER_COMPOSE_FILE_CMD} exec web poetry -C ${RENGINE_FOLDER} run ruff check --fix --config ${RENGINE_HOME_FOLDER}/pyproject.toml ${RENGINE_FOLDER}

ruff-unsafe-fix:	## Fix code issues using ruff linter with unsafe fixes.
	${DOCKER_COMPOSE_FILE_CMD} exec web poetry -C ${RENGINE_FOLDER} run ruff check --fix --unsafe-fixes --config ${RENGINE_HOME_FOLDER}/pyproject.toml ${RENGINE_FOLDER}

# Test commands (KEEPDB=1 to keep test DB, VERBOSITY=1|2|3, defaults: no keepdb, verbosity 1)
VERBOSITY ?= 1
TEST_OPTS := --no-input $(if $(filter 1,$(KEEPDB)),--keepdb,) --verbosity $(VERBOSITY)

test:			## Run all unit tests for all apps. Options: KEEPDB=1, VERBOSITY=1|2|3
	${DOCKER_COMPOSE_FILE_CMD} exec web poetry -C ${RENGINE_FOLDER} run python3 manage.py test $(TEST_OPTS)

test-app:		## Run unit tests for specific app(s). Usage: make test-app APPS=app1,app2 [KEEPDB=1] [VERBOSITY=2]
	@if [ -z "$(APPS)" ]; then \
		echo "Error: APPS parameter is required. Usage: make test-app APPS=app1,app2"; \
		echo "Available apps: api, dashboard, recon_note, reNgine, scanEngine, startScan, targetApp"; \
		exit 1; \
	fi
	${DOCKER_COMPOSE_FILE_CMD} exec web poetry -C ${RENGINE_FOLDER} run python3 manage.py test $(APPS) $(TEST_OPTS)

test-verbose:		## Run all unit tests with verbose output (VERBOSITY=2).
	$(MAKE) test VERBOSITY=2

test-app-verbose:	## Run unit tests for specific app(s) with verbose output. Usage: make test-app-verbose APPS=app1,app2
	$(MAKE) test-app APPS=$(APPS) VERBOSITY=2

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
	@echo "  make <target> [GPU=1] (default: help)"
	@echo ""
	@echo "Options:"
	@echo "  GPU=1                                    Enable GPU support for Ollama LLM"
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
	@echo ""
	@echo "Code Quality (Ruff):"
	@echo "  make ruff-format                        				Format code using ruff formatter"
	@echo "  make ruff-check                         				Check code quality using ruff linter"
	@echo "  make ruff-fix                           				Fix code issues using ruff linter"
	@echo "  make ruff-unsafe-fix                    				Fix code issues using ruff linter with unsafe fixes"
	@echo ""
	@echo "Testing (default: no keepdb, VERBOSITY=1; use KEEPDB=1 to keep test DB):"
	@echo "  make test [KEEPDB=1] [VERBOSITY=1|2|3]  				Run all unit tests for all apps"
	@echo "  make test-app APPS=app1,app2 [KEEPDB=1] [VERBOSITY=2]		Run unit tests for specific app(s)"
	@echo "  make test-verbose                       				Run all unit tests with verbose output (VERBOSITY=2)"
	@echo "  make test-app-verbose APPS=app1,app2    				Run unit tests for specific app(s) with verbose output"
	@echo ""
	@echo "Examples:"
	@echo "  make up GPU=1                          				Start all services with GPU support"
	@echo "  make dev_up GPU=1                      				Start development environment with GPU support"
	@echo "  make build GPU=1                       				Build all images with GPU support"
	@echo "  make build_up GPU=1                    				Build and start all services with GPU support"
	@echo "  make build-service SERVICE=web         				Build only the web service without removing images"
	@echo "  make build-service SERVICE=web GPU=1   				Build only the web service with GPU support"
	@echo "  make build-service SERVICE=web REBUILD=1				Build web service after removing its image"
	@echo "  make build-service SERVICE=redis REBUILD=1 GPU=1		Build redis service after removing image with GPU support"
	@echo "  make test-app APPS=api,scanEngine      				Run tests for api and scanEngine apps"
	@echo "  make ruff-fix                           				Fix code quality issues automatically"
	@echo ""
	@echo "Database backup/restore (backups in $(BACKUP_DIR)/, requires sudo for volume access):"
	@echo "  make db-backup [PG_VOLUME=/path]       				Create timestamped backup"
	@echo "  make db-list                           				List available backups"
	@echo "  make db-restore [BACKUP=name] [PG_VOLUME=/path]			Restore; BACKUP=name without .tar.gz"
	@echo "  make db-restore                        				Restore: choose backup by number"
	@echo ""
	@echo "Secator Initialization:"
	@echo "  make secator-init                        				Initialize Secator (generate API key + load all from Secator)"
	@echo "  make secator-key                         				Generate Secator API key only if none exists"
	@echo "  make secator-load                        				Load Secator components (tasks, workflows, scans)"
	@echo "  make secator-check                       				Check Secator configuration and status"
	@echo "  make secator-health [SECATOR_HEALTH_URL=<url>]			Test Secator API health (uses SECATOR_ADDONS_API_KEY from .env)"
	@echo "  make update-check                        				Check if a reNgine-ng update is available"

%:
	@:
