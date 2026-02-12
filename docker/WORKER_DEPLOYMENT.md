# Secator Worker Remote Deployment Guide (SSH mode)

This guide explains how to deploy Secator workers on remote machines (VPS, internal networks, etc.) to perform distributed scanning. Workers run in **SSH mode**: no Redis or Celery on the remote host. reNgine-ng launches each scan via SSH by running a Python script inside the worker container.

## Overview

- **reNgine-ng** runs the web UI, API, and database. It does **not** use Redis for worker task distribution.
- **Secator workers** run in Docker on remote hosts. The container runs in **CLI-only** mode (e.g. `sleep infinity`). reNgine-ng connects via **SSH**, syncs custom configs to `~/.secator/templates/` (or the deploy path equivalent), pushes a job file and a runner script, then runs the scan with `docker exec <container> python /path/to/run_secator_job.py /path/to/job.json`. Results are reported to reNgine-ng via the API (Secator hooks).

Workers need:

- **SSH access** from reNgine-ng to the remote host (so reNgine-ng can deploy, sync configs, and run scans).
- **Outbound access** from the worker container to the reNgine-ng API (for hooks and health check).

No Redis or inbound ports are required on the worker.

## Architecture

```
┌─────────────────┐
│  reNgine-ng     │
│  (Main Server)  │
│  - Web UI       │
│  - API          │
│  - Database     │
└────────┬────────┘
         │ SSH (deploy, sync configs, docker exec)
         ▼
┌────────────────────────────────────────┐
│  Remote host                           │
│  ┌──────────────────────────────────┐ │
│  │  Secator container (CLI only)     │ │
│  │  - sleep infinity                 │ │
│  │  - ~/.secator/templates/ (mount)  │ │
│  │  - run_secator_job.py + job.json  │ │
│  │  - Outbound → reNgine-ng API      │ │
│  └──────────────────────────────────┘ │
└────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Docker (and Docker Compose v2 or docker-compose) on the remote machine.
- SSH access from the reNgine-ng server to the remote machine (key or password).
- Network access from the worker container to reNgine-ng's API (HTTPS/HTTP).

### Step 1: Copy files to the remote machine

```bash
scp docker-compose.worker.yml user@remote-machine:~/
scp .env-dist.worker user@remote-machine:~/.env
```

### Step 2: Configure environment variables

On the remote machine, edit the `.env` file. **Redis is not used**; only API-related variables are needed:

```bash
# API configuration (Secator API addon – required for hooks)
SECATOR_ADDONS_API_ENABLED=true
SECATOR_ADDONS_API_URL=https://your-rengine-server.com/api/secator
SECATOR_ADDONS_API_KEY=your-generated-api-key-from-rengine
SECATOR_ADDONS_API_FORCE_SSL=false
```

Leave `SECATOR_CELERY_BROKER_URL` and `SECATOR_CELERY_RESULT_BACKEND` empty or commented out.

### Step 3: Start the worker container

The compose file runs the container with `command: ["sleep", "infinity"]` so it stays up; reNgine-ng will run scans via `docker exec`:

```bash
docker-compose -f docker-compose.worker.yml up -d
```

### Step 4: Register and deploy from reNgine-ng (recommended)

In reNgine-ng, go to **Scan Engine** → **Workers** → **Add Worker**. Enter SSH host, user, key or password, and deploy path. Then click **Deploy** so reNgine-ng copies the compose file and `.env` (with broker/backend empty) and starts the container. reNgine-ng will use this SSH connection to sync custom configs and run scans.

### Step 5: Verify API reachability

In the Workers list, use **Refresh**. reNgine-ng runs **inside the container**: `wget --no-check-certificate -q -O - <health_url>`. If reNgine-ng uses a self-signed certificate, this avoids strict certificate verification. The **API** column and **Last check** are updated accordingly.

## Custom configs (templates)

Custom workflows, scans, tasks, and profiles must be present on the worker in `~/.secator/templates/` (with subdirs `workflows/`, `scans/`, `tasks/`, `profiles/`). Secator loads them via `CONFIG.dirs.templates`.

- **From reNgine-ng**: Before each remote scan, reNgine-ng syncs the required custom configs via SFTP to the deploy path (e.g. `deploy_path/templates/`), which is mounted in the container as `~/.secator/templates/`. You can also use **Sync configs** in the worker UI to push all custom configs at once.

## Configuration details

### Environment variables (worker `.env`)

| Variable | Description | Example |
|----------|-------------|---------|
| `SECATOR_CELERY_BROKER_URL` | Not used (SSH mode). Leave empty. | — |
| `SECATOR_CELERY_RESULT_BACKEND` | Not used (SSH mode). Leave empty. | — |
| `SECATOR_ADDONS_API_ENABLED` | Enable API addon | `true` |
| `SECATOR_ADDONS_API_URL` | reNgine-ng API endpoint | `https://rengine.example.com/api/secator` |
| `SECATOR_ADDONS_API_KEY` | System API key (from main instance) | From main `.env` |
| `SECATOR_ADDONS_API_FORCE_SSL` | Force SSL verification | `false` |

### Secator installed with pipx

If Secator is installed via **pipx** inside the worker container, the system `python` does not see the `secator` module. Configure reNgine-ng (e.g. in its `.env`) so the runner uses the pipx venv Python:

```bash
SECATOR_WORKER_CONTAINER_PYTHON=/root/.local/share/pipx/venvs/secator/bin/python
```

Adjust the path if the container user is not root (e.g. `~/.local/share/pipx/venvs/secator/bin/python` for a non-root user).

### Container path differs from host (e.g. container user is secator)

If the path where scripts are visible **inside the container** is different from `deploy_path` (e.g. on the host you use `/home/rengine/secator-worker` but inside the container the same directory is `/home/secator/secator-worker` because the container user is `secator`), set in reNgine-ng's environment:

```bash
SECATOR_WORKER_CONTAINER_SCRIPT_BASE=/home/secator/secator-worker
```

Scripts are still uploaded to `deploy_path/scripts/` on the host; the command run via `docker exec` will use `SECATOR_WORKER_CONTAINER_SCRIPT_BASE/scripts/` so the container finds the files.

### SSH tunnel (API access type: tunnel)

When the worker uses **SSH tunnel** to reach the API, reNgine-ng starts a reverse tunnel (`ssh -R 0.0.0.0:port:target_host:443`). The tunnel process runs **inside the reNgine-ng web container**. The tunnel client must connect to the host where nginx listens on 443:

- **Docker deployment**: nginx runs in the `proxy` container. Set `RENGINE_TUNNEL_TARGET_HOST=proxy` (default) so the tunnel forwards to the proxy service. No change needed if you use the default.
- **Bare metal** (single host): nginx listens on localhost. Set `RENGINE_TUNNEL_TARGET_HOST=localhost` in reNgine-ng's environment.

On the worker host, `sshd_config` must have `GatewayPorts yes` so the tunnel can bind to `0.0.0.0`.

### API health check from the worker

When you click **Refresh** in the Workers UI, reNgine-ng executes **inside the container**:

```bash
wget --no-check-certificate -q -O - <rengine_health_url>
```

So the worker does not need `curl`; `wget` is used, and self-signed certificates are accepted.

## Security considerations

- **SSH**: Use key-based auth when possible; restrict SSH access to the reNgine-ng server IP if feasible.
- **Firewall**: Allow outbound from the worker to reNgine-ng API (HTTPS/HTTP). No inbound ports required on the worker.
- **API key**: Store securely; rotate periodically. Use the same key as in the main reNgine-ng `.env` for the Secator addon.

## Troubleshooting

### Worker API unreachable after Refresh

- Ensure the container can reach reNgine-ng (HTTPS/HTTP). From the **host**: `docker exec <container_name> wget --no-check-certificate -q -O - https://your-rengine/api/secator/health/` (or the URL reNgine-ng uses).
- Check `SECATOR_ADDONS_API_URL` and `SECATOR_ADDONS_API_KEY` in the deployed `.env`.

### Scan not starting on worker

- Check reNgine-ng logs for SSH or `docker exec` errors.
- Ensure deploy path and container name match what reNgine-ng has for that worker.
- Use **Sync configs** so the worker has the required custom templates in `~/.secator/templates/`.

### Container exits or not running

- The default command is `sleep infinity`. Check `docker-compose -f docker-compose.worker.yml logs`. If the image was previously used with Celery, ensure you use the updated compose file (no Celery worker command).

## Maintenance

- **Update image**: `docker-compose -f docker-compose.worker.yml pull && docker-compose -f docker-compose.worker.yml up -d`
- **Logs**: `docker-compose -f docker-compose.worker.yml logs -f`
- **Stop**: `docker-compose -f docker-compose.worker.yml down`

## Support

- GitHub Issues: https://github.com/Security-Tools-Alliance/rengine-ng/issues
- Documentation: https://github.com/Security-Tools-Alliance/rengine-ng/wiki
