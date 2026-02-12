# Quick Guide: Deploying Remote Secator Workers (SSH mode)

Deploy Secator workers on remote machines for distributed scanning. Workers run in **SSH mode**: no Redis. reNgine-ng launches scans via SSH (`docker exec` in the container) and syncs custom configs to `~/.secator/templates/`.

## Quick Start

1. **Copy files to remote machine:**
   ```bash
   scp docker/docker-compose.worker.yml user@remote:.
   scp .env-dist.worker user@remote:.env
   ```

2. **Configure on remote machine** (no Redis; only API):
   ```bash
   # Edit .env – set API URL and key; leave broker/backend empty
   nano .env
   ```

3. **Start worker** (container runs `sleep infinity`; reNgine-ng runs scans via SSH):
   ```bash
   docker-compose -f docker-compose.worker.yml up -d
   ```

4. **Register in reNgine-ng**: Scan Engine → Workers → Add Worker (SSH host, user, key, deploy path) → **Deploy**.

## Required configuration (worker `.env`)

```bash
# Redis is NOT used in SSH mode – leave these empty or commented
# SECATOR_CELERY_BROKER_URL=
# SECATOR_CELERY_RESULT_BACKEND=

# Secator API addon (required for hooks and health check)
SECATOR_ADDONS_API_ENABLED=true
SECATOR_ADDONS_API_URL=https://your-rengine-server.com/api/secator
SECATOR_ADDONS_API_KEY=<from-main-rengine-env>
SECATOR_ADDONS_API_FORCE_SSL=false
```

**API key:** Use the same key as in your main reNgine-ng `.env` (`SECATOR_ADDONS_API_KEY`).

## API health check

**Refresh** in the Workers UI runs **inside the container**: `wget --no-check-certificate -q -O - <health_url>`. No Redis check; certificate verification is relaxed for self-signed reNgine-ng instances.

## Custom configs

Custom workflows/scans/tasks/profiles are synced to `~/.secator/templates/` (workflows/, scans/, tasks/, profiles/) before each remote scan. Use **Sync configs** in the worker UI to push all custom configs at once.

## Use cases

- Multi-location scanning (VPS in different regions)
- Internal network scanning (worker inside your network, outbound-only to reNgine-ng)
- Horizontal scaling (multiple workers; reNgine-ng chooses one per scan via UI or API)

## Full documentation

See [docker/WORKER_DEPLOYMENT.md](docker/WORKER_DEPLOYMENT.md) for architecture, security, troubleshooting, and maintenance.

## Support

- [Full Documentation](docker/WORKER_DEPLOYMENT.md)
- [GitHub Issues](https://github.com/Security-Tools-Alliance/rengine-ng/issues)
- [Wiki](https://github.com/Security-Tools-Alliance/rengine-ng/wiki)
