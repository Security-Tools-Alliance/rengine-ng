# Quick Guide: Deploying Remote Secator Workers

Deploy Secator workers on remote machines for distributed scanning.

## Quick Start

1. **Copy files to remote machine:**
   ```bash
   scp docker/docker-compose.worker.yml user@remote:.
   scp .env-dist.worker user@remote:.env
   ```

2. **Configure on remote machine:**
   ```bash
   # Edit .env with your reNgine-ng server details
   nano .env
   ```

3. **Start worker:**
   ```bash
   docker-compose -f docker-compose.worker.yml up -d
   ```

## Required Configuration

In `.env` on the remote machine:

```bash
# Redis connection (point to your reNgine-ng instance)
SECATOR_CELERY_BROKER_URL=redis://your-server:6379/0
SECATOR_CELERY_RESULT_BACKEND=redis://your-server:6379/0

# Secator API addon configuration
SECATOR_ADDONS_API_ENABLED=true
SECATOR_ADDONS_API_URL=https://your-rengine-server.com/api/secator
SECATOR_ADDONS_API_KEY=<from-main-rengine-env>
SECATOR_ADDONS_API_FORCE_SSL=false
```

**Where to get the API key?**  
Check your main reNgine-ng instance's `.env` file for `SECATOR_ADDONS_API_KEY`

## Use Cases

- 🌍 **Multi-location scanning** - Deploy on VPS worldwide
- 🔒 **Internal network scanning** - Scan internal infrastructure
- ⚡ **Scalable architecture** - Multiple workers in parallel

## Full Documentation

See [docker/WORKER_DEPLOYMENT.md](docker/WORKER_DEPLOYMENT.md) for:
- Detailed setup instructions
- Security best practices
- Troubleshooting guide
- Advanced configurations
- Use case examples

## Troubleshooting

**Worker not connecting?**
```bash
# Check logs
docker-compose -f docker-compose.worker.yml logs -f

# Test Redis connectivity
telnet your-server 6379

# Test API connectivity
curl -H "Authorization: Api-Key $SECATOR_ADDONS_API_KEY" \
  $SECATOR_ADDONS_API_URL/runners
```

## Support

- [Full Documentation](docker/WORKER_DEPLOYMENT.md)
- [GitHub Issues](https://github.com/Security-Tools-Alliance/rengine-ng/issues)
- [Wiki](https://github.com/Security-Tools-Alliance/rengine-ng/wiki)

