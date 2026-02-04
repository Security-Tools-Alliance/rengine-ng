# Secator Worker Remote Deployment Guide

This guide explains how to deploy Secator workers on remote machines (VPS, internal networks, etc.) to perform distributed scanning.

## Overview

Task execution and scheduling are handled by **Secator** (workers and beat run in the Secator worker container). reNgine-ng no longer runs Celery; it uses Secator's Celery-compatible broker for the worker.

Secator workers can be deployed anywhere with network access to:
- **Redis broker** (used by Secator as Celery broker; set `SECATOR_CELERY_BROKER_URL` and `SECATOR_CELERY_RESULT_BACKEND`)
- **reNgine-ng API** (for downloading hooks and reporting results)

This enables use cases like:
- 🌍 **Distributed web scanning** from multiple geographic locations (VPS)
- 🔒 **Internal network scanning** via agents deployed on internal infrastructure
- ⚡ **Scalable architecture** with multiple workers processing scans in parallel

## Architecture

```
┌─────────────────┐
│  reNgine-ng     │◄───── HTTP/HTTPS ─────┐
│  (Main Server)  │                        │
│  - Web UI       │                        │
│  - API          │                        │
│  - Redis        │◄──── Redis ───┐       │
│  - Database     │                │       │
└─────────────────┘                │       │
                                   │       │
                            ┌──────┴───────┴──────┐
                            │  Secator Worker     │
                            │  (Remote Machine)   │
                            │  - Executes scans   │
                            │  - Reports results  │
                            └─────────────────────┘
```

## Quick Start

### Prerequisites

- Docker installed on the remote machine
- Network access to reNgine-ng's Redis (port 6379)
- Network access to reNgine-ng's API (port 8000 or 443)

### Step 1: Copy Files to Remote Machine

Copy these files to your remote machine:
```bash
scp docker-compose.worker.yml user@remote-machine:~/
scp .env-dist.worker user@remote-machine:~/.env
```

### Step 2: Configure Environment Variables

On the remote machine, edit the `.env` file:

```bash
nano ~/.env
```

Update the following variables:

```bash
# Point to your reNgine-ng instance Redis
SECATOR_CELERY_BROKER_URL=redis://your-rengine-server.com:6379/0
SECATOR_CELERY_RESULT_BACKEND=redis://your-rengine-server.com:6379/0

# API configuration (Secator API addon)
SECATOR_ADDONS_API_ENABLED=true
SECATOR_ADDONS_API_URL=https://your-rengine-server.com/api/secator
SECATOR_ADDONS_API_KEY=your-generated-api-key-from-rengine
SECATOR_ADDONS_API_FORCE_SSL=false
```

**Important:** 
- Replace `your-rengine-server.com` with your actual reNgine-ng server address
- Get the API key from your main reNgine-ng instance's `.env` file (variable `SECATOR_ADDONS_API_KEY`)

### Step 3: Start the Worker

```bash
docker-compose -f docker-compose.worker.yml up -d
```

### Step 4: Verify

Check that the worker is running:
```bash
docker-compose -f docker-compose.worker.yml logs -f
```

You should see:
- ✅ Hooks downloaded successfully
- ✅ Secator worker starting
- ✅ Worker connected to Celery

## Configuration Details

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SECATOR_CELERY_BROKER_URL` | Redis broker URL for Celery | `redis://host:6379/0` |
| `SECATOR_CELERY_RESULT_BACKEND` | Redis backend URL for results | `redis://host:6379/0` |
| `SECATOR_ADDONS_API_ENABLED` | Enable API addon | `true` |
| `SECATOR_ADDONS_API_URL` | reNgine-ng API endpoint | `https://rengine.example.com/api/secator` |
| `SECATOR_ADDONS_API_KEY` | System API key (from main instance) | `StkhUn8u.eabOM...` |
| `SECATOR_ADDONS_API_FORCE_SSL` | Force SSL verification | `false` |

### Redis Connection

The Redis connection format is:
```
redis://[username:password@]host:port/db_number
```

Examples:
- Local network: `redis://192.168.1.100:6379/0`
- With auth: `redis://user:password@host:6379/0`
- SSL/TLS: `rediss://host:6380/0`

## Security Considerations

### Network Security

1. **Redis Authentication**: Use Redis authentication when possible
   ```bash
   SECATOR_CELERY_BROKER_URL=redis://username:password@host:6379/0
   ```

2. **Firewall Rules**: 
   - Allow outbound to reNgine-ng Redis (6379)
   - Allow outbound to reNgine-ng API (443/8000)
   - No inbound connections required

3. **HTTPS**: Use HTTPS for API communication
   ```bash
   RENGINE_API_URL=https://your-rengine-server.com
   ```

### API Key Security

- Store API key securely (never commit to git)
- Rotate API key periodically
- Use separate API keys for different worker pools if needed
- Monitor API key usage in reNgine-ng

### Data Security

- Scan results are transmitted to reNgine-ng via API
- Local scan results are stored in Docker volume (optional)
- Use encrypted connections (Redis SSL, HTTPS API)

## Use Cases

### 1. Multi-Location Web Scanning

Deploy workers on VPS in different countries:

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Worker US  │    │  Worker EU  │    │  Worker AS  │
│  (VPS)      │    │  (VPS)      │    │  (VPS)      │
└──────┬──────┘    └──────┬──────┘    └──────┬──────┘
       │                  │                  │
       └──────────────────┴──────────────────┘
                          │
                  ┌───────▼────────┐
                  │  reNgine-ng    │
                  │  (Main Server) │
                  └────────────────┘
```

**Benefits:**
- Geographic distribution for better scan coverage
- Bypass geo-blocking
- Reduce latency to targets
- Load distribution

### 2. Internal Network Scanning

Deploy worker on internal network via agent:

```
┌─────────────────────────────────┐
│  Internal Network               │
│  ┌────────────┐  ┌────────────┐ │
│  │ Target A   │  │ Target B   │ │
│  └──────▲─────┘  └──────▲─────┘ │
│         │                │       │
│  ┌──────┴────────────────┴─────┐ │
│  │  Secator Worker (Agent)    │ │
│  └──────────────┬──────────────┘ │
└─────────────────│────────────────┘
                  │ (Outbound only)
          ┌───────▼────────┐
          │  reNgine-ng    │
          │  (Internet)    │
          └────────────────┘
```

**Benefits:**
- Scan internal infrastructure without VPN
- No inbound connections required
- Secure communication via API
- Centralized management

### 3. Scalable Architecture

Multiple workers for high-volume scanning:

```
┌──────────┐  ┌──────────┐  ┌──────────┐
│ Worker 1 │  │ Worker 2 │  │ Worker N │
└─────┬────┘  └─────┬────┘  └─────┬────┘
      │             │             │
      └─────────────┴─────────────┘
                    │
            ┌───────▼────────┐
            │  reNgine-ng    │
            │  - Task Queue  │
            │  - Results DB  │
            └────────────────┘
```

**Benefits:**
- Horizontal scaling
- Parallel scan execution
- Load balancing
- High availability

## Troubleshooting

### Worker Cannot Connect to Redis

**Symptoms:** Worker logs show Redis connection errors

**Solutions:**
1. Check network connectivity:
   ```bash
   telnet your-rengine-server.com 6379
   ```
2. Verify Redis is accessible (firewall rules)
3. Check Redis authentication if enabled
4. Verify `SECATOR_CELERY_BROKER_URL` in `.env`

### Worker Cannot Connect to API

**Symptoms:** "Failed to connect to API" or "401 Unauthorized" errors

**Solutions:**
1. Check API URL is correct (must include `/api/secator` path)
2. Verify API key is valid
3. Test API connectivity:
   ```bash
   curl -H "Authorization: Api-Key $SECATOR_ADDONS_API_KEY" \
     $SECATOR_ADDONS_API_URL/runners
   ```
4. Check firewall allows HTTPS/HTTP to reNgine-ng

### Worker Not Processing Tasks

**Symptoms:** Worker idle, tasks queued in reNgine-ng

**Solutions:**
1. Check worker logs: `docker-compose -f docker-compose.worker.yml logs`
2. Verify worker is registered with Celery
3. Check Redis connection
4. Ensure worker is using correct Redis URL

### API Authentication Failures

**Symptoms:** 401/403 errors in logs

**Solutions:**
1. Verify API key is correct (check main `.env`)
2. Regenerate API key if needed:
   ```bash
   docker exec rengine-web-1 poetry run python3 manage.py \
     generate_secator_api_key --recreate --show-key
   ```
3. Update worker `.env` with new key

## Maintenance

### Updating Workers

```bash
# Pull latest image
docker-compose -f docker-compose.worker.yml pull

# Restart worker
docker-compose -f docker-compose.worker.yml up -d
```

### Monitoring

View real-time logs:
```bash
docker-compose -f docker-compose.worker.yml logs -f
```

Check worker health:
```bash
docker-compose -f docker-compose.worker.yml ps
```

### Stopping Workers

```bash
# Graceful shutdown
docker-compose -f docker-compose.worker.yml down

# Force stop
docker-compose -f docker-compose.worker.yml down -v
```

## Advanced Configuration

### Multiple Workers on Same Machine

Create separate directories for each worker:

```bash
mkdir -p ~/secator-worker-1 ~/secator-worker-2
cp docker-compose.worker.yml .env ~/secator-worker-1/
cp docker-compose.worker.yml .env ~/secator-worker-2/

# Start workers
cd ~/secator-worker-1 && docker-compose -f docker-compose.worker.yml up -d
cd ~/secator-worker-2 && docker-compose -f docker-compose.worker.yml up -d
```

### Custom Worker Names

Edit `docker-compose.worker.yml` and change:
```yaml
container_name: secator-worker-custom-name
```

### Resource Limits

Add resource limits in `docker-compose.worker.yml`:
```yaml
deploy:
  resources:
    limits:
      cpus: '2.0'
      memory: 4G
    reservations:
      cpus: '1.0'
      memory: 2G
```

## Support

For issues or questions:
- GitHub Issues: https://github.com/Security-Tools-Alliance/rengine-ng/issues
- Documentation: https://github.com/Security-Tools-Alliance/rengine-ng/wiki
- Discord: Check project README for invite link

