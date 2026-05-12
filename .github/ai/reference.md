# reNgine-ng — Full Stack Reference

Loaded on demand when the agent needs detailed stack or module information.

## Core Technologies

### Backend
- **Django** (5.x): ORM, REST API, auth, permissions
- **Python** 3.12: backend logic, type hints
- **Secator** (0.25.1+): async scan execution, workflow orchestration, Redis, Celery delegation

### Database
- **PostgreSQL** 17: persistent storage
- **PgBouncer**: connection pooling

### Frontend
- HTML5, CSS3 (Bootstrap), JavaScript (ES6+), AJAX, DataTables (server-side)

### Deployment
- **Docker** / Docker Compose
- **Uvicorn** (prod), **Daphne** (dev), **Nginx** (reverse proxy, SSL, static)

### Quality & Tooling
- **Ruff**: lint and format; config in `docker/web/pyproject.toml`
- Django test framework; tests under `web/<app>/tests/`

## Security & Scanning

- **Secator**: task and workflow runner for security assessments; scan orchestration, workflows, multiple integrated tools (recon, HTTP, vuln). Docs: [Secator docs](https://github.com/freelabz/secator-docs), [Secator repo](https://github.com/freelabz/secator). Full tools list: see [secator-tools.md](secator-tools.md).
- API key auth for external integrations

## Key Modules

- **User management**: Django auth, profiles, RBAC, sessions
- **targetApp** (Organizations, Scopes, Targets):
  - Models: `Organization.scan_config`, `Scope.scan_config`, `Target.scan_config` — all JSONFields with the same schema (profiles, threads, rate_limit, timeout, retries, delay, proxy, user_agent, request_headers, follow_redirect, depth, extra_config).
  - Services (`web/targetApp/services/scope_params.py`): `resolve_scan_params()`, `build_effective_params_display()`, `parse_scan_config_from_post()`.
  - Service (`web/targetApp/services/scan_param_definitions.py`): scan parameter definitions and defaults.
- **startScan** (Scans):
  - `ScanHistory.scan_config` JSONField stores user overrides at scan launch time.
  - The scan page uses `secatar_scan_core.js` for parameter/profile management.
- **Workers**: remote deployment, SSH, health checks
- **UI**: responsive, real-time, DataTables, charts; shared `_scan_params_block.html` template and `scan_params.js` for scan config editing

## Best Practices (summary)

- Security: validation, sanitization, ORM, XSS/CSRF protection
- Performance: indexing, query optimization, Redis, PgBouncer
- Scalability: multiple workers, load balancing, connection pooling
- Maintainability: modular layout, logging, error handling

## Learning Resources

- [Django](https://docs.djangoproject.com/), [DRF](https://www.django-rest-framework.org/)
- [Python](https://docs.python.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Secator documentation](https://github.com/freelabz/secator-docs) · [Secator (tools, README)](https://github.com/freelabz/secator) · Tools list: [secator-tools.md](secator-tools.md)
- [Docker](https://docs.docker.com/)
