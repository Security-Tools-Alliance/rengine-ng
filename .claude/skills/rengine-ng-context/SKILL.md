---
name: rengine-ng-context
description: Provides the reNgine-ng project technology stack, architecture, and conventions. Use when contributing to reNgine-ng, implementing features, debugging, or when the user asks about the stack, Django, Secator, PostgreSQL, reconnaissance tools, scans, or the codebase structure.
---

# reNgine-ng Context

Project context and technology stack for the reNgine-ng security assessment platform.

## When to Use

- Contributing code, fixing bugs, or adding features in this repository
- User asks about the stack, frameworks, or how the app is built
- Implementing or modifying scans, targets, API, or UI
- Need to know where dependencies live (e.g. `docker/web/pyproject.toml`) or which versions (Django 5.x, Python 3.12, PostgreSQL 17)

## Stack Summary

| Layer        | Technology |
|-------------|------------|
| Backend     | Django 5.x, Python 3.12 |
| DB          | PostgreSQL 17, PgBouncer |
| Tasks       | Secator (workflows, scans) |
| Frontend    | HTML5, CSS3, JS (Bootstrap, DataTables server-side) |
| Servers     | Uvicorn (prod), Daphne (dev), Nginx |
| Containers  | Docker, Docker Compose |
| Quality     | Ruff (lint/format), type hints, tests in `app_name/tests/` |

- **Paths**: App code under `web/`; in Docker, project root is `/home/rengine/rengine` (maps to `web/`).
- **API**: Django REST Framework; use User API key for automated tests (no CSRF).
- **Datatables**: All server-side; shared helpers in `web/api/helpers/datatables.py` and `web/static/custom/datatables/`.
- **Logging**: Use `ModuleLogger` and `logger.log_line(...)` only; no direct `logger.info`/`logger.debug` etc.

## Conventions (from project rules)

- Code and comments in English; SOLID, KISS, DRY.
- Types on new code; tests for changes; `BaseTestCase` and `TestDataGenerator` for tests; anonymize test data.
- Private methods at the bottom of the file.
- No path built from user input without `reNgine.core.path` / `reNgine.core.validators` helpers; no raw exception messages to the client.
- **Scan config**: Organization, Scope, Target, and ScanHistory each have a `scan_config` JSONField. Parameters resolve via `resolve_scan_params()` in `web/targetApp/services/scope_params.py` following Organization → Scope → Target → Scan hierarchy. See `rengine-ng-coding.mdc` for full details.
- Run `make ruff-format` and `make ruff-fix` to verify style.

## Secator

- **Documentation:** [Secator docs](https://github.com/freelabz/secator-docs) (GitBook/source); [Secator repo](https://github.com/freelabz/secator) (README, tools list).
- Workflows: `get_configs_by_type("workflow")` · Scans: `get_configs_by_type("scan")` · Tasks: `get_configs_by_type("task")`
- Run inside web container: `poetry run -C /home/rengine/rengine python3 -c 'from secator.loader import get_configs_by_type; print(get_configs_by_type("workflow"))'`
- For the list of integrated tools (recon, HTTP, vuln, etc.), see [references/secator-tools.md](references/secator-tools.md).

## Additional Reference

- Full stack and modules: [reference.md](reference.md)
- Secator tools (recon and others): [references/secator-tools.md](references/secator-tools.md)
