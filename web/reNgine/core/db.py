"""
Database connection helpers - Leaf layer.

Resolves PostgreSQL host/port for Django DATABASES config (PgBouncer vs direct).
No Django dependencies; uses only stdlib and optional psycopg2.
"""

from typing import Any, Callable, Sequence

from reNgine.utilities.logger import get_module_logger


logger = get_module_logger(__name__)

# Management commands that require a direct PostgreSQL connection (e.g. migrations,
# superuser creation). When USE_PGBOUNCER=1, these use POSTGRES_DIRECT_* instead of
# PgBouncer to avoid "wrong password type" (SCRAM) and transaction-pooling limitations.
# entrypoint_setup and run_scheduled_scans are included so the entrypoint and the
# background cron loop use direct DB even when container env points at PgBouncer.
DB_DIRECT_COMMANDS = frozenset(
    {
        "collectstatic",
        "createsuperuser",
        "dbshell",
        "entrypoint_setup",
        "flush",
        "generate_secator_api_key",
        "load_secator_all",
        "makemigrations",
        "migrate",
        "run_scheduled_scans",
        "showmigrations",
        "sqlmigrate",
        "test",
    }
)


def resolve_db_host_port(
    environ: Callable[..., str],
    use_pgbouncer: bool,
    probe_at_startup: bool,
    argv: Sequence[Any],
) -> tuple[str, str]:
    """
    Resolve PostgreSQL host and port for DATABASES config.

    Uses PgBouncer (POSTGRES_HOST/POSTGRES_PORT) unless: (1) the management command
    is in DB_DIRECT_COMMANDS (e.g. migrate, createsuperuser), or (2) use_pgbouncer
    and probe_at_startup are True and the probe fails or psycopg2 is missing—then
    falls back to POSTGRES_DIRECT_HOST/POSTGRES_DIRECT_PORT.

    Args:
        environ: Callable returning env vars (e.g. env("KEY") or env("KEY", default="x")).
        use_pgbouncer: Whether PgBouncer is configured.
        probe_at_startup: Whether to probe PgBouncer and fallback to direct on failure.
        argv: Process argv; command name is argv[2] when argv[1] is manage.py (e.g. python3 manage.py cmd),
        else argv[1]; if that command is in DB_DIRECT_COMMANDS and use_pgbouncer, use direct PostgreSQL.

    Returns:
        (host, port) as strings.
    """
    host = environ("POSTGRES_HOST")
    port = str(environ("POSTGRES_PORT"))
    direct_host = environ("POSTGRES_DIRECT_HOST", default="db")
    direct_port = str(environ("POSTGRES_DIRECT_PORT", default="5432"))

    cmd: str | None = None
    if len(argv) > 2:
        first = argv[1]
        if first == "manage.py" or (isinstance(first, str) and first.endswith("manage.py")):
            cmd = argv[2] if isinstance(argv[2], str) else None
    if cmd is None and len(argv) > 1 and isinstance(argv[1], str):
        cmd = argv[1]
    if use_pgbouncer and cmd is not None and cmd in DB_DIRECT_COMMANDS:
        return direct_host, direct_port

    if not (use_pgbouncer and probe_at_startup):
        return host, port

    try:
        import psycopg2  # noqa: PLC0415

        conn = psycopg2.connect(
            dbname=environ("POSTGRES_DB"),
            user=environ("POSTGRES_USER"),
            password=environ("POSTGRES_PASSWORD"),
            host=host,
            port=port,
            connect_timeout=2,
        )
        conn.close()
    except ImportError:
        logger.warning(
            "psycopg2 not available; PgBouncer probe skipped, using direct PostgreSQL (%s:%s).",
            direct_host,
            direct_port,
        )
        return direct_host, direct_port
    except Exception as e:
        logger.warning(
            "PgBouncer probe failed: %s; using direct PostgreSQL (%s:%s).",
            e,
            direct_host,
            direct_port,
        )
        return direct_host, direct_port

    return host, port
