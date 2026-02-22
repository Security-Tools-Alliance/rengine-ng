"""
Shared query-building for EXPLAIN audit and index loadtest management commands.

Keeps command handle() methods short by centralizing sample fetching and
query definition logic.
"""

from typing import Any, Dict, List, Optional, Tuple

from django.apps import apps
from django.db import connection


def quote_identifier(s: str) -> str:
    """Quote a SQL identifier (table/column name) for raw queries."""
    return f'"{s}"'


def build_audit_samples() -> Dict[str, Any]:
    """Fetch one PK or key value per critical table for realistic EXPLAIN."""
    from dashboard.models import Project
    from startScan.models import ScanHistory

    q = quote_identifier
    samples: Dict[str, Any] = {
        "scan_id": 1,
        "runner_id": 1,
        "domain_id": 1,
        "project_id": 1,
        "project_slug": "default",
    }
    with connection.cursor() as cur:
        for name, table, col in [
            ("scan_id", ScanHistory._meta.db_table, "id"),
            ("domain_id", ScanHistory._meta.db_table, "domain_id"),
        ]:
            cur.execute(f"SELECT {q(col)} FROM {q(table)} LIMIT 1")
            row = cur.fetchone()
            if row:
                samples[name] = row[0]
        cur.execute(f"SELECT id, slug FROM {q(Project._meta.db_table)} LIMIT 1")
        row = cur.fetchone()
        if row:
            samples["project_id"], samples["project_slug"] = row[0], row[1]
        from startScan.models import SecatorRunner

        cur.execute(f"SELECT id FROM {q(SecatorRunner._meta.db_table)} LIMIT 1")
        row = cur.fetchone()
        if row:
            samples["runner_id"] = row[0]
        cur.execute(f"SELECT id FROM {q('scanEngine_secatorworkflow')} LIMIT 1")
        row = cur.fetchone()
        samples["workflow_id"] = row[0] if row else 1
        cur.execute(f"SELECT name FROM {q('targetApp_domain')} LIMIT 1")
        row = cur.fetchone()
        samples["domain_name"] = row[0] if row else "example.com"
        cur.execute("SELECT id FROM auth_user LIMIT 1")
        row = cur.fetchone()
        samples["user_id"] = row[0] if row else 1
        cur.execute(f"SELECT id FROM {q('recon_note_todonote')} LIMIT 1")
        row = cur.fetchone()
        samples["todonote_id"] = row[0] if row else 1
        cur.execute(f"SELECT name FROM {q('scanEngine_secatorworker')} LIMIT 1")
        row = cur.fetchone()
        samples["worker_name"] = row[0] if row else "local"
        cur.execute(f"SELECT name FROM {q('targetApp_organization')} LIMIT 1")
        row = cur.fetchone()
        samples["organization_name"] = row[0] if row else "Default"
        cur.execute(f"SELECT id FROM {q('startScan_subdomain')} LIMIT 1")
        row = cur.fetchone()
        samples["subdomain_id"] = row[0] if row else 1
        cur.execute(f"SELECT id FROM {q('startScan_scanactivity')} LIMIT 1")
        row = cur.fetchone()
        samples["activity_id"] = row[0] if row else 1
    return samples


def get_audit_queries(samples: Dict[str, Any], app_filter: Optional[str] = None) -> List[Tuple[str, str, List[Any]]]:
    """
    Return list of (name, sql, params) for all critical EXPLAIN patterns.
    If app_filter is set, only return queries for that app.
    """
    from dashboard.models import Project, UserAPIKey
    from recon_note.models import TodoNote
    from startScan.models import (
        Command as CommandModel,
    )
    from startScan.models import (
        Domain,
        EndPoint,
        ScanActivity,
        ScanHistory,
        SecatorRunner,
        Subdomain,
        SubScan,
        Vulnerability,
    )

    q = quote_identifier
    scan_id = samples["scan_id"]
    runner_id = samples["runner_id"]
    domain_id = samples["domain_id"]
    project_id = samples["project_id"]
    project_slug = samples["project_slug"]
    user_id = samples.get("user_id", 1)

    t_scan = ScanHistory._meta.db_table
    t_domain = Domain._meta.db_table
    t_project = Project._meta.db_table
    t_subdomain = Subdomain._meta.db_table
    t_endpoint = EndPoint._meta.db_table
    t_vuln = Vulnerability._meta.db_table
    t_subscan = SubScan._meta.db_table
    t_activity = ScanActivity._meta.db_table
    t_runner = SecatorRunner._meta.db_table
    t_command = CommandModel._meta.db_table
    t_todonote = TodoNote._meta.db_table

    def for_app(*apps_list: str) -> bool:
        if not app_filter:
            return True
        return app_filter in apps_list

    queries: List[Tuple[str, str, List[Any]]] = []

    if for_app("startScan"):
        queries.extend(
            [
                (
                    "SecatorRunner scan_history_id+runner_type",
                    f"SELECT 1 FROM {q(t_runner)} WHERE scan_history_id = %s AND runner_type IN ('workflow', 'scan') LIMIT 1",
                    [scan_id],
                ),
                (
                    "ScanActivity scan_of_id+runner_id+time",
                    f"SELECT * FROM {q(t_activity)} WHERE scan_of_id = %s AND runner_id_id = %s ORDER BY time DESC LIMIT 1",
                    [scan_id, runner_id],
                ),
                (
                    "ScanActivity scan_of_id+status",
                    f"SELECT id FROM {q(t_activity)} WHERE scan_of_id = %s AND status = %s",
                    [scan_id, 1],
                ),
                (
                    "SubScan scan_history_id+status",
                    f"SELECT id FROM {q(t_subscan)} WHERE scan_history_id = %s AND status = %s",
                    [scan_id, 1],
                ),
                (
                    "SubScan secator_runner_id",
                    f"SELECT id FROM {q(t_subscan)} WHERE secator_runner_id = %s",
                    [runner_id],
                ),
                (
                    "Command scan_history_id+name",
                    f"SELECT id FROM {q(t_command)} WHERE scan_history_id = %s AND name = %s LIMIT 1",
                    [scan_id, "nuclei"],
                ),
                (
                    "Subdomain scan_history_id",
                    f"SELECT id FROM {q(t_subdomain)} WHERE scan_history_id = %s LIMIT 100",
                    [scan_id],
                ),
                (
                    "Subdomain scan_history_id+http_status",
                    f"SELECT id FROM {q(t_subdomain)} WHERE scan_history_id = %s AND http_status > 0 LIMIT 100",
                    [scan_id],
                ),
                (
                    "EndPoint scan_history_id",
                    f"SELECT id FROM {q(t_endpoint)} WHERE scan_history_id = %s LIMIT 100",
                    [scan_id],
                ),
                (
                    "EndPoint scan_history_id+http_status",
                    f"SELECT id FROM {q(t_endpoint)} WHERE scan_history_id = %s AND http_status > 0 LIMIT 100",
                    [scan_id],
                ),
                (
                    "Vulnerability scan_history_id",
                    f"SELECT id FROM {q(t_vuln)} WHERE scan_history_id = %s LIMIT 100",
                    [scan_id],
                ),
                (
                    "Vulnerability scan_history_id+severity",
                    f"SELECT id FROM {q(t_vuln)} WHERE scan_history_id = %s AND severity = %s LIMIT 100",
                    [scan_id, 1],
                ),
                (
                    "SecatorRunner scan_history_id",
                    f"SELECT id FROM {q(t_runner)} WHERE scan_history_id = %s",
                    [scan_id],
                ),
                (
                    "ScanHistory domain_id",
                    f"SELECT id FROM {q(t_scan)} WHERE domain_id = %s ORDER BY start_scan_date DESC LIMIT 20",
                    [domain_id],
                ),
                (
                    "ScanHistory domain_id+scan_status",
                    f"SELECT id FROM {q(t_scan)} WHERE domain_id = %s AND scan_status = %s",
                    [domain_id, -1],
                ),
                ("ScanHistory id by domain", f"SELECT id FROM {q(t_scan)} WHERE domain_id = %s LIMIT 1", [domain_id]),
            ]
        )
    if for_app("dashboard"):
        queries.extend(
            [
                ("Project by slug", f"SELECT id FROM {q(t_project)} WHERE slug = %s", [project_slug]),
                (
                    "Project exclude id filter slug (exists)",
                    f"SELECT 1 FROM {q(t_project)} WHERE slug = %s AND id != %s LIMIT 1",
                    [project_slug, project_id],
                ),
                ("Project order by name", f"SELECT id FROM {q(t_project)} ORDER BY name LIMIT 50", []),
                (
                    "UserAPIKey by user_id",
                    f"SELECT id FROM {q(UserAPIKey._meta.db_table)} WHERE user_id = %s LIMIT 50",
                    [user_id],
                ),
                (
                    "UserAPIKey by user_id order created_at desc",
                    f"SELECT id FROM {q(UserAPIKey._meta.db_table)} WHERE user_id = %s ORDER BY created_at DESC LIMIT 50",
                    [user_id],
                ),
                (
                    "UserAPIKey by user_id+name (exists)",
                    f"SELECT 1 FROM {q(UserAPIKey._meta.db_table)} WHERE user_id = %s AND name = %s LIMIT 1",
                    [user_id, "test-key"],
                ),
            ]
        )
    if for_app("recon_note"):
        queries.extend(
            [
                ("TodoNote project_id", f"SELECT id FROM {q(t_todonote)} WHERE project_id = %s LIMIT 50", [project_id]),
                (
                    "TodoNote scan_history_id",
                    f"SELECT id FROM {q(t_todonote)} WHERE scan_history_id = %s LIMIT 50",
                    [scan_id],
                ),
                (
                    "TodoNote by id (PK)",
                    f"SELECT id FROM {q(t_todonote)} WHERE id = %s",
                    [samples.get("todonote_id", 1)],
                ),
            ]
        )
    if for_app("scanEngine"):
        queries.extend(
            [
                (
                    "SecatorWorkflow is_active",
                    f"SELECT id FROM {q('scanEngine_secatorworkflow')} WHERE is_active = %s LIMIT 50",
                    [True],
                ),
                (
                    "SecatorWorkflow by id (PK)",
                    f"SELECT id FROM {q('scanEngine_secatorworkflow')} WHERE id = %s",
                    [samples.get("workflow_id", 1)],
                ),
                (
                    "SecatorWorkflow name+workflow_type+is_active",
                    f"SELECT id FROM {q('scanEngine_secatorworkflow')} WHERE name = %s AND workflow_type = %s AND is_active = %s LIMIT 1",
                    ["custom", "custom", True],
                ),
                (
                    "SecatorProfile name+profile_type",
                    f"SELECT id FROM {q('scanEngine_secatorprofile')} WHERE name = %s AND profile_type = %s LIMIT 1",
                    ["default", "custom"],
                ),
                (
                    "SecatorWorker by name",
                    f"SELECT id FROM {q('scanEngine_secatorworker')} WHERE name = %s LIMIT 1",
                    [samples.get("worker_name", "local")],
                ),
                (
                    "EngineType default_engine",
                    f"SELECT id FROM {q('scanEngine_enginetype')} WHERE default_engine = %s LIMIT 20",
                    [False],
                ),
            ]
        )
    if for_app("targetApp"):
        queries.extend(
            [
                (
                    "Domain by name (unique)",
                    f"SELECT id FROM {q('targetApp_domain')} WHERE name = %s LIMIT 1",
                    [samples.get("domain_name", "example.com")],
                ),
                (
                    "Organization by name",
                    f"SELECT id FROM {q('targetApp_organization')} WHERE name = %s LIMIT 1",
                    [samples.get("organization_name", "Default")],
                ),
            ]
        )
    if for_app("api"):
        subdomain_id = samples.get("subdomain_id", 1)
        activity_id = samples.get("activity_id", 1)
        queries.extend(
            [
                (
                    "API Domain by project_id",
                    f"SELECT id FROM {q(t_domain)} WHERE project_id = %s LIMIT 100",
                    [project_id],
                ),
                (
                    "API SubScan by subdomain_id order stop_scan_date",
                    f"SELECT id FROM {q(t_subscan)} WHERE subdomain_id = %s ORDER BY stop_scan_date DESC NULLS LAST LIMIT 50",
                    [subdomain_id],
                ),
                (
                    "API Command by activity_id",
                    f"SELECT id FROM {q(t_command)} WHERE activity_id = %s ORDER BY id LIMIT 100",
                    [activity_id],
                ),
                (
                    "API Subdomain by domain_id",
                    f"SELECT id FROM {q(t_subdomain)} WHERE domain_id = %s LIMIT 100",
                    [domain_id],
                ),
                (
                    "API Vulnerability by domain_id",
                    f"SELECT id FROM {q(t_vuln)} WHERE domain_id = %s LIMIT 100",
                    [domain_id],
                ),
                (
                    "API TodoNote by subdomain_id",
                    f"SELECT id FROM {q(t_todonote)} WHERE subdomain_id = %s LIMIT 50",
                    [subdomain_id],
                ),
                (
                    "API ScanHistory by domain_id order start_scan_date",
                    f"SELECT id FROM {q(t_scan)} WHERE domain_id = %s ORDER BY start_scan_date DESC LIMIT 20",
                    [domain_id],
                ),
                (
                    "API EndPoint by scan_history_id",
                    f"SELECT id FROM {q(t_endpoint)} WHERE scan_history_id = %s LIMIT 100",
                    [scan_id],
                ),
            ]
        )
    if for_app("datatable"):
        queries.extend(
            [
                (
                    "DT Subdomain order content_length",
                    f"SELECT id FROM {q(t_subdomain)} WHERE scan_history_id = %s ORDER BY content_length DESC NULLS LAST LIMIT 50",
                    [scan_id],
                ),
                (
                    "DT Subdomain order name",
                    f"SELECT id FROM {q(t_subdomain)} WHERE scan_history_id = %s ORDER BY name LIMIT 50",
                    [scan_id],
                ),
                (
                    "DT Subdomain order http_status",
                    f"SELECT id FROM {q(t_subdomain)} WHERE scan_history_id = %s ORDER BY http_status DESC LIMIT 50",
                    [scan_id],
                ),
                (
                    "DT EndPoint order content_length",
                    f"SELECT id FROM {q(t_endpoint)} WHERE scan_history_id = %s ORDER BY content_length DESC NULLS LAST LIMIT 50",
                    [scan_id],
                ),
                (
                    "DT EndPoint order http_url",
                    f"SELECT id FROM {q(t_endpoint)} WHERE scan_history_id = %s ORDER BY http_url LIMIT 50",
                    [scan_id],
                ),
                (
                    "DT Vulnerability order cvss_score",
                    f"SELECT id FROM {q(t_vuln)} WHERE scan_history_id = %s ORDER BY cvss_score DESC NULLS LAST LIMIT 50",
                    [scan_id],
                ),
                (
                    "DT Vulnerability order severity",
                    f"SELECT id FROM {q(t_vuln)} WHERE scan_history_id = %s ORDER BY severity DESC LIMIT 50",
                    [scan_id],
                ),
            ]
        )

    return queries


def build_loadtest_samples(app_labels: List[str]) -> Dict[Tuple[str, str], Any]:
    """
    For each model in the given apps, fetch one primary key value.
    Returns dict keyed by (app_label, model_name) -> pk value (or 1 if empty).
    """
    samples: Dict[Tuple[str, str], Any] = {}
    q = quote_identifier
    with connection.cursor() as cur:
        for app_label in app_labels:
            try:
                app_config = apps.get_app_config(app_label)
            except LookupError:
                continue
            for model in app_config.get_models():
                table = model._meta.db_table
                pk_col = model._meta.pk.column
                cur.execute(f"SELECT {q(pk_col)} FROM {q(table)} LIMIT 1")
                row = cur.fetchone()
                samples[(app_label, model.__name__)] = row[0] if row else 1
    return samples


def get_loadtest_custom_queries(samples: Dict[Tuple[str, str], Any]) -> List[Tuple[str, str, List[Any]]]:
    """Secator sync and other critical indexed queries. Returns list of (name, sql, params)."""
    from startScan.models import (
        Command as CommandModel,
    )
    from startScan.models import (
        ScanActivity,
        SecatorRunner,
        SubScan,
    )

    q = quote_identifier
    scan_id = samples.get(("startScan", "ScanHistory"), 1)
    runner_id = samples.get(("startScan", "SecatorRunner"), 1)
    t_runner = SecatorRunner._meta.db_table
    t_activity = ScanActivity._meta.db_table
    t_subscan = SubScan._meta.db_table
    t_command = CommandModel._meta.db_table

    return [
        (
            "SecatorRunner (scan_history_id + runner_type IN)",
            f"SELECT 1 FROM {q(t_runner)} WHERE scan_history_id = %s AND runner_type IN ('workflow', 'scan') LIMIT 1",
            [scan_id],
        ),
        (
            "ScanActivity (scan_of_id + runner_id + ORDER BY time DESC)",
            f"SELECT * FROM {q(t_activity)} WHERE scan_of_id = %s AND runner_id_id = %s ORDER BY time DESC LIMIT 1",
            [scan_id, runner_id],
        ),
        (
            "ScanActivity (scan_of_id + status)",
            f"SELECT id FROM {q(t_activity)} WHERE scan_of_id = %s AND status = %s",
            [scan_id, 1],
        ),
        (
            "SubScan (scan_history_id + status)",
            f"SELECT id FROM {q(t_subscan)} WHERE scan_history_id = %s AND status = %s",
            [scan_id, 1],
        ),
        (
            "SubScan (secator_runner_id)",
            f"SELECT id FROM {q(t_subscan)} WHERE secator_runner_id = %s",
            [runner_id],
        ),
        (
            "Command (scan_history_id + name)",
            f"SELECT id FROM {q(t_command)} WHERE scan_history_id = %s AND name = %s LIMIT 1",
            [scan_id, "nuclei"],
        ),
    ]


def get_loadtest_pk_queries_for_app(
    app_label: str, samples: Dict[Tuple[str, str], Any]
) -> List[Tuple[str, str, List[Any]]]:
    """One SELECT by PK per model in the app. Returns list of (name, sql, params)."""
    result: List[Tuple[str, str, List[Any]]] = []
    q = quote_identifier
    try:
        app_config = apps.get_app_config(app_label)
    except LookupError:
        return result
    for model in app_config.get_models():
        table = model._meta.db_table
        pk_col = model._meta.pk.column
        pk_val = samples.get((app_label, model.__name__), 1)
        name = f"{app_label}.{model.__name__} (PK)"
        sql = f"SELECT 1 FROM {q(table)} WHERE {q(pk_col)} = %s LIMIT 1"
        result.append((name, sql, [pk_val]))
    return result


def get_loadtest_queries(
    app_labels: List[str], samples: Dict[Tuple[str, str], Any]
) -> List[Tuple[str, str, List[Any]]]:
    """Custom indexed queries first, then per-app PK lookups."""
    custom = get_loadtest_custom_queries(samples)
    pk_queries: List[Tuple[str, str, List[Any]]] = []
    for app_label in app_labels:
        pk_queries.extend(get_loadtest_pk_queries_for_app(app_label, samples))
    return custom + pk_queries
