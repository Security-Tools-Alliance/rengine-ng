"""
DataTables action column URL builders for RengineDatatableActionRenderers (custom/datatables/actions.js).

Target URLs are returned as "base" strings (trailing id stripped) so the frontend can append row.id.
"""

from django.urls import reverse


def _target_url_base(url: str) -> str:
    """Strip trailing /0 or /0/ so the frontend can append row.id. Returns base with trailing slash."""
    u = url.rstrip("/")
    base = (u[:-1].rstrip("/")) if u.endswith("/0") else u
    base = base if base.startswith("/") else f"/{base}"
    return base if base.endswith("/") else f"{base}/"


def get_datatable_action_urls(project_slug: str) -> dict:
    """
    Build the full dict of action URLs for RengineDatatableActionRenderers in custom/datatables/actions.js.

    Returns dict with keys 'subdomain', 'ip', 'vulnerability', 'target', each mapping to
    the URL dict expected by the corresponding renderer.

    For the scan-detail IP table, ``ip['attackSurface']``, ``ip['toggleIpImportant']``, and
    ``ip['unlinkScanIps']`` enable the matching action buttons; for the target-summary IP table,
    ``ip['unlinkTargetIps']`` enables per-row removal from the target. Missing keys omit those
    controls on the client (subtask scan and recon note do not require these URLs).
    """
    return {
        "subdomain": {
            "attackSurface": reverse("api:llm_get_possible_attacks"),
            "toggleSubdomain": reverse("api:toggle_subdomain"),
        },
        "ip": {
            "attackSurface": reverse("api:llm_get_possible_attacks"),
            "toggleIpImportant": reverse("api:toggle_ip_important"),
            "unlinkScanIps": reverse("api:unlink_scan_ip_addresses"),
            "unlinkTargetIps": reverse("api:unlink_target_ip_addresses"),
            "getIpDetails": reverse("api:getIpDetails"),
            "querySubdomains": reverse("api:querySubdomains"),
        },
        "vulnerability": {
            "llmReport": reverse("api:llm_vulnerability_report_generator"),
            "hackeroneReport": reverse("api:vulnerability_report"),
            "deleteVulnerability": reverse("api:delete_vulnerability"),
        },
        "target": {
            "targetSummaryBase": _target_url_base(reverse("target_summary", args=[project_slug, 0])),
            "startScanBase": _target_url_base(reverse("start_scan", args=[project_slug, 0])),
            "scheduleScanBase": _target_url_base(reverse("schedule_scan", args=[project_slug, 0])),
            "updateTargetBase": _target_url_base(reverse("update_target", args=[project_slug, 0])),
            "deleteTargetBase": _target_url_base(reverse("delete_target", args=[project_slug, 0])),
        },
    }
