"""
Celery tasks for reNgine.

⚠️ LEGACY TASKS REMOVED ⚠️
The following legacy tasks have been removed as Secator now handles all scanning:
- command tasks (run_command)
- subdomain tasks (subdomain_discovery)
- dns tasks (ip_range_discovery, ping_hosts_task, etc.)
- port scan tasks (nmap, port_scan, etc.)
- url tasks (fetch_url, remove_duplicate_endpoints, etc.)
- vulnerability tasks (nuclei_scan, dalfox_xss_scan, etc.)
- fuzzing tasks (dir_file_fuzz)
- screenshot tasks (screenshot)
- http tasks (http_crawl, etc.)
- detect tasks (run_cmseek, waf_detection, etc.)
- osint tasks (dorking, h8mail, etc.)

For all scanning needs, use Secator tasks via initiate_secator_scan.
"""

from reNgine.tasks.geo import geo_localize, geo_localize_batch
from reNgine.tasks.llm import llm_vulnerability_report
from reNgine.tasks.notification import (
    send_file_to_discord,
    send_hackerone_report,
    send_notif,
    send_scan_notif,
    send_task_notif,
)
from reNgine.tasks.reporting import report
from reNgine.tasks.scan import initiate_scan, initiate_subscan
from reNgine.tasks.secator_tasks import (
    initiate_secator_scan,
    load_secator_tasks,
    load_secator_workflows,
    run_secator_tasks,
    run_secator_workflow,
)


# Export all tasks
__all__ = [
    # Core scan tasks
    "initiate_scan",
    "initiate_subscan",
    # Secator tasks
    "initiate_secator_scan",
    "load_secator_tasks",
    "load_secator_workflows",
    "run_secator_tasks",
    "run_secator_workflow",
    # Utility tasks
    "geo_localize",
    "geo_localize_batch",
    "llm_vulnerability_report",
    "report",
    # Notification tasks
    "send_file_to_discord",
    "send_hackerone_report",
    "send_notif",
    "send_scan_notif",
    "send_task_notif",
]


def get_scan_tasks():
    """
    Return dictionary of available Secator scan tasks.

    ⚠️ DEPRECATED: Legacy scan tasks have been removed.
    Only Secator tasks are returned: initiate_secator_scan, run_secator_workflow, run_secator_tasks.
    All scanning is now handled by Secator via initiate_secator_scan.
    """
    import sys
    import warnings

    warnings.warn(
        "get_scan_tasks() is deprecated. Use Secator tasks via initiate_secator_scan instead.",
        DeprecationWarning,
        stacklevel=2,
    )

    current_module = sys.modules[__name__]

    # Only Secator tasks are available
    scan_compatible_tasks = [
        "initiate_secator_scan",
        "run_secator_workflow",
        "run_secator_tasks",
    ]

    return {
        task_name: getattr(current_module, task_name)
        for task_name in scan_compatible_tasks
        if hasattr(current_module, task_name)
    }


def get_subscan_tasks():
    """
    Return dictionary of available subscan tasks.

    ⚠️ DEPRECATED: Legacy scan tasks have been removed.
    Use Secator tasks via initiate_secator_scan instead.
    """
    return get_scan_tasks()
