"""
reNgine tasks (helpers and notifications).

Legacy Celery scan tasks have been removed; Secator handles scanning via
initiate_secator_scan. Scan completion and status are updated by the Secator
flow (progress, service), not by a report task.
"""

from reNgine.secator import initiate_secator_scan
from reNgine.tasks.geo import geo_localize, geo_localize_batch
from reNgine.tasks.llm import llm_vulnerability_report
from reNgine.tasks.notification import (
    send_file_to_discord,
    send_hackerone_report,
    send_notif,
    send_scan_notif,
    send_task_notif,
)


# Export all tasks
__all__ = [
    # Core scan tasks
    "initiate_secator_scan",
    # Utility tasks
    "geo_localize",
    "geo_localize_batch",
    "llm_vulnerability_report",
    # Notification tasks
    "send_file_to_discord",
    "send_hackerone_report",
    "send_notif",
    "send_scan_notif",
    "send_task_notif",
]
