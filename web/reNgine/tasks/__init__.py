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
