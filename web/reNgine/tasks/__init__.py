"""
Tasks package for reNgine.

This package provides all task functionality for the reNgine application.
"""

# Import tasks
# Import deadlock prevention utilities
from reNgine.utilities.deadlock_prevention import (
    DeadlockPreventionError,
    http_crawl_safe,
    safe_chain_execution,
    safe_chord_execution,
    safe_group_execution,
    validate_task_isolation,
)

from .detect import (
    run_cmseek,
    run_wafw00f,
    waf_detection,
)
from .dns import (
    ip_range_discovery,
    ping_hosts_distributed,
    ping_hosts_task,
    query_ip_history,
    query_reverse_whois,
    query_whois,
)
from .fuzzing import (
    dir_file_fuzz,
)
from .geo import (
    geo_localize,
    geo_localize_batch,
)

# Note: http_distributed.py has been moved to backup/ as it's now redundant
# All distributed HTTP crawling functionality is now in http.py
# Import legacy tasks for backward compatibility
from .http import (
    http_crawl,  # Legacy task - now redirects to distributed system
    http_crawl_batch,
    http_crawl_coordinator,
    http_crawl_orchestrator,
    intermediate_crawl,
    post_crawl,
    pre_crawl,
)
from .http import (
    intermediate_crawl as intermediate_crawl_legacy,
)
from .http import (
    post_crawl as post_crawl_legacy,
)
from .http import (
    pre_crawl as pre_crawl_legacy,
)
from .llm import (
    llm_vulnerability_report,
    llm_vulnerability_report_batch,
)
from .notification import (
    send_notification,
    send_notification_batch,
    send_notification_orchestrator,
)
from .osint import (
    osint_scan,
    osint_scan_batch,
    osint_scan_orchestrator,
)
from .port_scan import (
    port_scan,
    port_scan_batch,
    port_scan_orchestrator,
)
from .reporting import (
    generate_report,
    generate_report_batch,
    generate_report_orchestrator,
)
from .scan import (
    initiate_scan,
    initiate_subscan,
    scan_coordinator,
    scan_orchestrator,
)
from .screenshot import (
    screenshot,
)
from .subdomain import (
    subdomain_discovery,
    subdomain_discovery_batch,
    subdomain_discovery_orchestrator,
)
from .url import (
    fetch_url,
    remove_duplicate_endpoints,
    run_gf_list,
)
from .vulnerability import (
    vulnerability_scan,
    vulnerability_scan_batch,
    vulnerability_scan_orchestrator,
)


# Export all tasks
__all__ = [
    # HTTP crawling tasks
    "http_crawl_batch",
    "http_crawl_orchestrator",
    "http_crawl_coordinator",
    "pre_crawl",
    "intermediate_crawl",
    "post_crawl",
    # Subdomain discovery tasks
    "subdomain_discovery",
    "subdomain_discovery_orchestrator",
    "subdomain_discovery_batch",
    # Scan orchestration tasks
    "initiate_scan",
    "initiate_subscan",
    "scan_orchestrator",
    "scan_coordinator",
    # Port scanning tasks
    "port_scan",
    "port_scan_batch",
    "port_scan_orchestrator",
    # Vulnerability scanning tasks
    "vulnerability_scan",
    "vulnerability_scan_batch",
    "vulnerability_scan_orchestrator",
    # OSINT tasks
    "osint_scan",
    "osint_scan_batch",
    "osint_scan_orchestrator",
    # Notification tasks
    "send_notification",
    "send_notification_batch",
    "send_notification_orchestrator",
    # Reporting tasks
    "generate_report",
    "generate_report_batch",
    "generate_report_orchestrator",
    # Detection tasks
    "waf_detection",
    "run_wafw00f",
    "run_cmseek",
    # DNS tasks
    "query_whois",
    "query_reverse_whois",
    "query_ip_history",
    "ip_range_discovery",
    "ping_hosts_task",
    "ping_hosts_distributed",
    # Fuzzing tasks
    "dir_file_fuzz",
    # Geolocation tasks
    "geo_localize",
    "geo_localize_batch",
    # LLM tasks
    "llm_vulnerability_report",
    "llm_vulnerability_report_batch",
    # Screenshot tasks
    "screenshot",
    # URL tasks
    "fetch_url",
    "remove_duplicate_endpoints",
    "run_gf_list",
    # Deadlock prevention utilities
    "http_crawl_safe",
    "safe_group_execution",
    "safe_chain_execution",
    "safe_chord_execution",
    "validate_task_isolation",
    "DeadlockPreventionError",
    # Note: Distributed HTTP crawling tasks are now in http.py
    # Legacy tasks (for backward compatibility)
    "http_crawl",
    "pre_crawl_legacy",
    "intermediate_crawl_legacy",
    "post_crawl_legacy",
    "run_command",
]
