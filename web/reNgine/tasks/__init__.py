from reNgine.tasks.command import run_command
from reNgine.tasks.detect import run_cmseek, run_wafw00f, waf_detection
from reNgine.tasks.dns import ip_range_discovery, ping_hosts_task, query_ip_history, query_reverse_whois, query_whois
from reNgine.tasks.fuzzing import dir_file_fuzz
from reNgine.tasks.geo import geo_localize, geo_localize_batch
from reNgine.tasks.http import http_crawl, intermediate_crawl, post_crawl, pre_crawl
from reNgine.tasks.llm import llm_vulnerability_report
from reNgine.tasks.notification import (
    send_file_to_discord,
    send_hackerone_report,
    send_notif,
    send_scan_notif,
    send_task_notif,
)
from reNgine.tasks.osint import (
    dorking,
    h8mail,
    osint,
    osint_discovery,
    the_harvester,
)
from reNgine.tasks.port_scan import (
    nmap,
    port_scan,
    run_nmap,
)
from reNgine.tasks.reporting import report
from reNgine.tasks.scan import initiate_scan, initiate_subscan
from reNgine.tasks.screenshot import screenshot
from reNgine.tasks.subdomain import subdomain_discovery
from reNgine.tasks.url import (
    fetch_url,
    remove_duplicate_endpoints,
    run_gf_list,
)
from reNgine.tasks.vulnerability import (
    crlfuzz_scan,
    dalfox_xss_scan,
    nuclei_individual_severity_module,
    nuclei_scan,
    s3scanner,
    vulnerability_scan,
)


# Export all tasks
__all__ = [
    "crlfuzz_scan",
    "dalfox_xss_scan",
    "dir_file_fuzz",
    "dorking",
    "fetch_url",
    "geo_localize",
    "geo_localize_batch",
    "h8mail",
    "http_crawl",
    "initiate_scan",
    "initiate_subscan",
    "intermediate_crawl",
    "ip_range_discovery",
    "llm_vulnerability_report",
    "nmap",
    "nuclei_individual_severity_module",
    "nuclei_scan",
    "osint",
    "osint_discovery",
    "ping_hosts_task",
    "port_scan",
    "post_crawl",
    "pre_crawl",
    "query_ip_history",
    "query_reverse_whois",
    "query_whois",
    "remove_duplicate_endpoints",
    "report",
    "resolve_ip_chunk_task",
    "run_cmseek",
    "run_command",
    "run_gf_list",
    "run_nmap",
    "run_wafw00f",
    "s3scanner",
    "screenshot",
    "send_file_to_discord",
    "send_hackerone_report",
    "send_notif",
    "send_scan_notif",
    "send_task_notif",
    "subdomain_discovery",
    "the_harvester",
    "vulnerability_scan",
    "waf_detection",
]


def get_scan_tasks():
    """Return dictionary of all available scan tasks."""
    import sys

    current_module = sys.modules[__name__]

    # All scan-compatible tasks
    scan_compatible_tasks = [
        "subdomain_discovery",
        "osint",
        "pre_crawl",
        "intermediate_crawl",
        "post_crawl",
        "port_scan",
        "fetch_url",
        "dir_file_fuzz",
        "vulnerability_scan",
        "screenshot",
        "waf_detection",
    ]

    return {
        task_name: getattr(current_module, task_name)
        for task_name in scan_compatible_tasks
        if hasattr(current_module, task_name)
    }


# Keep the old function for backward compatibility
def get_subscan_tasks():
    """Return dictionary of available subscan tasks."""
    return get_scan_tasks()
