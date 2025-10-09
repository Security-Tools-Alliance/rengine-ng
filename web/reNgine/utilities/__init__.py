"""
Utilities package for reNgine.

This package contains various utility functions organized by theme.
"""

# Import deadlock prevention utilities
from .deadlock_prevention import (
    http_crawl_safe,
    safe_group_execution,
    safe_chain_execution,
    safe_chord_execution,
    validate_task_isolation,
    DeadlockPreventionError,
    SafeTaskExecutor,
    prevent_deadlock,
    create_safe_batch_executor,
    get_safe_executor
)

# Import core utilities
from .core import *

# Import distributed utilities
from .distributed import *

# Import main utilities
from .command import (
    CommandProcessor,
    run_command,
    generate_header_param,
    validate_command_input,
    get_command_statistics
)

from .database import (
    DatabaseProcessor,
    save_endpoint,
    save_subdomain,
    validate_and_save_subdomain,
    save_vulnerability,
    save_technology,
    save_waf,
    validate_database_input,
    get_database_statistics,
    get_task_cache_key
)

from .url import (
    URLProcessor,
    sanitize_url,
    get_subdomain_from_url,
    add_port_to_url,
    remove_port_from_url,
    normalize_url,
    is_same_domain,
    extract_paths_from_urls,
    filter_urls_by_domain,
    validate_urls_batch,
    get_url_statistics
)

from .dns import (
    resolve_subdomain_ips,
    get_reverse_dns,
    get_current_dns_servers,
    check_host_alive,
    resolve_ip_with_dns,
    resolve_ip_chunk
)

from .time import (
    get_time_taken,
    format_timestamp,
    get_current_timestamp,
    get_current_timestamp_string,
    parse_timestamp,
    is_timestamp_valid
)

from .subdomain import (
    get_subdomains,
    get_new_added_subdomain,
    get_removed_subdomain,
    get_interesting_subdomains,
    get_subdomain_by_name,
    get_subdomains_by_domain,
    get_subdomains_by_scan
)

from .misc import (
    debug,
    fmt_traceback,
    get_traceback_path,
    get_and_save_emails,
    determine_target_type,
    determine_scan_type_from_engine_name,
    save_traceback_to_file,
    extract_emails_from_text,
    validate_target_name,
    sanitize_target_name,
    enrich_notification
)

__all__ = [
    # Deadlock prevention utilities
    'http_crawl_safe',
    'safe_group_execution',
    'safe_chain_execution',
    'safe_chord_execution',
    'validate_task_isolation',
    'DeadlockPreventionError',
    'SafeTaskExecutor',
    'prevent_deadlock',
    'create_safe_batch_executor',
    'get_safe_executor',
    
    # Main utilities
    'CommandProcessor',
    'run_command',
    'generate_header_param',
    'validate_command_input',
    'get_command_statistics',
    
    'DatabaseProcessor',
    'save_endpoint',
    'save_subdomain',
    'validate_and_save_subdomain',
    'save_vulnerability',
    'save_technology',
    'save_waf',
    'validate_database_input',
    'get_database_statistics',
    'get_task_cache_key',
    
    'URLProcessor',
    'sanitize_url',
    'get_subdomain_from_url',
    'add_port_to_url',
    'remove_port_from_url',
    'normalize_url',
    'is_same_domain',
    'extract_paths_from_urls',
    'filter_urls_by_domain',
    'validate_urls_batch',
    'get_url_statistics',
    
    # DNS utilities
    'resolve_subdomain_ips',
    'get_reverse_dns',
    'get_current_dns_servers',
    'check_host_alive',
    'resolve_ip_with_dns',
    'resolve_ip_chunk',
    
    # Time utilities
    'get_time_taken',
    'format_timestamp',
    'get_current_timestamp',
    'get_current_timestamp_string',
    'parse_timestamp',
    'is_timestamp_valid',
    
    # Subdomain utilities
    'get_subdomains',
    'get_new_added_subdomain',
    'get_removed_subdomain',
    'get_interesting_subdomains',
    'get_subdomain_by_name',
    'get_subdomains_by_domain',
    'get_subdomains_by_scan',
    
    # Misc utilities
    'debug',
    'fmt_traceback',
    'get_traceback_path',
    'get_and_save_emails',
    'determine_target_type',
    'determine_scan_type_from_engine_name',
    'save_traceback_to_file',
    'extract_emails_from_text',
    'validate_target_name',
    'sanitize_target_name',
    'enrich_notification',
    
    # All core utilities (imported via core.*)
    # All distributed utilities (imported via distributed.*)
]