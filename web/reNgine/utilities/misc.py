"""
Miscellaneous utilities for debugging, traceback handling, and target analysis.

This module provides various utility functions for debugging, error handling,
and target type determination.
"""

import os
import traceback
from contextlib import suppress
from pathlib import Path
from typing import Optional, Union

from celery.utils.log import get_task_logger

from reNgine.utilities.core.validation import is_valid_ipv4, is_valid_ipv6, is_valid_domain
from reNgine.utilities.core.file import join_path, file_exists, write_file_content, read_file_content
from reNgine.utilities.core.data import extract_emails


logger = get_task_logger(__name__)


def debug():
    """
    Activate remote debug for scan worker.
    
    This function sets up remote debugging for Celery workers when enabled
    in the configuration.
    """
    try:
        # Import settings here to avoid circular imports
        from reNgine.settings import CELERY_REMOTE_DEBUG, CELERY_REMOTE_DEBUG_PORT
        
        if CELERY_REMOTE_DEBUG:
            logger.info(
                f"\n⚡ Debugger started on port {str(CELERY_REMOTE_DEBUG_PORT)}"
                + ", task is waiting IDE (VSCode ...) to be attached to continue ⚡\n"
            )
            os.environ["GEVENT_SUPPORT"] = "True"
            import debugpy

            debugpy.listen(("0.0.0.0", CELERY_REMOTE_DEBUG_PORT))
            debugpy.wait_for_client()
    except Exception as e:
        logger.error(f"Debug setup failed: {e}")


def fmt_traceback(exc: Exception) -> str:
    """
    Format an exception traceback as a string.
    
    Args:
        exc: The exception to format
        
    Returns:
        Formatted traceback string
        
    Examples:
        >>> try:
        ...     raise ValueError("Test error")
        ... except ValueError as e:
        ...     print(fmt_traceback(e))
    """
    return "\n".join(traceback.format_exception(None, exc, exc.__traceback__))


def get_traceback_path(
    task_name: str,
    results_dir: str,
    scan_history_id: Optional[int] = None,
    subscan_id: Optional[int] = None
) -> str:
    """
    Generate a traceback file path for a task.
    
    Args:
        task_name: Name of the task
        results_dir: Results directory path
        scan_history_id: Scan history ID (optional)
        subscan_id: Subscan ID (optional)
        
    Returns:
        Full path to the traceback file
        
    Examples:
        >>> get_traceback_path("http_crawl", "/tmp/results", 123)
        '/tmp/results/#123-http_crawl.txt'
        
        >>> get_traceback_path("subdomain_scan", "/tmp/results", 123, 456)
        '/tmp/results/#123-456-subdomain_scan.txt'
    """
    path = results_dir
    if scan_history_id:
        path += f"/#{scan_history_id}"
        if subscan_id:
            path += f"-#{subscan_id}"
    path += f"-{task_name}.txt"
    return path


def get_and_save_emails(
    domain_name: str,
    activity_id: Optional[int] = None,
    results_dir: str = "/tmp",
    db_interface=None
) -> list:
    """
    Get and save emails from Google, Bing and Baidu.

    Args:
        domain_name: Domain name to search for emails
        activity_id: ScanActivity Object (optional)
        results_dir: Results directory
        db_interface: Database interface for saving emails

    Returns:
        List of emails found.
    """
    from reNgine.utilities.command import run_command

    emails = []

    # Gather emails from Google, Bing and Baidu
    output_file = join_path(results_dir, "emails_tmp.txt")
    history_file = join_path(results_dir, "commands.txt")
    command = f"infoga --domain {domain_name} --source all --report {output_file}"
    
    try:
        run_command(command, shell=False, history_file=history_file, activity_id=activity_id)

        if not file_exists(output_file):
            logger.info("No Email results")
            return []

        # Read and parse email results
        content = read_file_content(output_file)
        if content:
            for line in content.split('\n'):
                if "Email" in line:
                    parts = line.split(" ")
                    if len(parts) > 2:
                        email = parts[2]
                        emails.append(email)

        # Save emails to final output file
        output_path = join_path(results_dir, "emails.txt")
        email_content = "\n".join(emails)
        write_file_content(output_path, email_content)

        # Save emails to database if interface provided
        if db_interface and emails:
            for email_address in emails:
                try:
                    email_data = {
                        "email": email_address,
                        "scan_history_id": activity_id
                    }
                    db_interface.create_record("email", email_data)
                except Exception as e:
                    logger.warning(f"Failed to save email {email_address}: {e}")

    except Exception as e:
        logger.exception(f"Error getting emails for domain {domain_name}: {e}")
    
    return emails


def determine_target_type(target_name: str) -> str:
    """
    Determine the type of target based on its name.

    This function analyzes a target name and determines whether it's an IP address,
    IP range, domain, subdomain, or custom text. This is used to adapt the scan
    workflow and tasks according to the target type.

    Args:
        target_name: The target name to analyze

    Returns:
        Target type - 'ip_address', 'ip_range', 'custom_text', 'domain', or 'subdomain'

    Examples:
        >>> determine_target_type("192.168.1.1")
        'ip_address'
        >>> determine_target_type("192.168.1.0_24")
        'ip_range'
        >>> determine_target_type("example.com")
        'domain'
        >>> determine_target_type("www.example.com")
        'subdomain'
        >>> determine_target_type("My Custom Target")
        'custom_text'
    """
    if not target_name or not isinstance(target_name, str):
        return "custom_text"

    # Check if it's an IP address
    if is_valid_ipv4(target_name) or is_valid_ipv6(target_name):
        return "ip_address"

    # Check if it's an IP range (format: 192.168.1.0_28)
    if "_" in target_name and target_name.count(".") == 3:
        parts = target_name.split("_")
        if len(parts) == 2:
            ip_part = parts[0]
            cidr_part = parts[1]
            # Validate IP part
            if is_valid_ipv4(ip_part):
                # Validate CIDR part (should be a number between 0-32)
                with suppress(ValueError):
                    cidr = int(cidr_part)
                    if 0 <= cidr <= 32:
                        return "ip_range"

    # Check if it's a valid domain/subdomain
    if is_valid_domain(target_name):
        # Use tldextract for accurate parsing if available
        try:
            import tldextract
            extracted = tldextract.extract(target_name)
            if extracted.domain and extracted.suffix:
                return "subdomain" if extracted.subdomain else "domain"
        except ImportError:
            # Fallback: simple domain detection
            if "." in target_name and not target_name.startswith(".") and not target_name.endswith("."):
                return "domain"

    # If none of the above, it's custom text
    return "custom_text"


def determine_scan_type_from_engine_name(engine_name: str) -> str:
    """
    Determine the scan type based on engine name by reading the scan_type from the engine's YAML configuration.

    This function reads the scan_type directly from the engine's YAML file in the Global vars section,
    providing a more direct and maintainable approach.

    Args:
        engine_name: The name of the scan engine

    Returns:
        Scan type - 'bug_bounty' or 'internal_network'

    Examples:
        >>> determine_scan_type_from_engine_name("Internal Network - Port Scan")
        'internal_network'
        >>> determine_scan_type_from_engine_name("Initial Scan - reNgine recommended")
        'bug_bounty'
        >>> determine_scan_type_from_engine_name("Custom Engine")
        'bug_bounty'
    """
    try:
        # Look for the engine's YAML file in default_scan_engines directory
        engines_dir = Path(__file__).parent.parent / "config" / "default_scan_engines"
        yaml_file_path = engines_dir / f"{engine_name}.yaml"

        if yaml_file_path.exists():
            # Read the engine's YAML configuration
            content = read_file_content(str(yaml_file_path))
            if content:
                try:
                    import yaml
                    engine_config = yaml.safe_load(content)

                    # Extract scan_type from the configuration
                    if isinstance(engine_config, dict) and "scan_type" in engine_config:
                        scan_type = engine_config["scan_type"]
                        logger.debug(f"Found scan_type in engine '{engine_name}': {scan_type}")
                        return scan_type
                    else:
                        logger.warning(f"No scan_type found in engine '{engine_name}', using default")
                except Exception as e:
                    logger.warning(f"Error parsing YAML for engine '{engine_name}': {e}")
        else:
            logger.warning(f"Engine file not found: {yaml_file_path}, using default")

        # Fallback to default
        return "bug_bounty"

    except Exception as e:
        logger.error(f"Error determining scan type for engine '{engine_name}': {e}")
        return "bug_bounty"  # Safe fallback


def save_traceback_to_file(
    task_name: str,
    exception: Exception,
    results_dir: str,
    scan_history_id: Optional[int] = None,
    subscan_id: Optional[int] = None
) -> str:
    """
    Save a traceback to a file.
    
    Args:
        task_name: Name of the task that failed
        exception: The exception that occurred
        results_dir: Results directory path
        scan_history_id: Scan history ID (optional)
        subscan_id: Subscan ID (optional)
        
    Returns:
        Path to the saved traceback file
    """
    try:
        traceback_path = get_traceback_path(task_name, results_dir, scan_history_id, subscan_id)
        traceback_content = fmt_traceback(exception)
        write_file_content(traceback_path, traceback_content)
        logger.info(f"Traceback saved to: {traceback_path}")
        return traceback_path
    except Exception as e:
        logger.error(f"Failed to save traceback: {e}")
        return ""


def extract_emails_from_text(text: str) -> list:
    """
    Extract email addresses from text content.
    
    Args:
        text: Text content to extract emails from
        
    Returns:
        List of email addresses found
    """
    try:
        return extract_emails(text)
    except Exception as e:
        logger.warning(f"Error extracting emails from text: {e}")
        return []


def validate_target_name(target_name: str) -> bool:
    """
    Validate if a target name is acceptable for scanning.
    
    Args:
        target_name: Target name to validate
        
    Returns:
        True if target is valid, False otherwise
    """
    if not target_name or not isinstance(target_name, str):
        return False
    
    # Check for minimum length
    if len(target_name.strip()) < 1:
        return False
    
    # Check for dangerous characters
    dangerous_chars = ['<', '>', '|', '&', ';', '`', '$', '(', ')']
    if any(char in target_name for char in dangerous_chars):
        return False
    
    return True


def sanitize_target_name(target_name: str) -> str:
    """
    Sanitize a target name for safe use.
    
    Args:
        target_name: Target name to sanitize
        
    Returns:
        Sanitized target name
    """
    if not target_name or not isinstance(target_name, str):
        return ""
    
    # Remove dangerous characters
    dangerous_chars = ['<', '>', '|', '&', ';', '`', '$', '(', ')']
    sanitized = target_name
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    
    # Strip whitespace
    sanitized = sanitized.strip()
    
    return sanitized


def enrich_notification(message, scan_history_id, subscan_id):
    """Add scan id / subscan id to notification message.

    Args:
        message (str): Original notification message.
        scan_history_id (int): Scan history id.
        subscan_id (int): Subscan id.

    Returns:
        str: Message.
    """
    if scan_history_id is not None:
        if subscan_id:
            message = f"`#{scan_history_id}_{subscan_id}`: {message}"
        else:
            message = f"`#{scan_history_id}`: {message}"
    return message
