from contextlib import suppress
import os
import traceback

import tldextract
import validators

from reNgine.settings import CELERY_REMOTE_DEBUG, CELERY_REMOTE_DEBUG_PORT
from reNgine.utilities.logger import get_module_logger


PREFIX_MISC = "[MISC]"
logger = get_module_logger(__name__)


# -----------------#
# Misc Functions  #
# -----------------#


def debug():
    try:
        # Activate remote debug for scan worker
        if CELERY_REMOTE_DEBUG:
            logger.log_line(
                PREFIX_MISC,
                "DEBUG",
                "\n⚡ Debugger started on port %s, task is waiting IDE (VSCode ...) to be attached to continue ⚡\n"
                % (CELERY_REMOTE_DEBUG_PORT,),
                level="info",
            )
            os.environ["GEVENT_SUPPORT"] = "True"
            import debugpy

            debugpy.listen(("0.0.0.0", CELERY_REMOTE_DEBUG_PORT))
            debugpy.wait_for_client()
    except Exception as e:
        logger.log_line(
            PREFIX_MISC,
            "DEBUG",
            "Debugger error: %s" % (e,),
            level="error",
        )


def fmt_traceback(exc):
    return "\n".join(traceback.format_exception(None, exc, exc.__traceback__))


def get_traceback_path(task_name, results_dir, scan_history_id=None, subscan_id=None):
    path = results_dir
    if scan_history_id:
        path += f"/#{scan_history_id}"
        if subscan_id:
            path += f"-#{subscan_id}"
    path += f"-{task_name}.txt"
    return path


def determine_target_type(target_name):
    """
    Determine the type of target based on its name.

    This function analyzes a target name and determines whether it's an IP address,
    IP range, domain, subdomain, or custom text. This is used to adapt the scan
    workflow and tasks according to the target type.

    Args:
        target_name (str): The target name to analyze

    Returns:
        str: Target type - 'ip_address', 'ip_range', 'custom_text', 'domain', or 'subdomain'

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
    # Check if it's an IP address
    if validators.ip_address.ipv4(target_name) or validators.ip_address.ipv6(target_name):
        return "ip_address"

    # Check if it's an IP range (format: 192.168.1.0_28)
    if "_" in target_name and target_name.count(".") == 3:
        parts = target_name.split("_")
        if len(parts) == 2:
            ip_part = parts[0]
            cidr_part = parts[1]
            # Validate IP part
            if validators.ip_address.ipv4(ip_part):
                # Validate CIDR part (should be a number between 0-32)
                with suppress(ValueError):
                    cidr = int(cidr_part)
                    if 0 <= cidr <= 32:
                        return "ip_range"

    # Check if it's a valid domain/subdomain using tldextract for accurate parsing
    if validators.domain(target_name):
        # Use tldextract to parse the domain accurately
        extracted = tldextract.extract(target_name)
        if extracted.domain and extracted.suffix:
            return "subdomain" if extracted.subdomain else "domain"

    # If none of the above, it's custom text
    return "custom_text"


def determine_scan_type_from_engine_name(engine_name):
    """
    Determine the scan type from the engine name using the EngineType model (database).

    Args:
        engine_name (str): The name of the scan engine

    Returns:
        str: Scan type - 'internet' or 'internal_network'
    """
    try:
        from scanEngine.models import EngineType

        engine = EngineType.objects.filter(engine_name=engine_name).first()
        if engine and getattr(engine, "scan_type", None):
            return engine.scan_type
        return "internet"
    except Exception as e:
        logger.log_line(
            PREFIX_MISC,
            "SCAN_TYPE",
            "Error determining scan type for engine '%s': %s" % (engine_name, e),
            level="error",
        )
        return "internet"
