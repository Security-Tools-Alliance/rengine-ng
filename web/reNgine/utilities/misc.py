from contextlib import suppress
import os
from pathlib import Path
import traceback

import tldextract
import validators
import yaml

from reNgine.settings import CELERY_REMOTE_DEBUG, CELERY_REMOTE_DEBUG_PORT
from reNgine.utilities.logger import get_module_logger


logger = get_module_logger(__name__)


# -----------------#
# Misc Functions  #
# -----------------#


def debug():
    try:
        # Activate remote debug for scan worker
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
        logger.error(e)


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
    Determine the scan type based on engine name by reading the scan_type from the engine's YAML configuration.

    This function reads the scan_type directly from the engine's YAML file in the Global vars section,
    providing a more direct and maintainable approach.

    Args:
        engine_name (str): The name of the scan engine

    Returns:
        str: Scan type - 'internet' or 'internal_network'

    Examples:
        >>> determine_scan_type_from_engine_name("Internal Network - Port Scan")
        'internal_network'
        >>> determine_scan_type_from_engine_name("Initial Scan - reNgine recommended")
        'internet'
        >>> determine_scan_type_from_engine_name("Custom Engine")
        'internet'
    """
    try:
        # Look for the engine's YAML file in default_scan_engines directory
        engines_dir = Path(__file__).parent.parent.parent / "config" / "default_scan_engines"
        yaml_file_path = engines_dir / f"{engine_name}.yaml"

        if yaml_file_path.exists():
            # Read the engine's YAML configuration
            with open(yaml_file_path, "r", encoding="utf-8") as f:
                engine_config = yaml.safe_load(f)

            # Extract scan_type from the configuration
            if isinstance(engine_config, dict) and "scan_type" in engine_config:
                scan_type = engine_config["scan_type"]
                logger.debug(f"Found scan_type in engine '{engine_name}': {scan_type}")
                return scan_type
            else:
                logger.warning(f"No scan_type found in engine '{engine_name}', using default")
        else:
            logger.warning(f"Engine file not found: {yaml_file_path}, using default")

        # Fallback to default
        return "internet"

    except Exception as e:
        logger.error(f"Error determining scan type for engine '{engine_name}': {e}")
        return "internet"  # Safe fallback
