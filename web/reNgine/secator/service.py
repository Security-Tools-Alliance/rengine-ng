"""
Secator scan service - Business logic for starting Secator scans.

This service provides the core logic for starting scans, decoupled from
API and UI layers for better reusability and testability.
"""

import logging
import threading

from reNgine.definitions import ABORTED_TASK, FAILED_TASK, SUCCESS_TASK
from reNgine.secator.tasks import initiate_secator_scan
from reNgine.services.repositories.scan_repository import ScanRepository
from scanEngine.models import SecatorScan
from startScan.models import ScanHistory
from targetApp.models import Domain


logger = logging.getLogger(__name__)


def handle_scan_error(scan: ScanHistory, error: Exception) -> None:
    """
    Handle scan error by marking scan as failed if not already in terminal state.

    This function prevents race conditions with hooks that may have updated
    the scan status to a terminal state (SUCCESS, FAILED, or ABORTED).

    Args:
        scan: ScanHistory instance to update
        error: Exception that occurred during scan execution
    """
    logger.error(f"Error in scan thread: {str(error)}")
    # Refresh from DB to get current state before modifying
    scan.refresh_from_db()
    # Only mark as failed if scan is not already in a terminal state
    # to avoid race conditions with hooks that may have updated the status
    terminal_statuses = [SUCCESS_TASK, FAILED_TASK, ABORTED_TASK]
    if scan.scan_status not in terminal_statuses:
        scan.scan_status = FAILED_TASK
        scan.save()
    else:
        logger.debug(f"Scan {scan.id} already in terminal state {scan.scan_status}, skipping error status update")


def start_secator_scan(
    domain_id: int,
    user_id: int,
    execution_mode: str = None,
    workflow_id: int = None,
    task_ids: list = None,
    secator_scan_type: str = None,
    secator_scan_id: int = None,
    imported_subdomains: list = None,
    out_of_scope_subdomains: list = None,
    url_filter: str = "",
    scan_existing_elements: bool = False,
    secator_config: dict = None,
    speed_profile: str = None,
    stealth_profile: str = None,
    expert_mode: bool = False,
) -> dict:
    """
    Start a Secator scan with the given parameters.

    This is a shared service function that can be called from both API and UI layers
    without coupling them together.

    Args:
        domain_id: ID of the target domain
        user_id: ID of the user initiating the scan
        execution_mode: workflow|tasks|scan
        workflow_id: Required for workflow mode
        task_ids: Required for tasks mode
        secator_scan_type: Required for scan mode
        secator_scan_id: ID of existing SecatorScan configuration
        imported_subdomains: List of subdomains to import
        out_of_scope_subdomains: List of subdomains to exclude
        url_filter: URL filter/path to scan
        scan_existing_elements: Whether to scan existing elements
        secator_config: Configuration parameters
        speed_profile: Speed profile (jaguar|rabbit|turtle)
        stealth_profile: Stealth profile (ninja|chameleon|mouse)
        expert_mode: Enable expert mode

    Returns:
        dict: Result with 'status' (bool), 'scan_id' (int), 'error' (str), 'http_status' (int), etc.
    """
    if task_ids is None:
        task_ids = []
    if imported_subdomains is None:
        imported_subdomains = []
    if out_of_scope_subdomains is None:
        out_of_scope_subdomains = []
    if secator_config is None:
        secator_config = {}

    # Validate required parameters
    if not domain_id:
        return {"status": False, "error": "domain_id is required", "http_status": 400}

    # Verify domain exists
    try:
        domain = Domain.objects.get(id=domain_id)
    except Domain.DoesNotExist:
        return {"status": False, "error": f"Domain with ID {domain_id} not found", "http_status": 404}

    # Ensure lists are properly formatted
    if isinstance(imported_subdomains, str):
        imported_subdomains = [s.strip() for s in imported_subdomains.split("\n") if s.strip()]
    if isinstance(out_of_scope_subdomains, str):
        out_of_scope_subdomains = [s.strip() for s in out_of_scope_subdomains.split("\n") if s.strip()]

    try:
        # Handle existing SecatorScan ID
        if secator_scan_id:
            # Use existing SecatorScan - this is a special case for API
            try:
                secator_scan = SecatorScan.objects.get(id=secator_scan_id)
            except SecatorScan.DoesNotExist:
                return {
                    "status": False,
                    "error": f"SecatorScan with ID {secator_scan_id} not found",
                    "http_status": 404,
                }

            # Use the existing scan configuration
            scan_repo = ScanRepository()
            scan_history_id = scan_repo.create_scan(
                host_id=domain_id,
                engine_id=1,
                initiated_by_id=user_id,
            )
            scan = ScanHistory.objects.get(pk=scan_history_id)

            # Extract scan type from YAML configuration or use default
            yaml_config = secator_scan._parse_yaml_config()
            secator_scan_type = (
                yaml_config.get("input_types", ["domain"])[0] if yaml_config.get("input_types") else "domain"
            )

            # Copy user ID to local variable for thread safety
            initiated_by_id = user_id

            # Launch scan asynchronously in a separate thread
            def launch_scan():
                try:
                    initiate_secator_scan(
                        scan_history_id=scan.id,
                        domain_id=domain_id,
                        execution_mode="scan",
                        secator_scan_type=secator_scan_type,
                        imported_subdomains=imported_subdomains,
                        out_of_scope_subdomains=out_of_scope_subdomains,
                        url_filter=url_filter,
                        scan_existing_elements=scan_existing_elements,
                        secator_config=secator_config,
                        speed_profile=speed_profile,
                        stealth_profile=stealth_profile,
                        expert_mode=expert_mode,
                        initiated_by_id=initiated_by_id,
                    )
                    # Do not save scan here - status is managed by Secator hooks via SecatorRunnerUpdate API
                    # Saving would overwrite the status updated by the hooks
                except Exception as e:
                    handle_scan_error(scan, e)

            scan_thread = threading.Thread(target=launch_scan, daemon=True)
            scan_thread.start()

            # Return immediately without waiting for scan completion
            return {
                "status": True,
                "scan_id": scan.id,
                "scan_status": scan.scan_status,
                "domain_id": domain.id,
                "domain_name": domain.name,
                "secator_scan_id": secator_scan.id,
                "execution_mode": "scan",
                "message": f"Scan started successfully for {domain.name}",
                "http_status": 200,
            }

        elif execution_mode:
            # Create scan object first (synchronously)
            scan_repo = ScanRepository()
            scan_history_id = scan_repo.create_scan(
                host_id=domain_id,
                engine_id=1,  # Fixed engine ID for all Secator scans
                initiated_by_id=user_id,
            )
            scan = ScanHistory.objects.get(pk=scan_history_id)

            # Copy user ID to local variable for thread safety
            initiated_by_id = user_id

            # Launch scan asynchronously in a separate thread
            # Secator will handle Celery tasks internally
            def launch_scan():
                try:
                    initiate_secator_scan(
                        scan_history_id=scan.id,
                        domain_id=domain_id,
                        execution_mode=execution_mode,
                        workflow_id=workflow_id,
                        task_ids=task_ids,
                        secator_scan_type=secator_scan_type,
                        imported_subdomains=imported_subdomains,
                        out_of_scope_subdomains=out_of_scope_subdomains,
                        url_filter=url_filter,
                        scan_existing_elements=scan_existing_elements,
                        secator_config=secator_config,
                        speed_profile=speed_profile,
                        stealth_profile=stealth_profile,
                        expert_mode=expert_mode,
                        initiated_by_id=initiated_by_id,
                    )
                    # Do not save scan here - status is managed by Secator hooks via SecatorRunnerUpdate API
                    # Saving would overwrite the status updated by the hooks
                except Exception as e:
                    handle_scan_error(scan, e)

            scan_thread = threading.Thread(target=launch_scan, daemon=True)
            scan_thread.start()

            # Return immediately without waiting for scan completion
            return {
                "status": True,
                "scan_id": scan.id,
                "scan_status": scan.scan_status,
                "domain_id": domain.id,
                "domain_name": domain.name,
                "execution_mode": execution_mode,
                "message": f"Scan started successfully for {domain.name}",
                "http_status": 200,
            }
        else:
            return {
                "status": False,
                "error": "Must provide either secator_scan_id or execution_mode with parameters",
                "http_status": 400,
            }

    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        return {"status": False, "error": "Failed to start scan due to a server error.", "http_status": 500}
