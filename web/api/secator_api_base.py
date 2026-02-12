"""
Secator API Base - Common functionality for Secator API endpoints.
Provides shared validation, mapping, and error handling logic.
"""

from abc import ABC
from typing import Any, Dict, Optional, Tuple, Type

from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from reNgine.services.repositories.certificate_repository import CertificateRepository
from reNgine.services.repositories.dns_repository import DnsRepository
from reNgine.services.repositories.domain_repository import DomainRepository
from reNgine.services.repositories.employee_repository import EmployeeRepository
from reNgine.services.repositories.endpoint_repository import EndpointRepository
from reNgine.services.repositories.exploit_repository import ExploitRepository
from reNgine.services.repositories.ip_repository import IpRepository
from reNgine.services.repositories.port_repository import PortRepository
from reNgine.services.repositories.subdomain_repository import SubdomainRepository
from reNgine.services.repositories.technology_repository import TechnologyRepository
from reNgine.services.repositories.vulnerability_repository import VulnerabilityRepository
from reNgine.utilities.error import get_safe_user_message
from reNgine.utilities.logger import get_secator_api_logger
from startScan.models import ScanHistory
from targetApp.models import Domain


def _is_validation_like_error(error: Exception) -> bool:
    """Return True if the error message suggests a validation/client error (400)."""
    error_str = str(error).lower()
    return "validation" in error_str or "invalid" in error_str or "required" in error_str


class SecatorAPIBase(APIView, ABC):
    """
    Base class for Secator API endpoints.
    Provides common validation, mapping, and error handling.
    """

    # Mapping of finding types to repository classes
    FINDING_REPOSITORY_MAPPING: Dict[str, Type] = {
        "ip": IpRepository,
        "subdomain": SubdomainRepository,
        "port": PortRepository,
        "url": EndpointRepository,
        "tag": TechnologyRepository,
        "vulnerability": VulnerabilityRepository,
        "record": DnsRepository,
        "domain": DomainRepository,
        "exploit": ExploitRepository,
        "user_account": EmployeeRepository,
        "certificate": CertificateRepository,
    }

    # Types that are metadata/logs and should not be saved to database
    METADATA_TYPES = {"warning", "stat", "target", "log", "debug", "info", "error"}

    def __init__(self, **kwargs):
        """Initialize the base class."""
        super().__init__(**kwargs)
        self.logger = get_secator_api_logger()

    def initial(self, request: Request, *args: Any, **kwargs: Any) -> None:
        """Log request body size for diagnosing nginx buffering, then run default initial."""
        content_length = request.META.get("CONTENT_LENGTH")
        self.logger.log_request_body_size(request.method, request.path, content_length)
        super().initial(request, *args, **kwargs)

    def validate_request_data(
        self, data: Any, entity_id: Optional[str] = None, prefix: Optional[str] = None
    ) -> Tuple[bool, Optional[Response]]:
        """
        Validate that request data is a dictionary.

        Args:
            data: Request data to validate
            entity_id: Optional entity ID for error messages
            prefix: Optional log prefix (defaults to PREFIX_RUNNER for backward compatibility)

        Returns:
            tuple: (is_valid, error_response) - If is_valid is False, error_response contains the error Response
        """
        if not isinstance(data, dict):
            error_msg = f"Invalid request data format: expected dict, got {type(data)}"
            if entity_id:
                error_msg += f" for {entity_id}"
            log_prefix = prefix or self.logger.PREFIX_RUNNER
            self.logger.log_error(
                ValueError(error_msg),
                {"prefix": log_prefix, "action": "VALIDATE", "id": entity_id},
                exc_info=False,
            )
            return False, Response({"status": False, "error": "Invalid request data format"}, status=400)
        return True, None

    def extract_runner_context(self, runner_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract context information from runner data.

        Args:
            runner_data: Runner data dictionary

        Returns:
            dict: Extracted context information with all keys always present (None if missing)
        """
        context = runner_data.get("context", {})
        return {
            "runner_type": runner_data.get("config", {}).get("type"),
            "runner_name": runner_data.get("config", {}).get("name") or runner_data.get("name"),
            "scan_history_id": context.get("scan_history_id"),
            "domain_id": context.get("domain_id"),
            "subscan_id": context.get("subscan_id"),
            "celery_id": context.get("celery_id"),
            "workspace_name": context.get("workspace_name"),
            "status": runner_data.get("status"),
            "progress": runner_data.get("progress"),
            "done": runner_data.get("done"),
        }

    def extract_finding_context(self, finding_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract context information from finding data.

        Secator API hook stores the reNgine runner id in context as task_id,
        workflow_id, or scan_id depending on runner type.

        Args:
            finding_data: Finding data dictionary

        Returns:
            dict: Extracted context information (includes runner_id when present)
        """
        context = finding_data.get("_context", {})
        runner_id = context.get("task_id") or context.get("workflow_id") or context.get("scan_id")
        return {
            "finding_type": finding_data.get("_type"),
            "scan_history_id": context.get("scan_history_id"),
            "domain_id": context.get("domain_id"),
            "task": context.get("task"),
            "runner_id": runner_id,
        }

    def validate_scan_context(
        self,
        scan_history_id: Optional[int],
        domain_id: Optional[int],
        finding_type: Optional[str] = None,
        prefix: Optional[str] = None,
    ) -> Tuple[bool, Optional[Response], Optional[ScanHistory], Optional[Domain]]:
        """
        Validate that scan_history_id and domain_id are provided and exist.

        Args:
            scan_history_id: ID of the scan history
            domain_id: ID of the domain
            finding_type: Optional finding type for error messages
            prefix: Optional log prefix (defaults to PREFIX_FINDING for backward compatibility)

        Returns:
            tuple: (is_valid, error_response, scan_history, domain)
        """
        log_prefix = prefix or self.logger.PREFIX_FINDING
        if not scan_history_id:
            return self._create_missing_context_error_response(
                "Missing scan_history_id in context",
                finding_type,
                "Missing scan_history_id in _context",
                log_prefix,
            )
        if not domain_id:
            return self._create_missing_context_error_response(
                "Missing domain_id in context",
                finding_type,
                "Missing domain_id in _context",
                log_prefix,
            )
        # Validate that ScanHistory and Domain exist
        try:
            scan_history = ScanHistory.objects.get(id=scan_history_id)
            self.logger.log_debug(
                log_prefix,
                "VALIDATE",
                f"ScanHistory {scan_history_id} found: {scan_history.scan_name}",
            )
        except ObjectDoesNotExist:
            self.logger.log_error(
                ObjectDoesNotExist(f"ScanHistory {scan_history_id} not found"),
                {"prefix": log_prefix, "action": "VALIDATE", "scan_id": scan_history_id},
                exc_info=False,
            )
            return (
                False,
                Response({"status": False, "error": f"ScanHistory {scan_history_id} not found"}, status=404),
                None,
                None,
            )

        try:
            domain = Domain.objects.get(id=domain_id)
            self.logger.log_debug(log_prefix, "VALIDATE", f"Domain {domain_id} found: {domain.name}")
        except ObjectDoesNotExist:
            self.logger.log_error(
                ObjectDoesNotExist(f"Domain {domain_id} not found"),
                {"prefix": log_prefix, "action": "VALIDATE", "domain_id": domain_id},
                exc_info=False,
            )
            return (
                False,
                Response({"status": False, "error": f"Domain {domain_id} not found"}, status=404),
                scan_history,
                None,
            )

        return True, None, scan_history, domain

    def _create_missing_context_error_response(
        self,
        error_message: str,
        finding_type: Optional[str],
        response_error_message: str,
        prefix: Optional[str] = None,
    ) -> Tuple[bool, Response, None, None]:
        """
        Create an error response for missing context validation.

        Args:
            error_message: Error message for logging
            finding_type: Optional finding type to include in error message
            response_error_message: Error message for the response
            prefix: Optional log prefix (defaults to PREFIX_FINDING for backward compatibility)

        Returns:
            tuple: (False, error_response, None, None)
        """
        log_prefix = prefix or self.logger.PREFIX_FINDING
        error_msg = error_message
        if finding_type:
            error_msg += f" for finding type={finding_type}"
        self.logger.log_warning(
            error_msg,
            {"prefix": log_prefix, "action": "VALIDATE", "type": finding_type},
        )
        return (
            False,
            Response({"status": False, "error": response_error_message}, status=400),
            None,
            None,
        )

    def get_repository_for_finding_type(self, finding_type: str) -> Optional[Type]:
        """
        Get repository class for a finding type.

        Args:
            finding_type: Type of finding

        Returns:
            Type: Repository class or None if not found
        """
        return self.FINDING_REPOSITORY_MAPPING.get(finding_type)

    def is_metadata_type(self, finding_type: str) -> bool:
        """
        Check if a finding type is a metadata type that should be ignored.

        Args:
            finding_type: Type of finding

        Returns:
            bool: True if it's a metadata type
        """
        return finding_type in self.METADATA_TYPES

    def handle_repository_error(
        self,
        error: Exception,
        finding_type: str,
        scan_history_id: int,
        domain_id: int,
        finding_id: Optional[str] = None,
    ) -> Response:
        """
        Handle errors from repository operations.

        Args:
            error: Exception that occurred
            finding_type: Type of finding
            scan_history_id: ID of the scan history
            domain_id: ID of the domain
            finding_id: Optional finding ID

        Returns:
            Response: Error response
        """
        context = {
            "prefix": self.logger.PREFIX_FINDING,
            "action": "SAVE",
            "type": finding_type,
            "scan_id": scan_history_id,
            "domain_id": domain_id,
        }
        if finding_id:
            context["id"] = finding_id

        # Logging is done via self.logger.log_error in each branch; logger=None avoids double logging in get_safe_user_message.
        if isinstance(error, ObjectDoesNotExist):
            self.logger.log_error(error, context, exc_info=True)
            return Response({"status": False, "error": get_safe_user_message(error, None)}, status=404)
        elif isinstance(error, IntegrityError):
            self.logger.log_error(error, context, exc_info=True)
            return Response({"status": False, "error": get_safe_user_message(error, None)}, status=409)
        else:
            self.logger.log_error(error, context, exc_info=True)
            return Response(
                {"status": False, "error": get_safe_user_message(error, None)},
                status=400 if _is_validation_like_error(error) else 500,
            )
