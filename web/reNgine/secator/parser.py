"""
SecatorParser - Parse Secator results and convert to Django models.

This module handles the conversion of Secator output to reNgine's Django models,
ensuring compatibility with the existing database structure.
"""

import logging
from typing import Any, Dict, List, Optional

from django.db import transaction


logger = logging.getLogger(__name__)


class SecatorParser:
    """
    Parse Secator results and convert to Django models.

    This class handles the conversion of Secator output to reNgine's Django models,
    ensuring compatibility with the existing database structure.
    """

    def __init__(self):
        """Initialize the SecatorParser."""
        pass

    def parse(self, result: Dict[str, Any]) -> Optional[Any]:
        """
        Parse a Secator result and convert to appropriate Django model.

        Args:
            result: Secator result dictionary

        Returns:
            Django model instance or None if parsing fails
        """
        try:
            result_type = result.get("type", "").lower()

            parser_map = {
                "subdomain": self._parse_subdomain,
                "url": self._parse_url,
                "vulnerability": self._parse_vulnerability,
                "port": self._parse_port,
                "tag": self._parse_technology,
                "email": self._parse_email,
                "ip": self._parse_ip,
            }

            if parser_func := parser_map.get(result_type):
                return parser_func(result)
            logger.warning(f"Unknown result type: {result_type}")
            return None

        except Exception as e:
            logger.error(f"Error parsing Secator result: {e}")
            return None

    def _parse_subdomain(self, result: Dict[str, Any]) -> Optional[Any]:
        """
        Parse subdomain result and create Subdomain model instance.

        Args:
            result: Secator subdomain result

        Returns:
            Subdomain model instance or None
        """
        try:
            from startScan.models import Subdomain

            subdomain_data = {
                "name": result.get("target", ""),
                "is_imported_subdomain": False,
                "is_important": False,
            }

            return Subdomain(**subdomain_data)
        except Exception as e:
            logger.error(f"Error parsing subdomain result: {e}")
            return None

    def _parse_url(self, result: Dict[str, Any]) -> Optional[Any]:
        """
        Parse URL result and create EndPoint model instance.

        Args:
            result: Secator URL result

        Returns:
            EndPoint model instance or None
        """
        try:
            from startScan.models import EndPoint

            url_data = {
                "http_url": result.get("target", ""),
                "is_imported_subdomain": False,
                "is_important": False,
            }

            return EndPoint(**url_data)
        except Exception as e:
            logger.error(f"Error parsing URL result: {e}")
            return None

    def _parse_vulnerability(self, result: Dict[str, Any]) -> Optional[Any]:
        """
        Parse vulnerability result and create Vulnerability model instance.

        Args:
            result: Secator vulnerability result

        Returns:
            Vulnerability model instance or None
        """
        try:
            from startScan.models import Vulnerability

            # Validate and map severity
            valid_severities = {"critical", "high", "medium", "low", "info"}
            raw_severity = result.get("severity", "").lower()
            if raw_severity not in valid_severities:
                logger.warning(
                    f"Unknown or missing severity '{raw_severity}' in vulnerability result, defaulting to 'medium'"
                )
                severity = "medium"
            else:
                severity = raw_severity

            vuln_data = {
                "name": result.get("name", ""),
                "description": result.get("description", ""),
                "severity": severity,
                "url": result.get("target", ""),
                "http_url": result.get("target", ""),
                "is_imported_subdomain": False,
                "is_important": False,
            }

            return Vulnerability(**vuln_data)
        except Exception as e:
            logger.error(f"Error parsing vulnerability result: {e}")
            return None

    def _parse_port(self, result: Dict[str, Any]) -> Optional[Any]:
        """
        Parse port result and create Port model instance.

        Args:
            result: Secator port result

        Returns:
            Port model instance or None
        """
        try:
            from startScan.models import Port

            # Validate that port number is present and valid
            port_number = result.get("port")
            if port_number is None:
                logger.warning(f"Port result missing port number: {result}")
                return None

            # Check for boolean values (True/False)
            if isinstance(port_number, bool):
                logger.warning(f"Port number '{port_number}' is a boolean value: {result}")
                return None

            # Ensure port number is a valid integer
            try:
                # Check if it's already an integer
                if isinstance(port_number, int):
                    port_number = port_number
                else:
                    # Try to convert to float first to catch decimal numbers
                    float_port = float(port_number)
                    # Check if it's a whole number
                    if float_port != int(float_port):
                        logger.warning(f"Port number '{port_number}' is not a whole number: {result}")
                        return None
                    port_number = int(float_port)
            except (ValueError, TypeError):
                logger.warning(f"Invalid port number '{port_number}' in result: {result}")
                return None

            # Validate port number range (1-65535)
            if not (1 <= port_number <= 65535):
                logger.warning(f"Port number {port_number} out of valid range (1-65535): {result}")
                return None

            port_data = {
                "number": port_number,
                "is_uncommon": False,
                "service_name": result.get("service", ""),
                "description": result.get("description", ""),
            }

            return Port(**port_data)
        except Exception as e:
            logger.error(f"Error parsing port result: {e}")
            return None

    def _parse_technology(self, result: Dict[str, Any]) -> Optional[Any]:
        """
        Parse technology result and create Technology model instance.

        Args:
            result: Secator technology result

        Returns:
            Technology model instance or None
        """
        try:
            from startScan.models import Technology

            tech_data = {
                "name": result.get("name", ""),
                "description": result.get("description", ""),
                "is_imported_subdomain": False,
                "is_important": False,
            }

            return Technology(**tech_data)
        except Exception as e:
            logger.error(f"Error parsing technology result: {e}")
            return None

    def _parse_email(self, result: Dict[str, Any]) -> Optional[Any]:
        """
        Parse email result and create Email model instance.

        Args:
            result: Secator email result

        Returns:
            Email model instance or None
        """
        try:
            from startScan.models import Email

            email_data = {
                "address": result.get("target", ""),
                "is_imported_subdomain": False,
                "is_important": False,
            }

            return Email(**email_data)
        except Exception as e:
            logger.error(f"Error parsing email result: {e}")
            return None

    def _parse_ip(self, result: Dict[str, Any]) -> Optional[Any]:
        """
        Parse IP result and create IPAddress model instance.

        Args:
            result: Secator IP result

        Returns:
            IPAddress model instance or None
        """
        try:
            from startScan.models import IPAddress

            ip_data = {
                "address": result.get("target", ""),
                "is_imported_subdomain": False,
                "is_important": False,
            }

            return IPAddress(**ip_data)
        except Exception as e:
            logger.error(f"Error parsing IP result: {e}")
            return None

    def parse_batch(self, results: List[Dict[str, Any]]) -> List[Any]:
        """
        Parse a batch of Secator results.

        Args:
            results: List of Secator result dictionaries

        Returns:
            List of Django model instances
        """
        parsed_results = []

        for result in results:
            if parsed_result := self.parse(result):
                parsed_results.append(parsed_result)

        return parsed_results

    def save_results(self, results: List[Any], scan_history_id: int) -> int:
        """
        Save parsed results to database with transaction.

        Args:
            results: List of Django model instances
            scan_history_id: Scan history ID for association

        Returns:
            Number of results saved
        """
        saved_count = 0

        try:
            with transaction.atomic():
                for result in results:
                    if result:
                        # Set appropriate association based on model type
                        self._set_model_association(result, scan_history_id)

                        result.save()
                        saved_count += 1

        except Exception as e:
            logger.error(f"Error saving results: {e}")

        return saved_count

    def _set_model_association(self, model_instance: Any, scan_history_id: int) -> None:
        """
        Set appropriate association for model instance based on its type.

        Args:
            model_instance: Django model instance
            scan_history_id: Scan history ID for association
        """
        try:
            # Get the model class name
            model_class = model_instance.__class__.__name__

            # Import ScanHistory for association
            from startScan.models import ScanHistory

            # Get the scan history instance
            scan_history = ScanHistory.objects.get(id=scan_history_id)

            # Set association based on model type
            if model_class == "Subdomain":
                # Subdomain has scan_history field
                model_instance.scan_history = scan_history

            elif model_class == "EndPoint":
                # EndPoint has scan_history field
                model_instance.scan_history = scan_history

            elif model_class == "Vulnerability":
                # Vulnerability has scan_history field
                model_instance.scan_history = scan_history

            elif model_class == "Port":
                # Port doesn't have scan_history, but has ip_address
                # We need to find or create the associated IP address
                # For now, we'll skip setting association for Port
                # as it requires more complex logic to determine the IP
                logger.debug("Port model doesn't have scan_history field, skipping association")

            elif model_class == "Technology":
                # Technology doesn't have scan_history field
                # It's associated through subdomain relationships
                logger.debug("Technology model doesn't have scan_history field, skipping association")

            elif model_class == "Email":
                # Email doesn't have scan_history field
                logger.debug("Email model doesn't have scan_history field, skipping association")

            elif model_class == "IpAddress":
                # IpAddress doesn't have scan_history field
                logger.debug("IpAddress model doesn't have scan_history field, skipping association")

            elif hasattr(model_instance, "scan_history"):
                model_instance.scan_history = scan_history
            elif hasattr(model_instance, "scan_history_id"):
                model_instance.scan_history_id = scan_history_id
            else:
                logger.debug(f"Model {model_class} doesn't have scan_history field, skipping association")

        except Exception as e:
            logger.error(f"Error setting model association for {model_instance.__class__.__name__}: {e}")
            # Don't raise the exception, just log it and continue
