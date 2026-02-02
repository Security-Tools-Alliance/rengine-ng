"""
Port Repository - Data access for port operations.
Handles Port database operations with IP dependency from Secator.
"""

from typing import Any, Dict, List, Optional, Tuple

from celery.utils.log import get_task_logger
from django.core.exceptions import ObjectDoesNotExist
from django.db import DatabaseError, IntegrityError

from reNgine.core.validators import is_valid_ip, is_valid_port
from reNgine.services.repositories.endpoint_repository import EndpointRepository
from startScan.models import IpAddress, Port, ScanHistory
from targetApp.models import Domain


logger = get_task_logger(__name__)


class PortRepository:
    """Repository for port-related database operations."""

    def save_from_secator(
        self,
        item: Dict[str, Any],
        scan_history_id: int,
        domain_id: int,
        rengine_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Port]:
        """
        Save port from Secator result.

        Args:
            item: Secator port item
            scan_history_id: ID of the scan history
            domain_id: ID of the domain
            rengine_context: Optional context (unused for ports)

        Returns:
            Port: Saved port object or None
        """
        try:
            return self._process_secator_port_item(item, scan_history_id, domain_id)
        except ObjectDoesNotExist as e:
            logger.error(f"Object not found when saving port: {e}")
            return None
        except IntegrityError as e:
            logger.error(f"Integrity error saving port: {e}")
            return None
        except DatabaseError as e:
            logger.error(f"Database error saving port from Secator: {e}")
            return None

    def _process_secator_port_item(self, item: Dict[str, Any], scan_history_id: int, domain_id: int) -> Optional[Port]:
        raw_port = item.get("port")
        raw_ip = item.get("ip")
        raw_host = item.get("host")

        if raw_port is None:
            logger.warning("Port item missing port number field")
            return None

        try:
            port_number = int(raw_port)
        except (TypeError, ValueError):
            logger.warning(f"Invalid port number type/value: {raw_port!r}")
            return None

        if not is_valid_port(port_number):
            logger.warning(f"Invalid port number: {port_number}")
            return None

        ip_address: Optional[str] = None
        if raw_ip:
            if is_valid_ip(raw_ip):
                ip_address = raw_ip
            else:
                logger.warning(f"Invalid IP address in 'ip' field for port: {raw_ip}")
        if ip_address is None and raw_host:
            if is_valid_ip(raw_host):
                ip_address = raw_host
            else:
                logger.info("Port item host is not an IP address; treating 'host' as hostname: %s", raw_host)
        if ip_address is None:
            if raw_ip is None and raw_host is None:
                logger.warning("Port item missing both 'ip' and 'host' fields")
            else:
                logger.warning("Port item does not contain a valid IP address in either 'ip' or 'host' fields")
            return None

        # Get or create IP address first
        ip_obj = self._get_or_create_ip(ip_address, scan_history_id, domain_id)
        if not ip_obj:
            logger.error(f"Failed to get or create IP address: {ip_address}")
            return None

        # Get or create port
        port_obj, created = Port.objects.get_or_create(
            number=port_number,
            ip_address=ip_obj,
            defaults={
                "service_name": item.get("service_name", ""),
                "description": item.get("description", ""),
                "is_uncommon": self._is_uncommon_port(port_number),
                "state": item.get("state", ""),
                "cpes": item.get("cpes", []),
                "protocol": item.get("protocol", ""),
                "host": item.get("host", ""),
                "confidence": self._validate_confidence(item.get("confidence", "")),
            },
        )

        if created:
            logger.info(f"Created port: {port_number} on {ip_address}")
        else:
            logger.debug(f"Port already exists: {port_number} on {ip_address}")

        return port_obj

    def get_or_create(self, port_number: int, ip_address: str, **kwargs) -> Tuple[Optional[Port], bool]:
        """
        Get or create a port.

        Args:
            port_number: Port number
            ip_address: IP address string
            **kwargs: Additional fields

        Returns:
            tuple: (Port, created boolean) or (None, False)
        """
        try:
            if not is_valid_port(port_number):
                logger.warning(f"Invalid port number: {port_number}")
                return None, False

            if not is_valid_ip(ip_address):
                logger.warning(f"Invalid IP address: {ip_address}")
                return None, False

            # Get or create IP address
            ip_obj, _ = IpAddress.objects.get_or_create(
                address=ip_address,
                defaults={
                    "is_cdn": False,
                    "is_private": self._is_private_ip(ip_address),
                    "version": self._get_ip_version(ip_address),
                },
            )

            defaults = {
                "service_name": "",
                "description": "",
                "is_uncommon": self._is_uncommon_port(port_number),
            } | kwargs
            port_obj, created = Port.objects.get_or_create(number=port_number, ip_address=ip_obj, defaults=defaults)

            return port_obj, created

        except (IntegrityError, DatabaseError) as e:
            logger.error(f"Error in get_or_create port: {e}")
            return None, False

    def bulk_create(self, ports: list, scan_history_id: int, domain_id: int) -> list:
        """
        Bulk create ports.

        Args:
            ports: List of port dictionaries with 'port' and 'ip' keys
            scan_history_id: ID of the scan history
            domain_id: ID of the domain

        Returns:
            list: List of created Port objects
        """
        try:
            return self._create_ports_in_bulk(scan_history_id, domain_id, ports)
        except ObjectDoesNotExist as e:
            logger.error(f"Object not found: {e}")
            return []
        except DatabaseError as e:
            logger.error(f"Error in bulk create ports: {e}")
            return []

    def _create_ports_in_bulk(self, scan_history_id: int, domain_id: int, ports: List[Dict[str, Any]]) -> List[Port]:
        # Validate scan_history and domain exist
        ScanHistory.objects.get(id=scan_history_id)
        Domain.objects.get(id=domain_id)

        port_objects = []
        seen_ips = set()
        for port_data in ports:
            port_number = port_data.get("port")
            ip_address = port_data.get("ip")

            if is_valid_port(port_number) and is_valid_ip(ip_address):
                # Get or create IP address
                ip_obj, _ = IpAddress.objects.get_or_create(
                    address=ip_address,
                    defaults={
                        "is_cdn": False,
                        "is_private": self._is_private_ip(ip_address),
                        "version": self._get_ip_version(ip_address),
                    },
                )
                if ip_address not in seen_ips:
                    seen_ips.add(ip_address)
                    EndpointRepository().create_endpoint_for_ip(ip_address, scan_history_id, domain_id)

                port_objects.append(
                    Port(
                        number=port_number,
                        ip_address=ip_obj,
                        service_name=port_data.get("service_name", ""),
                        description=port_data.get("description", ""),
                        is_uncommon=self._is_uncommon_port(port_number),
                    )
                )

        if port_objects:
            created = Port.objects.bulk_create(port_objects, ignore_conflicts=True)
            logger.info(f"Bulk created {len(created)} ports")
            return created

        return []

    def update_service_info(self, port_id: int, service_name: str = None, description: str = None) -> bool:
        """
        Update service information for a port.

        Args:
            port_id: ID of the port
            service_name: Service name
            description: Service description

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            port_obj = Port.objects.get(id=port_id)

            if service_name is not None:
                port_obj.service_name = service_name
            if description is not None:
                port_obj.description = description

            port_obj.save()
            return True

        except ObjectDoesNotExist:
            logger.error(f"Port with ID {port_id} not found")
            return False
        except DatabaseError as e:
            logger.error(f"Error updating port service info: {e}")
            return False

    def _get_or_create_ip(self, ip_address: str, scan_history_id: int, domain_id: int) -> Optional[IpAddress]:
        """
        Get or create IP address for port association.

        Args:
            ip_address: IP address string
            scan_history_id: Scan history ID
            domain_id: Domain ID

        Returns:
            IpAddress: IP address object or None
        """
        try:
            ip_obj, created = IpAddress.objects.get_or_create(
                address=ip_address,
                defaults={
                    "is_cdn": False,
                    "is_private": self._is_private_ip(ip_address),
                    "version": self._get_ip_version(ip_address),
                },
            )

            if created:
                logger.info(f"Created IP address for port: {ip_address}")

            return ip_obj

        except (IntegrityError, DatabaseError) as e:
            logger.error(f"Error getting or creating IP for port: {e}")
            return None

    def _validate_confidence(self, confidence: str) -> str:
        """
        Validate and normalize confidence level.

        Args:
            confidence: Confidence string to validate

        Returns:
            str: Validated confidence or empty string if invalid
        """
        from reNgine.core.validators import validate_confidence

        validated = validate_confidence(confidence)
        return validated if validated else ""

    def _is_uncommon_port(self, port_number: int) -> bool:
        """
        Check if port is uncommon.

        Args:
            port_number: Port number

        Returns:
            bool: True if uncommon port
        """
        # Common ports that are not considered uncommon
        common_ports = {
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            135,
            139,
            143,
            443,
            445,  # Standard services
            993,
            995,
            1433,
            1521,
            3306,
            3389,
            5432,
            6379,
            27017,  # Database services
        }

        return port_number not in common_ports

    def _is_private_ip(self, ip_address: str) -> bool:
        """
        Check if IP address is private.

        Args:
            ip_address: IP address to check

        Returns:
            bool: True if private IP
        """
        try:
            import ipaddress

            ip_obj = ipaddress.ip_address(ip_address)
            return ip_obj.is_private
        except (ValueError, ipaddress.AddressValueError):
            return False

    def _get_ip_version(self, ip_address: str) -> int:
        """
        Get IP version (4 or 6).

        Args:
            ip_address: IP address

        Returns:
            int: IP version (4 or 6)
        """
        try:
            import ipaddress

            ip_obj = ipaddress.ip_address(ip_address)
            return ip_obj.version
        except (ValueError, ipaddress.AddressValueError):
            return 4  # Default to IPv4
