"""
Port Repository - Data access for port operations.
Handles Port database operations with IP dependency from Secator.
"""

from typing import Any, Dict, List, Optional, Tuple

from django.core.exceptions import ObjectDoesNotExist
from django.db import DatabaseError, IntegrityError

from reNgine.core.validators import is_valid_ip, is_valid_port
from reNgine.services.repositories.endpoint_repository import EndpointRepository
from reNgine.services.repositories.subdomain_repository import SubdomainRepository
from reNgine.utilities.domain import get_domain_by_id, resolve_domain_for_scan
from reNgine.utilities.logger import get_module_logger
from reNgine.utilities.url import is_acceptable_subdomain_name
from startScan.models import IpAddress, Port, ScanHistory
from targetApp.models import Target


PREFIX_PORT_REPO = "[PORT_REPO]"
logger = get_module_logger(__name__)


class PortRepository:
    """Repository for port-related database operations."""

    def save_from_secator(
        self,
        item: Dict[str, Any],
        scan_history_id: int,
        target_id: int,
        rengine_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Port]:
        """
        Save port from Secator result.

        Args:
            item: Secator port item
            scan_history_id: ID of the scan history
            target_id: ID of the target (reNgine-ng scan context)
            rengine_context: Optional context (unused for ports)

        Returns:
            Port: Saved port object or None
        """
        try:
            return self._process_secator_port_item(item, scan_history_id, target_id)
        except ObjectDoesNotExist as e:
            logger.log_line(
                PREFIX_PORT_REPO,
                "SAVE",
                "Object not found when saving port: %s" % (e,),
                level="error",
            )
            return None
        except IntegrityError as e:
            logger.log_line(
                PREFIX_PORT_REPO,
                "SAVE",
                "Integrity error saving port: %s" % (e,),
                level="error",
            )
            return None
        except DatabaseError as e:
            logger.log_line(
                PREFIX_PORT_REPO,
                "SAVE",
                "Database error saving port from Secator: %s" % (e,),
                level="error",
            )
            return None

    def _process_secator_port_item(self, item: Dict[str, Any], scan_history_id: int, target_id: int) -> Optional[Port]:
        target_value = Target.objects.filter(id=target_id).values_list("value", flat=True).first() or ""
        domain = resolve_domain_for_scan(
            scan_history_id,
            target_value,
            create=True,
            log_failure={
                "logger": logger,
                "prefix": PREFIX_PORT_REPO,
                "extra": "target_id=%s" % (target_id,),
            },
        )
        if not domain:
            return None
        domain_id = domain.id

        raw_port = item.get("port")
        raw_ip = item.get("ip")
        raw_host = item.get("host")

        if raw_port is None:
            logger.log_line(
                PREFIX_PORT_REPO,
                "SAVE",
                "Port item missing port number field",
                level="warning",
            )
            return None

        try:
            port_number = int(raw_port)
        except (TypeError, ValueError):
            logger.log_line(
                PREFIX_PORT_REPO,
                "SAVE",
                "Invalid port number type/value: %s" % (repr(raw_port),),
                level="warning",
            )
            return None

        if not is_valid_port(port_number):
            logger.log_line(
                PREFIX_PORT_REPO,
                "SAVE",
                "Invalid port number: %s" % (port_number,),
                level="warning",
            )
            return None

        ip_address: Optional[str] = None
        if raw_ip:
            if is_valid_ip(raw_ip):
                ip_address = raw_ip
            else:
                logger.log_line(
                    PREFIX_PORT_REPO,
                    "SAVE",
                    "Invalid IP address in 'ip' field for port: %s" % (raw_ip,),
                    level="warning",
                )
        if ip_address is None and raw_host:
            if is_valid_ip(raw_host):
                ip_address = raw_host
            else:
                logger.log_line(
                    PREFIX_PORT_REPO,
                    "SAVE",
                    "Port item host is not an IP address; treating 'host' as hostname: %s" % (raw_host,),
                    level="info",
                )
        if ip_address is None:
            if raw_ip is None and raw_host is None:
                logger.log_line(
                    PREFIX_PORT_REPO,
                    "SAVE",
                    "Port item missing both 'ip' and 'host' fields",
                    level="warning",
                )
            else:
                logger.log_line(
                    PREFIX_PORT_REPO,
                    "SAVE",
                    "Port item does not contain a valid IP address in either 'ip' or 'host' fields",
                    level="warning",
                )
            return None

        # Get or create IP address first
        ip_obj = self._get_or_create_ip(ip_address, scan_history_id, domain_id)
        if not ip_obj:
            logger.log_line(
                PREFIX_PORT_REPO,
                "SAVE",
                "Failed to get or create IP address: %s" % (ip_address,),
                level="error",
            )
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
            logger.log_line(
                PREFIX_PORT_REPO,
                "SAVE",
                "Created port: %s on %s" % (port_number, ip_address),
                level="info",
            )
        else:
            logger.log_line(
                PREFIX_PORT_REPO,
                "SAVE",
                "Port already exists: %s on %s" % (port_number, ip_address),
                level="debug",
            )

        if raw_host and raw_host.strip().lower() != ip_address and is_acceptable_subdomain_name(raw_host):
            SubdomainRepository().get_or_create_from_host(scan_history_id, target_id, raw_host)

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
                logger.log_line(
                    PREFIX_PORT_REPO,
                    "GET_OR_CREATE",
                    "Invalid port number: %s" % (port_number,),
                    level="warning",
                )
                return None, False

            if not is_valid_ip(ip_address):
                logger.log_line(
                    PREFIX_PORT_REPO,
                    "GET_OR_CREATE",
                    "Invalid IP address: %s" % (ip_address,),
                    level="warning",
                )
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
            logger.log_line(
                PREFIX_PORT_REPO,
                "GET_OR_CREATE",
                "Error in get_or_create port: %s" % (e,),
                level="error",
            )
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
            logger.log_line(
                PREFIX_PORT_REPO,
                "BULK_CREATE",
                "Object not found: %s" % (e,),
                level="error",
            )
            return []
        except DatabaseError as e:
            logger.log_line(
                PREFIX_PORT_REPO,
                "BULK_CREATE",
                "Error in bulk create ports: %s" % (e,),
                level="error",
            )
            return []

    def _create_ports_in_bulk(self, scan_history_id: int, domain_id: int, ports: List[Dict[str, Any]]) -> List[Port]:
        # Validate scan_history and domain exist
        ScanHistory.objects.get(id=scan_history_id)
        if get_domain_by_id(domain_id) is None:
            return []

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
            logger.log_line(
                PREFIX_PORT_REPO,
                "BULK_CREATE",
                "Bulk created %s ports" % (len(created),),
                level="info",
            )
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
            logger.log_line(
                PREFIX_PORT_REPO,
                "UPDATE_SERVICE",
                "Port with ID %s not found" % (port_id,),
                level="error",
            )
            return False
        except DatabaseError as e:
            logger.log_line(
                PREFIX_PORT_REPO,
                "UPDATE_SERVICE",
                "Error updating port service info: %s" % (e,),
                level="error",
            )
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
                logger.log_line(
                    PREFIX_PORT_REPO,
                    "GET_OR_CREATE_IP",
                    "Created IP address for port: %s" % (ip_address,),
                    level="info",
                )

            return ip_obj

        except (IntegrityError, DatabaseError) as e:
            logger.log_line(
                PREFIX_PORT_REPO,
                "GET_OR_CREATE_IP",
                "Error getting or creating IP for port: %s" % (e,),
                level="error",
            )
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
