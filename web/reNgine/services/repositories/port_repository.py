"""
Port Repository - Data access for port operations.
Handles Port database operations with IP dependency from Secator.
"""

from typing import Any, Dict, Optional, Tuple

from celery.utils.log import get_task_logger
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError

from reNgine.core.validators import is_valid_ip, is_valid_port
from startScan.models import IpAddress, Port, ScanHistory
from targetApp.models import Domain


logger = get_task_logger(__name__)


class PortRepository:
    """Repository for port-related database operations."""

    def save_from_secator(self, item: Dict[str, Any], scan_history_id: int, domain_id: int) -> Optional[Port]:
        """
        Save port from Secator result.

        Args:
            item: Secator port item
            scan_history_id: ID of the scan history
            domain_id: ID of the domain

        Returns:
            Port: Saved port object or None
        """
        try:
            port_number = item.get("port")
            ip_address = item.get("ip") or item.get("host")

            if not port_number:
                logger.warning("Port item missing port number field")
                return None

            if not is_valid_port(port_number):
                logger.warning(f"Invalid port number: {port_number}")
                return None

            if not ip_address:
                logger.warning("Port item missing IP address field")
                return None

            if not is_valid_ip(ip_address):
                logger.warning(f"Invalid IP address for port: {ip_address}")
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
                },
            )

            if created:
                logger.info(f"Created port: {port_number} on {ip_address}")
            else:
                logger.debug(f"Port already exists: {port_number} on {ip_address}")

            return port_obj

        except ObjectDoesNotExist as e:
            logger.error(f"Object not found when saving port: {e}")
            return None
        except IntegrityError as e:
            logger.error(f"Integrity error saving port: {e}")
            return None
        except Exception as e:
            logger.error(f"Error saving port from Secator: {e}")
            return None

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
            }
            defaults.update(kwargs)

            port_obj, created = Port.objects.get_or_create(number=port_number, ip_address=ip_obj, defaults=defaults)

            return port_obj, created

        except Exception as e:
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
            # Validate scan_history and domain exist
            ScanHistory.objects.get(id=scan_history_id)
            Domain.objects.get(id=domain_id)

            port_objects = []
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

        except ObjectDoesNotExist as e:
            logger.error(f"Object not found: {e}")
            return []
        except Exception as e:
            logger.error(f"Error in bulk create ports: {e}")
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
        except Exception as e:
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

        except Exception as e:
            logger.error(f"Error getting or creating IP for port: {e}")
            return None

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
