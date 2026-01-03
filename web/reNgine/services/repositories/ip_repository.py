"""
IP Address Repository - Data access for IP address operations.
Handles IpAddress database operations with Secator integration.
"""

from typing import Any, Dict, Optional, Tuple

from celery.utils.log import get_task_logger
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError

from reNgine.core.validators import is_valid_ip
from startScan.models import IpAddress, ScanHistory, Subdomain
from targetApp.models import Domain


logger = get_task_logger(__name__)


class IpRepository:
    """Repository for IP address-related database operations."""

    def save_from_secator(self, item: Dict[str, Any], scan_history_id: int, domain_id: int) -> Optional[IpAddress]:
        """
        Save IP address from Secator result.

        Args:
            item: Secator IP item
            scan_history_id: ID of the scan history
            domain_id: ID of the domain

        Returns:
            IpAddress: Saved IP address object or None
        """
        try:
            return self._process_secator_ip_item(item, scan_history_id, domain_id)
        except ObjectDoesNotExist as e:
            logger.error(f"Object not found when saving IP address: {e}")
            return None
        except IntegrityError as e:
            logger.error(f"Integrity error saving IP address: {e}")
            return None
        except Exception as e:
            logger.error(f"Error saving IP address from Secator: {e}")
            return None

    def _process_secator_ip_item(
        self, item: Dict[str, Any], scan_history_id: int, domain_id: int
    ) -> Optional[IpAddress]:
        ip_address = item.get("ip") or item.get("target") or item.get("host")

        if not ip_address:
            logger.warning("IP item missing IP address field")
            return None

        if not is_valid_ip(ip_address):
            logger.warning(f"Invalid IP address: {ip_address}")
            return None

        # Validate scan_history and domain exist
        ScanHistory.objects.get(id=scan_history_id)
        Domain.objects.get(id=domain_id)

        # Get or create IP address
        ip_obj, created = IpAddress.objects.get_or_create(
            address=ip_address,
            defaults={
                "is_cdn": False,
                "is_private": self._is_private_ip(ip_address),
                "version": self._get_ip_version(ip_address),
                "alive": item.get("alive", False),
            },
        )

        if created:
            logger.info(f"Created IP address: {ip_address}")
            # Collect for batch geolocalization
            self._collect_ip_for_geolocalization(ip_address)
        else:
            logger.debug(f"IP address already exists: {ip_address}")

        # Associate with subdomain if hostname provided
        hostname = item.get("host")
        if hostname and not is_valid_ip(hostname):  # hostname is not an IP
            self._associate_with_subdomain(ip_obj, hostname, scan_history_id)

        return ip_obj

    def get_or_create(self, address: str, **kwargs) -> Tuple[Optional[IpAddress], bool]:
        """
        Get or create an IP address.

        Args:
            address: IP address
            **kwargs: Additional fields

        Returns:
            tuple: (IpAddress, created boolean) or (None, False)
        """
        try:
            if not is_valid_ip(address):
                logger.warning(f"Invalid IP address: {address}")
                return None, False

            defaults = {
                "is_cdn": False,
                "is_private": self._is_private_ip(address),
                "version": self._get_ip_version(address),
            } | kwargs
            ip_obj, created = IpAddress.objects.get_or_create(address=address, defaults=defaults)

            if created:
                logger.info(f"Created new IP address: {address}")
                self._collect_ip_for_geolocalization(address)

            return ip_obj, created

        except Exception as e:
            logger.error(f"Error in get_or_create IP address: {e}")
            return None, False

    def bulk_create(self, ip_addresses: list, scan_history_id: int, domain_id: int) -> list:
        """
        Bulk create IP addresses.

        Args:
            ip_addresses: List of IP address strings
            scan_history_id: ID of the scan history
            domain_id: ID of the domain

        Returns:
            list: List of created IpAddress objects
        """
        try:
            # Validate scan_history and domain exist
            ScanHistory.objects.get(id=scan_history_id)
            Domain.objects.get(id=domain_id)

            if ip_objects := [
                IpAddress(
                    address=ip_address,
                    is_cdn=False,
                    is_private=self._is_private_ip(ip_address),
                    version=self._get_ip_version(ip_address),
                )
                for ip_address in ip_addresses
                if is_valid_ip(ip_address)
            ]:
                created = IpAddress.objects.bulk_create(ip_objects, ignore_conflicts=True)
                logger.info(f"Bulk created {len(created)} IP addresses")

                # Collect all for batch geolocalization
                for ip_obj in created:
                    self._collect_ip_for_geolocalization(ip_obj.address)

                return created

            return []

        except ObjectDoesNotExist as e:
            logger.error(f"Object not found: {e}")
            return []
        except Exception as e:
            logger.error(f"Error in bulk create IP addresses: {e}")
            return []

    def update_geolocation(self, ip_address_id: int, geo_data: Dict[str, Any]) -> bool:
        """
        Update geolocation data for an IP address.

        Args:
            ip_address_id: ID of the IP address
            geo_data: Geolocation data dictionary

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            ip_obj = IpAddress.objects.get(id=ip_address_id)

            # Update geolocation fields if available
            if "country_iso" in geo_data:
                from startScan.models import CountryISO

                country, _ = CountryISO.objects.get_or_create(
                    iso=geo_data["country_iso"], defaults={"name": geo_data.get("country_name", "")}
                )
                ip_obj.geo_iso = country

            ip_obj.save()
            return True

        except ObjectDoesNotExist:
            logger.error(f"IpAddress with ID {ip_address_id} not found")
            return False
        except Exception as e:
            logger.error(f"Error updating IP geolocation: {e}")
            return False

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

    def _associate_with_subdomain(self, ip_obj: IpAddress, hostname: str, scan_history_id: int) -> None:
        """
        Associate IP address with subdomain if found.

        Args:
            ip_obj: IP address object
            hostname: Hostname to search for
            scan_history_id: Scan history ID
        """
        try:
            if subdomain := Subdomain.objects.filter(name=hostname, scan_history_id=scan_history_id).first():
                subdomain.ip_addresses.add(ip_obj)
                logger.debug(f"Associated IP {ip_obj.address} with subdomain {hostname}")
            else:
                logger.debug(f"No subdomain found for hostname {hostname} in scan {scan_history_id}")

        except Exception as e:
            logger.error(f"Error associating IP with subdomain: {e}")

    def _collect_ip_for_geolocalization(self, ip_address: str) -> None:
        """
        Collect IP address for batch geolocalization.

        Args:
            ip_address: IP address to collect
        """
        try:
            # Import here to avoid circular imports
            from reNgine.utilities.dns import collect_ip_for_geolocalization

            collect_ip_for_geolocalization(ip_address)
        except Exception as e:
            logger.error(f"Error collecting IP for geolocalization: {e}")
