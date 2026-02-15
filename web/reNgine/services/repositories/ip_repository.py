"""
IP Address Repository - Data access for IP address operations.
Handles IpAddress database operations with Secator integration.
"""

from typing import Any, Dict, Optional, Tuple

from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError

from reNgine.core.validators import is_valid_ip
from reNgine.utilities.logger import get_module_logger
from startScan.models import IpAddress, ScanHistory, Subdomain
from targetApp.models import Domain

PREFIX_IP_REPO = "[IP_REPO]"
logger = get_module_logger(__name__)


class IpRepository:
    """Repository for IP address-related database operations."""

    def save_from_secator(
        self,
        item: Dict[str, Any],
        scan_history_id: int,
        domain_id: int,
        rengine_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[IpAddress]:
        """
        Save IP address from Secator result.

        Args:
            item: Secator IP item
            scan_history_id: ID of the scan history
            domain_id: ID of the domain
            rengine_context: Optional context (e.g. subscan_id for SubScan linking)

        Returns:
            IpAddress: Saved IP address object or None
        """
        try:
            return self._process_secator_ip_item(item, scan_history_id, domain_id, rengine_context or {})
        except ObjectDoesNotExist as e:
            logger.log_line(
                PREFIX_IP_REPO,
                "SAVE",
                "Object not found when saving IP address: %s" % (e,),
                level="error",
            )
            return None
        except IntegrityError as e:
            logger.log_line(
                PREFIX_IP_REPO,
                "SAVE",
                "Integrity error saving IP address: %s" % (e,),
                level="error",
            )
            return None
        except Exception as e:
            logger.log_line(
                PREFIX_IP_REPO,
                "SAVE",
                "Error saving IP address from Secator: %s" % (e,),
                level="error",
            )
            return None

    def _process_secator_ip_item(
        self,
        item: Dict[str, Any],
        scan_history_id: int,
        domain_id: int,
        rengine_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[IpAddress]:
        rengine_context = rengine_context or {}
        ip_address = self._resolve_valid_ip_from_item(item)
        if not ip_address:
            return None

        # Validate scan_history and domain exist
        ScanHistory.objects.get(id=scan_history_id)
        Domain.objects.get(id=domain_id)

        version = self._get_ip_version(ip_address)
        protocol = self._resolve_protocol(version, item.get("protocol"))

        # Get or create IP address
        ip_obj, created = IpAddress.objects.get_or_create(
            address=ip_address,
            defaults={
                "is_cdn": False,
                "is_private": self._is_private_ip(ip_address),
                "version": version,
                "alive": item.get("alive", False),
                "protocol": protocol,
            },
        )

        if created:
            logger.log_line(
                PREFIX_IP_REPO,
                "SAVE",
                "Created IP address: %s" % (ip_address,),
                level="info",
            )
            # Collect for batch geolocalization
            self._collect_ip_for_geolocalization(ip_address)
        else:
            logger.log_line(
                PREFIX_IP_REPO,
                "SAVE",
                "IP address already exists: %s" % (ip_address,),
                level="debug",
            )

        # Associate with subdomain if hostname provided (use value not used as IP when applicable)
        hostname = self._resolve_hostname_for_association(item, ip_address)
        if hostname:
            self._associate_with_subdomain(ip_obj, hostname, scan_history_id)

        # Ensure an endpoint exists for this IP so it can be used as a Secator target (e.g. subscans)
        from reNgine.services.repositories.endpoint_repository import EndpointRepository

        EndpointRepository().create_endpoint_for_ip(ip_address, scan_history_id, domain_id)

        subscan_id = rengine_context.get("subscan_id")
        if subscan_id:
            from startScan.models import SubScan

            try:
                subscan = SubScan.objects.get(id=subscan_id)
                ip_obj.ip_subscan_ids.add(subscan)
            except SubScan.DoesNotExist:
                pass

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
                logger.log_line(
                    PREFIX_IP_REPO,
                    "GET_OR_CREATE",
                    "Invalid IP address: %s" % (address,),
                    level="warning",
                )
                return None, False

            version = self._get_ip_version(address)
            protocol = self._resolve_protocol(version, kwargs.get("protocol"))

            defaults = {
                "is_cdn": False,
                "is_private": self._is_private_ip(address),
                "version": version,
                "protocol": protocol,
            } | kwargs
            ip_obj, created = IpAddress.objects.get_or_create(address=address, defaults=defaults)

            if created:
                logger.log_line(
                    PREFIX_IP_REPO,
                    "GET_OR_CREATE",
                    "Created new IP address: %s" % (address,),
                    level="info",
                )
                self._collect_ip_for_geolocalization(address)

            return ip_obj, created

        except Exception as e:
            logger.log_line(
                PREFIX_IP_REPO,
                "GET_OR_CREATE",
                "Error in get_or_create IP address: %s" % (e,),
                level="error",
            )
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

            # Precompute version for each IP to avoid multiple calls
            ip_objects = []
            for ip_address in ip_addresses:
                if is_valid_ip(ip_address):
                    version = self._get_ip_version(ip_address)
                    ip_objects.append(
                        IpAddress(
                            address=ip_address,
                            is_cdn=False,
                            is_private=self._is_private_ip(ip_address),
                            version=version,
                            protocol="IPv6" if version == 6 else "IPv4",
                        )
                    )

            if ip_objects:
                created = IpAddress.objects.bulk_create(ip_objects, ignore_conflicts=True)
                logger.log_line(
                    PREFIX_IP_REPO,
                    "BULK_CREATE",
                    "Bulk created %s IP addresses" % (len(created),),
                    level="info",
                )

                # Collect all for batch geolocalization
                for ip_obj in created:
                    self._collect_ip_for_geolocalization(ip_obj.address)

                return created

            return []

        except ObjectDoesNotExist as e:
            logger.log_line(
                PREFIX_IP_REPO,
                "BULK_CREATE",
                "Object not found: %s" % (e,),
                level="error",
            )
            return []
        except Exception as e:
            logger.log_line(
                PREFIX_IP_REPO,
                "BULK_CREATE",
                "Error in bulk create IP addresses: %s" % (e,),
                level="error",
            )
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
            logger.log_line(
                PREFIX_IP_REPO,
                "UPDATE",
                "IpAddress with ID %s not found" % (ip_address_id,),
                level="error",
            )
            return False
        except Exception as e:
            logger.log_line(
                PREFIX_IP_REPO,
                "UPDATE",
                "Error updating IP geolocation: %s" % (e,),
                level="error",
            )
            return False

    def _resolve_valid_ip_from_item(self, item: Dict[str, Any]) -> Optional[str]:
        """
        Resolve a valid IP address from item, checking ip, target, then host.
        Used when Secator sends e.g. PTR with ip=hostname and host=IP; we take the valid IP.
        """
        for candidate in (item.get("ip"), item.get("target"), item.get("host")):
            if candidate and is_valid_ip(candidate):
                return candidate
        if any(item.get(k) for k in ("ip", "target", "host")):
            logger.log_line(
                PREFIX_IP_REPO,
                "SAVE",
                "Invalid IP address: no valid IP in ip/target/host (values: ip=%r, target=%r, host=%r)"
                % (item.get("ip"), item.get("target"), item.get("host")),
                level="warning",
            )
        else:
            logger.log_line(
                PREFIX_IP_REPO,
                "SAVE",
                "IP item missing IP address field",
                level="warning",
            )
        return None

    def _resolve_hostname_for_association(self, item: Dict[str, Any], ip_address_used: str) -> Optional[str]:
        """Return hostname for subdomain association (value that is not an IP, or host if it is not the IP used)."""
        host = item.get("host")
        ip_val = item.get("ip")
        if host and host != ip_address_used and not is_valid_ip(host):
            return host
        if ip_val and ip_val != ip_address_used and not is_valid_ip(ip_val):
            return ip_val
        if host and not is_valid_ip(host):
            return host
        if ip_val and not is_valid_ip(ip_val):
            return ip_val
        return None

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

    def _resolve_protocol(self, version: int, protocol: Optional[str]) -> str:
        """
        Resolve protocol string from version and optional protocol.
        Validates and normalizes protocol if provided; otherwise derives from version (IPv4/IPv6).
        """
        from reNgine.core.validators import validate_ip_protocol

        resolved = ""
        if protocol:
            validated = validate_ip_protocol(protocol)
            resolved = validated or ""
        if not resolved:
            resolved = "IPv6" if version == 6 else "IPv4"
        return resolved

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
                logger.log_line(
                    PREFIX_IP_REPO,
                    "ASSOCIATE",
                    "Associated IP %s with subdomain %s" % (ip_obj.address, hostname),
                    level="debug",
                )
            else:
                logger.log_line(
                    PREFIX_IP_REPO,
                    "ASSOCIATE",
                    "No subdomain found for hostname %s in scan %s" % (hostname, scan_history_id),
                    level="debug",
                )

        except Exception as e:
            logger.log_line(
                PREFIX_IP_REPO,
                "ASSOCIATE",
                "Error associating IP with subdomain: %s" % (e,),
                level="error",
            )

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
            logger.log_line(
                PREFIX_IP_REPO,
                "GEO",
                "Error collecting IP for geolocalization: %s" % (e,),
                level="error",
            )
