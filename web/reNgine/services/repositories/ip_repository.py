"""
IP Address Repository - Data access for IP address operations.

Handles IpAddress database operations with Secator integration.

Scan scoping and deduplication (aligned with reNgine.utilities.scan_lookups):
- An IP row is considered in a scan when it is linked via Subdomain.ip_addresses (M2M) for
  that scan_history, or via EndPoint.ip_address for that scan_history.
- Multiple IpAddress rows with the same normalized address in one scan are merged with
  merge_duplicate_into (lowest id kept). Prefer first_ip_in_scan / get_or_create_for_scan
  instead of ad hoc queries.
"""

from typing import Any, Dict, Optional, Tuple

from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError, transaction
from django.db.models import Exists, OuterRef, Q

from reNgine.core.ip_literal import normalize_ip_address_text
from reNgine.core.validators import is_valid_ip
from reNgine.secator.source_extraction import extract_secator_tool_source
from reNgine.utilities.extra_data_merge import merge_secator_item_extra_data_into_model
from reNgine.services.repositories.subdomain_repository import SubdomainRepository
from reNgine.utilities.domain import get_domain_by_id, resolve_domain_for_scan
from reNgine.utilities.logger import format_exception_for_log, get_module_logger
from reNgine.utilities.url import is_acceptable_subdomain_name
from startScan.models import (
    Certificate,
    EndPoint,
    Exploit,
    IpAddress,
    Port,
    ScanHistory,
    Subdomain,
    Vulnerability,
)
from targetApp.models import Target


PREFIX_IP_REPO = "[IP_REPO]"
logger = get_module_logger(__name__)

# Must match startScan.models.IpAddress.reverse_pointer max_length
_REVERSE_POINTER_MAX_LEN = 100


def normalize_ip_address_string(addr: str) -> Optional[str]:
    """Return canonical string form of addr if it is a valid IPv4/IPv6 address."""
    return normalize_ip_address_text(addr)


class IpRepository:
    """Repository for IP address-related database operations."""

    def merge_duplicate_into(self, canonical: IpAddress, duplicate: IpAddress) -> None:
        """Repoint all relations from duplicate to canonical and delete duplicate."""
        if canonical.pk == duplicate.pk:
            return
        with transaction.atomic():
            for sub in Subdomain.objects.filter(ip_addresses=duplicate).distinct():
                sub.ip_addresses.add(canonical)
                sub.ip_addresses.remove(duplicate)
            EndPoint.objects.filter(ip_address=duplicate).update(ip_address=canonical)
            Port.objects.filter(ip_address=duplicate).update(ip_address=canonical)
            Vulnerability.objects.filter(ip_address=duplicate).update(ip_address=canonical)
            Certificate.objects.filter(ip_address=duplicate).update(ip_address=canonical)
            Exploit.objects.filter(ip_address=duplicate).update(ip_address=canonical)
            duplicate.delete()

    def first_ip_in_scan(self, normalized_address: str, scan_history_id: int) -> Optional[IpAddress]:
        """Return the canonical IpAddress row for this address in the scan, merging duplicates if needed."""
        q = Q(ip_addresses__scan_history_id=scan_history_id) | Q(ip_endpoints__scan_history_id=scan_history_id)
        rows = list(IpAddress.objects.filter(address=normalized_address).filter(q).distinct().order_by("id"))
        if not rows:
            return None
        canon = rows[0]
        for dup in rows[1:]:
            self.merge_duplicate_into(canon, dup)
        return IpAddress.objects.filter(pk=canon.pk).first()

    def get_or_create_for_scan(
        self,
        scan_history_id: int,
        target_id: int,
        address: str,
        *,
        alive: Optional[bool] = None,
        item_protocol: Optional[str] = None,
        rengine_context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Optional[IpAddress], bool]:
        """
        Return (IpAddress, created) for this address scoped to the scan.

        Reuses an existing row linked via Subdomain M2M or EndPoint.ip_address for the same scan;
        merges duplicate rows for the same address in that scan.
        """
        normalized = normalize_ip_address_string(address)
        if not normalized:
            return None, False

        if existing := self.first_ip_in_scan(normalized, scan_history_id):
            if alive is not None and existing.alive != alive:
                existing.alive = alive
                existing.save(update_fields=["alive"])
            return existing, False

        version = self._get_ip_version(normalized)
        protocol = self._resolve_protocol(version, item_protocol)
        ip_obj = IpAddress.objects.create(
            address=normalized,
            is_cdn=False,
            is_private=self._is_private_ip(normalized),
            version=version,
            alive=alive if alive is not None else False,
            protocol=protocol,
        )
        logger.log_line(
            PREFIX_IP_REPO,
            "GET_OR_CREATE_SCAN",
            "Created IP address for scan: %s scan_id=%s" % (normalized, scan_history_id),
            level="info",
        )
        self._collect_ip_for_geolocalization(normalized)
        return ip_obj, True

    def sync_alive_from_http_evidence(self, ip_id: int, scan_history_id: int) -> bool:
        """
        Set alive=True when this IP has HTTP response evidence in the scan.

        Evidence: any EndPoint on this scan with http_status > 0 linked directly to the IP,
        or linked to a Subdomain that lists this IP in ip_addresses (subdomain.http_status > 0
        or any EndPoint for that subdomain on this scan with http_status > 0).

        Never sets alive=False (ingestion order and partial scans).

        Returns:
            True if this call saved alive=True; False if unchanged or IP missing.
        """
        try:
            ip_obj = IpAddress.objects.get(pk=ip_id)
        except IpAddress.DoesNotExist:
            return False
        if ip_obj.alive:
            return False
        if not self._ip_has_http_alive_evidence(ip_id, scan_history_id):
            return False
        ip_obj.alive = True
        ip_obj.save(update_fields=["alive"])
        logger.log_line(
            PREFIX_IP_REPO,
            "SYNC_ALIVE_HTTP",
            "Set alive=True from HTTP evidence ip_id=%s scan_id=%s" % (ip_id, scan_history_id),
            level="debug",
        )
        return True

    def save_from_secator(
        self,
        item: Dict[str, Any],
        scan_history_id: int,
        target_id: int,
        rengine_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[IpAddress]:
        """
        Save IP address from Secator result.

        Args:
            item: Secator IP item
            scan_history_id: ID of the scan history
            target_id: ID of the target (reNgine-ng scan context)
            rengine_context: Optional context (e.g. subscan_id for SubScan linking)

        Returns:
            IpAddress: Saved IP address object or None
        """
        try:
            return self._process_secator_ip_item(item, scan_history_id, target_id, rengine_context or {})
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

    def _process_secator_ip_item(
        self,
        item: Dict[str, Any],
        scan_history_id: int,
        target_id: int,
        rengine_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[IpAddress]:
        rengine_context = rengine_context or {}
        ip_address = self._resolve_valid_ip_from_item(item)
        if not ip_address:
            return None

        target_value = Target.objects.filter(id=target_id).values_list("value", flat=True).first() or ""
        domain = resolve_domain_for_scan(
            scan_history_id,
            target_value,
            create=True,
            log_failure={
                "logger": logger,
                "prefix": PREFIX_IP_REPO,
                "extra": "target_id=%s" % (target_id,),
            },
        )
        if not domain:
            return None
        domain_id = domain.id

        ScanHistory.objects.get(id=scan_history_id)

        ip_obj, created = self.get_or_create_for_scan(
            scan_history_id,
            target_id,
            ip_address,
            alive=item.get("alive", False),
            item_protocol=item.get("protocol"),
            rengine_context=rengine_context,
        )
        if not ip_obj:
            logger.log_line(
                PREFIX_IP_REPO,
                "SAVE",
                "Skipped Secator IP (invalid or unnormalizable address): scan_id=%s target_id=%s raw=%r"
                % (scan_history_id, target_id, ip_address),
                level="warning",
            )
            return None

        if created:
            logger.log_line(
                PREFIX_IP_REPO,
                "SAVE",
                "Created IP address for scan: %s" % (ip_obj.address,),
                level="info",
            )
        else:
            logger.log_line(
                PREFIX_IP_REPO,
                "SAVE",
                "IP address already in scan: %s" % (ip_obj.address,),
                level="debug",
            )

        self._apply_reverse_pointer_from_secator_item(ip_obj, item, ip_address)
        self._merge_ip_extra_data_from_secator(ip_obj, item)
        if src := extract_secator_tool_source(item, include_provider=False, max_length=200):
            if ip_obj.source != src:
                ip_obj.source = src
                ip_obj.save(update_fields=["source"])

        # Link this IpAddress to a DNS hostname on a Subdomain only (not IP literals; those use IpAddress + EndPoint).
        hostname = self._resolve_hostname_for_association(item, ip_address)
        if hostname and is_acceptable_subdomain_name(hostname) and not is_valid_ip(hostname):
            subdomain = SubdomainRepository().get_or_create_from_host(
                scan_history_id, target_id, hostname, rengine_context=rengine_context
            )
            if subdomain:
                subdomain.ip_addresses.add(ip_obj)
                logger.log_line(
                    PREFIX_IP_REPO,
                    "ASSOCIATE_IP_TO_SUBDOMAIN",
                    "IP %s linked to subdomain %s" % (ip_obj.address, hostname),
                    level="debug",
                )

        # Ensure an endpoint exists for this IP so it can be used as a Secator target (e.g. subscans)
        from reNgine.services.repositories.endpoint_repository import EndpointRepository

        EndpointRepository().create_endpoint_for_ip(ip_obj.address, scan_history_id, domain_id)

        if subscan_id := rengine_context.get("subscan_id"):
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
            if get_domain_by_id(domain_id) is None:
                return []

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
                    "ASSOCIATE_IP_TO_SUBDOMAIN",
                    "IP %s linked to subdomain %s" % (ip_obj.address, hostname),
                    level="debug",
                )
            else:
                logger.log_line(
                    PREFIX_IP_REPO,
                    "ASSOCIATE_IP_TO_SUBDOMAIN",
                    "Subdomain not found in scan: hostname=%s scan_id=%s" % (hostname, scan_history_id),
                    level="debug",
                )

        except Exception as e:
            reason = format_exception_for_log(e)
            logger.log_line(
                PREFIX_IP_REPO,
                "ASSOCIATE_IP_TO_SUBDOMAIN",
                "Error linking IP to subdomain: %s | hostname=%s scan_id=%s" % (reason, hostname, scan_history_id),
                level="error",
            )

    def _merge_ip_extra_data_from_secator(self, ip_obj: IpAddress, item: Dict[str, Any]) -> None:
        merge_secator_item_extra_data_into_model(ip_obj, item)

    def _apply_reverse_pointer_from_secator_item(
        self, ip_obj: IpAddress, item: Dict[str, Any], normalized_ip: str
    ) -> None:
        """Fill or refresh IpAddress.reverse_pointer from Secator Ip payload (PTR-aware)."""
        candidate, from_ptr = self._reverse_pointer_candidate_from_secator_item(item, normalized_ip)
        if not candidate:
            return
        current = (ip_obj.reverse_pointer or "").strip()
        if not from_ptr and current:
            return
        if current == candidate:
            return
        ip_obj.reverse_pointer = candidate
        ip_obj.save(update_fields=["reverse_pointer"])

    @staticmethod
    def _secator_item_tag_set(item: Dict[str, Any]) -> set[str]:
        raw = item.get("tags")
        if raw is None:
            return set()
        if isinstance(raw, str):
            return {raw.lower()}
        if isinstance(raw, (list, tuple)):
            return {str(t).lower() for t in raw if t is not None}
        return set()

    def _normalize_reverse_pointer_candidate(self, value: str, normalized_ip: str) -> Optional[str]:
        """Normalize a candidate reverse pointer hostname.

        The returned hostname is always lowercased so callers can use case-sensitive
        equality without treating DNS case-only differences as changes. Internal
        comparisons use the same lowercased form.
        """
        s = value.strip().rstrip(".").strip()
        if not s:
            return None
        s = s.lower()
        if is_valid_ip(s):
            return None
        if s == normalized_ip:
            return None
        equiv = normalize_ip_address_string(s)
        if equiv and equiv == normalized_ip:
            return None
        if len(s) > _REVERSE_POINTER_MAX_LEN:
            s = s[:_REVERSE_POINTER_MAX_LEN]
        return s

    def _reverse_pointer_candidate_from_secator_item(
        self, item: Dict[str, Any], normalized_ip: str
    ) -> Tuple[Optional[str], bool]:
        """
        Return (hostname, from_ptr_record).

        dnsx A/AAAA uses host as forward DNS name — do not store as reverse_pointer.
        dnsx PTR stores the PTR target in item['ip'] when host holds the address.
        """
        tags = self._secator_item_tag_set(item)
        if "ptr" in tags:
            raw = item.get("ip")
            if raw is not None:
                text = raw if isinstance(raw, str) else str(raw)
                cand = self._normalize_reverse_pointer_candidate(text, normalized_ip)
                if cand:
                    return cand, True
            return None, False
        if "a" in tags or "aaaa" in tags:
            return None, False
        host_raw = item.get("host")
        ip_raw = item.get("ip")
        if (
            isinstance(ip_raw, str)
            and isinstance(host_raw, str)
            and is_valid_ip(host_raw)
            and not is_valid_ip(ip_raw)
            and normalize_ip_address_string(host_raw) == normalized_ip
        ):
            cand = self._normalize_reverse_pointer_candidate(ip_raw, normalized_ip)
            if cand:
                return cand, True
        host = host_raw
        if host is None or not isinstance(host, str):
            return None, False
        cand = self._normalize_reverse_pointer_candidate(host, normalized_ip)
        if cand:
            return cand, False
        return None, False

    def _ip_has_http_alive_evidence(self, ip_id: int, scan_history_id: int) -> bool:
        if EndPoint.objects.filter(
            scan_history_id=scan_history_id,
            http_status__gt=0,
            ip_address_id=ip_id,
        ).exists():
            return True
        subdomain_http_or_endpoint = Subdomain.objects.filter(
            scan_history_id=scan_history_id,
            ip_addresses__id=ip_id,
        ).filter(
            Q(http_status__gt=0)
            | Exists(
                EndPoint.objects.filter(
                    scan_history_id=scan_history_id,
                    subdomain_id=OuterRef("pk"),
                    http_status__gt=0,
                )
            )
        )
        return subdomain_http_or_endpoint.exists()

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
