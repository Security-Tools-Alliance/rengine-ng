"""
DNS Repository - Data access for DNS record operations.
Handles DNSRecord database operations from Secator Record type.
"""

import json
from typing import Any, Dict, List, Optional, Tuple

from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError, transaction

from reNgine.utilities.extra_data_merge import (
    bounded_diagnostic_preview,
    coerce_extra_data_field_to_plain_dict,
    merge_extra_data_payload_into_model,
)
from reNgine.services.repositories.subdomain_repository import SubdomainRepository
from reNgine.utilities.domain import get_domain_by_id, get_or_create_domain_for_target
from reNgine.utilities.logger import get_module_logger
from reNgine.utilities.url import is_acceptable_subdomain_name
from startScan.models import DNSRecord, Domain, DomainInfo
from targetApp.models import Target


PREFIX_DNS_REPO = "[DNS_REPO]"
_LOG_MSG_SAVE_NON_DICT_EXTRA_DATA = (
    "Non-dict extra_data in save_from_secator; normalized while preserving diagnostics if needed. "
    "scan_history_id=%s target_id=%s record_name=%s raw_type=%s raw_preview=%s"
)
logger = get_module_logger(__name__)


class DnsRepository:
    """Repository for DNS record-related database operations."""

    # Valid DNS record types (uppercase). Includes Secator dnsx record kinds plus common extras.
    VALID_DNS_TYPES = {
        "A",
        "AAAA",
        "ANY",
        "CAA",
        "CNAME",
        "DNAME",
        "DNSKEY",
        "DS",
        "HINFO",
        "HTTPS",
        "MX",
        "NAPTR",
        "NSEC",
        "NSEC3",
        "NS",
        "PTR",
        "SOA",
        "SRV",
        "TLSA",
        "TXT",
        "AXFR",  # Zone transfer — security signal from dnsx
    }

    def save_from_secator(
        self,
        item: Dict[str, Any],
        scan_history_id: int,
        target_id: int,
        rengine_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[DNSRecord]:
        """
        Save DNS record from Secator result (Secator Record format: name, type, host).

        Args:
            item: Secator record item
            scan_history_id: ID of the scan history
            target_id: ID of the target (reNgine-ng scan context)
            rengine_context: Optional context (unused for DNS records)

        Returns:
            DNSRecord: Saved DNS record object or None
        """
        try:
            return self._process_secator_dns_record_item(item, scan_history_id, target_id)
        except ObjectDoesNotExist as e:
            logger.log_line(
                PREFIX_DNS_REPO,
                "SAVE",
                "Object not found when saving DNS record: %s" % (e,),
                level="error",
            )
            return None
        except IntegrityError as e:
            logger.log_line(
                PREFIX_DNS_REPO,
                "SAVE",
                "Integrity error saving DNS record: %s" % (e,),
                level="error",
            )
            return None

    def _process_secator_dns_record_item(
        self, item: Dict[str, Any], scan_history_id: int, target_id: int
    ) -> Optional[DNSRecord]:
        record_name = item.get("name")
        record_type = (item.get("type") or "").upper()
        host = item.get("host")

        if not record_name:
            logger.log_line(
                PREFIX_DNS_REPO,
                "SAVE",
                "DNS record item missing name field",
                level="warning",
            )
            return None

        if not record_type:
            logger.log_line(
                PREFIX_DNS_REPO,
                "SAVE",
                "DNS record item missing type field",
                level="warning",
            )
            return None

        if not host:
            logger.log_line(
                PREFIX_DNS_REPO,
                "SAVE",
                "DNS record item missing host/value field",
                level="warning",
            )
            return None

        # Validate DNS record type
        if record_type not in self.VALID_DNS_TYPES:
            logger.log_line(
                PREFIX_DNS_REPO,
                "SAVE",
                "Invalid DNS record type: %s, skipping" % (record_type,),
                level="warning",
            )
            return None

        target_value = Target.objects.filter(id=target_id).values_list("value", flat=True).first() or ""
        domain = get_or_create_domain_for_target(scan_history_id, target_value) if target_value else None
        if not domain and is_acceptable_subdomain_name(record_name):
            domain = get_or_create_domain_for_target(scan_history_id, record_name)
        if not domain:
            logger.log_line(
                PREFIX_DNS_REPO,
                "SAVE",
                "Could not resolve domain for target_id=%s, record name=%s" % (target_id, record_name),
                level="warning",
            )
            return None

        if is_acceptable_subdomain_name(record_name):
            SubdomainRepository().get_or_create_from_host(scan_history_id, target_id, record_name)
        if host and host != record_name and is_acceptable_subdomain_name(host):
            SubdomainRepository().get_or_create_from_host(scan_history_id, target_id, host)

        name_value = record_name
        incoming_extra = item.get("extra_data", {}) or {}
        if not isinstance(incoming_extra, dict):
            raw_extra = incoming_extra
            normalized_from_json: Optional[Dict[str, Any]] = None
            if isinstance(raw_extra, str):
                try:
                    decoded = json.loads(raw_extra)
                    if isinstance(decoded, dict):
                        normalized_from_json = decoded
                except (json.JSONDecodeError, TypeError, ValueError):
                    pass
            raw_preview = bounded_diagnostic_preview(raw_extra, use_repr=True)
            if normalized_from_json is not None:
                incoming_extra = normalized_from_json
            else:
                incoming_extra = {"extra_data_raw": raw_preview}
            logger.log_line(
                PREFIX_DNS_REPO,
                "SAVE",
                _LOG_MSG_SAVE_NON_DICT_EXTRA_DATA
                % (
                    scan_history_id,
                    target_id,
                    record_name,
                    type(raw_extra).__name__,
                    raw_preview,
                ),
                level="warning",
            )

        # Get or create domain info and DNS record atomically to prevent race conditions.
        # select_for_update locks the domain row until the transaction commits.
        with transaction.atomic():
            domain = Domain.objects.select_for_update().get(id=domain.id)
            domain_info = domain.domain_info if hasattr(domain, "domain_info") and domain.domain_info else None
            if not domain_info:
                domain_info = DomainInfo()
                domain_info.save()
                domain.domain_info = domain_info
                domain.save()
                logger.log_line(
                    PREFIX_DNS_REPO,
                    "SAVE",
                    "Created domain info for domain %s" % (domain.name,),
                    level="debug",
                )

            if existing_record := (
                domain_info.dns_records.filter(type=record_type, name=name_value).first()
                or domain_info.dns_records.filter(type=record_type, name=host).first()
            ):
                old_name = existing_record.name
                old_extra = coerce_extra_data_field_to_plain_dict(existing_record.extra_data)
                if old_name != name_value:
                    logger.log_line(
                        PREFIX_DNS_REPO,
                        "SAVE",
                        "Updated DNS record name from %s to %s (%s)" % (host, name_value, record_type),
                        level="info",
                    )
                else:
                    logger.log_line(
                        PREFIX_DNS_REPO,
                        "SAVE",
                        "Updated DNS record: %s (%s)" % (name_value, record_type),
                        level="debug",
                    )
                existing_record.name = name_value
                new_extra = self._merge_dns_extra_payload(old_extra, incoming_extra, host)
                existing_record.extra_data = new_extra
                update_fields: List[str] = []
                if existing_record.name != old_name:
                    update_fields.append("name")
                if new_extra != old_extra:
                    update_fields.append("extra_data")
                if update_fields:
                    existing_record.save(update_fields=update_fields)
                return existing_record

            merged_extra = self._merge_dns_extra_payload(None, incoming_extra, host)
            dns_record = DNSRecord.objects.create(name=name_value, type=record_type, extra_data=merged_extra)
            domain_info.dns_records.add(dns_record)
            logger.log_line(
                PREFIX_DNS_REPO,
                "SAVE",
                "Created DNS record: %s (%s)" % (name_value, record_type),
                level="info",
            )
            return dns_record

    @staticmethod
    def _strip_secator_scalar_as_host_string(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value.strip()
        return str(value).strip()

    @staticmethod
    def _merge_dns_extra_payload(
        existing: Optional[Dict[str, Any]],
        incoming: Dict[str, Any],
        secator_host: Optional[str],
    ) -> Dict[str, Any]:
        """Merge Secator extra_data with existing JSON.

        Sets ``secator_host`` from the Record ``host`` only when that key is missing or empty
        after merging incoming keys, so a previously stored value is not overwritten. When the
        Record host differs from a non-empty stored ``secator_host``, the stored value is kept
        and an info log records the mismatch for integration debugging.
        """
        base: Dict[str, Any] = coerce_extra_data_field_to_plain_dict(existing)
        for key, val in incoming.items():
            base[key] = val
        if secator_host:
            incoming_host = DnsRepository._strip_secator_scalar_as_host_string(secator_host)
            current = base.get("secator_host")
            stored = ""
            if current is not None and current != "":
                stored = DnsRepository._strip_secator_scalar_as_host_string(current)
            if not stored:
                base["secator_host"] = incoming_host
            elif stored != incoming_host:
                logger.log_line(
                    PREFIX_DNS_REPO,
                    "SAVE",
                    "Keeping existing secator_host; Record host differs from stored. stored=%s incoming=%s"
                    % (stored, incoming_host),
                    level="info",
                )
        return base

    def _update_dns_record_extra_data(self, extra_data: Any, dns_record: DNSRecord) -> None:
        """
        Merge extra_data into an existing DNS record (does not set secator_host — use save_from_secator for full Secator rows).
        """
        if extra_data is None:
            return
        if not isinstance(extra_data, dict):
            preview = bounded_diagnostic_preview(extra_data, use_repr=True)
            logger.log_line(
                PREFIX_DNS_REPO,
                "UPDATE_EXTRA",
                "Ignoring non-dict extra_data for DNSRecord id=%s name=%s rtype=%s raw_type=%s preview=%s"
                % (
                    dns_record.pk,
                    dns_record.name,
                    dns_record.type,
                    type(extra_data).__name__,
                    preview,
                ),
                level="warning",
            )
            return
        merge_extra_data_payload_into_model(dns_record, extra_data)

    def get_or_create(self, name: str, record_type: str, **kwargs) -> Tuple[Optional[DNSRecord], bool]:
        """
        Get or create a DNS record.

        Args:
            name: DNS record name
            record_type: DNS record type
            **kwargs: Additional fields (not used for DNSRecord model)

        Returns:
            tuple: (DNSRecord, created boolean) or (None, False)
        """
        try:
            if not name or not name.strip():
                logger.log_line(
                    PREFIX_DNS_REPO,
                    "GET_OR_CREATE",
                    "DNS record name is empty",
                    level="warning",
                )
                return None, False

            if not record_type or not record_type.strip():
                logger.log_line(
                    PREFIX_DNS_REPO,
                    "GET_OR_CREATE",
                    "DNS record type is empty",
                    level="warning",
                )
                return None, False

            record_type = record_type.upper().strip()
            if record_type not in self.VALID_DNS_TYPES:
                logger.log_line(
                    PREFIX_DNS_REPO,
                    "GET_OR_CREATE",
                    "Invalid DNS record type: %s" % (record_type,),
                    level="warning",
                )
                return None, False

            dns_record, created = DNSRecord.objects.get_or_create(name=name.strip(), type=record_type)

            return dns_record, created

        except Exception as e:
            logger.log_line(
                PREFIX_DNS_REPO,
                "GET_OR_CREATE",
                "Error in get_or_create DNS record: %s" % (e,),
                level="error",
            )
            return None, False

    def bulk_create(self, dns_records: List[Dict[str, str]]) -> List[DNSRecord]:
        """
        Bulk create DNS records.

        Args:
            dns_records: List of DNS record dictionaries with 'name' and 'type' keys

        Returns:
            list: List of created DNSRecord objects
        """
        try:
            record_objects = []
            for record_data in dns_records:
                name = record_data.get("name", "").strip()
                record_type = record_data.get("type", "").upper().strip()

                if name and record_type and record_type in self.VALID_DNS_TYPES:
                    record_objects.append(DNSRecord(name=name, type=record_type))

            if record_objects:
                created = DNSRecord.objects.bulk_create(record_objects, ignore_conflicts=True)
                logger.log_line(
                    PREFIX_DNS_REPO,
                    "BULK_CREATE",
                    "Bulk created %s DNS records" % (len(created),),
                    level="info",
                )
                return created

            return []

        except Exception as e:
            logger.log_line(
                PREFIX_DNS_REPO,
                "BULK_CREATE",
                "Error in bulk create DNS records: %s" % (e,),
                level="error",
            )
            return []

    def get_records_for_domain(self, domain_id: int) -> List[DNSRecord]:
        """
        Get all DNS records associated with a domain.

        Args:
            domain_id: Domain ID

        Returns:
            list: List of DNSRecord objects
        """
        try:
            domain = get_domain_by_id(domain_id)
            if domain is None:
                logger.log_line(
                    PREFIX_DNS_REPO,
                    "GET",
                    "Domain with ID %s not found" % (domain_id,),
                    level="error",
                )
                return []
            if domain.domain_info:
                return list(domain.domain_info.dns_records.all())
            logger.log_line(
                PREFIX_DNS_REPO,
                "GET",
                "No domain info found for domain %s" % (domain.name,),
                level="warning",
            )
            return []

        except Exception as e:
            logger.log_line(
                PREFIX_DNS_REPO,
                "GET",
                "Error getting DNS records for domain: %s" % (e,),
                level="error",
            )
            return []

    def get_records_by_type(self, record_type: str, domain_id: int = None) -> List[DNSRecord]:
        """
        Get DNS records by type, optionally filtered by domain.

        Args:
            record_type: DNS record type
            domain_id: Optional domain ID to filter by

        Returns:
            list: List of DNSRecord objects
        """
        try:
            record_type = record_type.upper().strip()
            if record_type not in self.VALID_DNS_TYPES:
                logger.log_line(
                    PREFIX_DNS_REPO,
                    "GET",
                    "Invalid DNS record type: %s" % (record_type,),
                    level="warning",
                )
                return []

            if domain_id:
                domain = get_domain_by_id(domain_id)
                if domain is None:
                    logger.log_line(
                        PREFIX_DNS_REPO,
                        "GET",
                        "Domain with ID %s not found" % (domain_id,),
                        level="error",
                    )
                    return []
                if domain.domain_info:
                    # Filter DNS records by type that are associated with this domain's domain_info
                    queryset = domain.domain_info.dns_records.filter(type=record_type)
                else:
                    logger.log_line(
                        PREFIX_DNS_REPO,
                        "GET",
                        "No domain info found for domain %s" % (domain.name,),
                        level="warning",
                    )
                    return []
            else:
                queryset = DNSRecord.objects.filter(type=record_type)

            return list(queryset)

        except ObjectDoesNotExist:
            logger.log_line(
                PREFIX_DNS_REPO,
                "GET",
                "Domain with ID %s not found" % (domain_id,),
                level="error",
            )
            return []
        except Exception as e:
            logger.log_line(
                PREFIX_DNS_REPO,
                "GET",
                "Error getting DNS records by type: %s" % (e,),
                level="error",
            )
            return []

    def validate_dns_record_type(self, record_type: str) -> bool:
        """
        Validate DNS record type.

        Args:
            record_type: DNS record type to validate

        Returns:
            bool: True if valid, False otherwise
        """
        return record_type.upper().strip() in self.VALID_DNS_TYPES

    def get_valid_dns_types(self) -> set:
        """
        Get set of valid DNS record types.

        Returns:
            set: Set of valid DNS record types
        """
        return self.VALID_DNS_TYPES.copy()

    def parse_extra_data(self, extra_data: Any) -> Dict[str, Any]:
        """
        Parse extra data from Secator DNS record.

        Args:
            extra_data: Extra payload from Secator (typically a dict; other types yield {})

        Returns:
            dict: Parsed extra data
        """
        try:
            if extra_data is None or extra_data == {}:
                return {}
            if not isinstance(extra_data, dict):
                preview = bounded_diagnostic_preview(extra_data, use_repr=True)
                logger.log_line(
                    PREFIX_DNS_REPO,
                    "PARSE",
                    "Non-dict extra_data in parse_extra_data; returning empty dict. raw_type=%s preview=%s"
                    % (type(extra_data).__name__, preview),
                    level="warning",
                )
                return {}
            parsed_data = {}

            # Common DNS record fields that might be in extra_data
            if "value" in extra_data:
                parsed_data["value"] = extra_data["value"]
            if "ttl" in extra_data:
                parsed_data["ttl"] = extra_data["ttl"]
            if "priority" in extra_data:
                parsed_data["priority"] = extra_data["priority"]
            if "weight" in extra_data:
                parsed_data["weight"] = extra_data["weight"]
            if "port" in extra_data:
                parsed_data["port"] = extra_data["port"]
            if "target" in extra_data:
                parsed_data["target"] = extra_data["target"]

            return parsed_data

        except Exception as e:
            logger.log_line(
                PREFIX_DNS_REPO,
                "PARSE",
                "Error parsing DNS record extra data: %s" % (e,),
                level="error",
            )
            return {}
