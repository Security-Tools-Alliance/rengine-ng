"""
DNS Repository - Data access for DNS record operations.
Handles DNSRecord database operations from Secator Record type.
"""

from typing import Any, Dict, List, Optional, Tuple

from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError, transaction

from reNgine.core.validators import is_valid_domain
from reNgine.utilities.domain import get_domain_by_id, get_or_create_domain_for_target
from reNgine.utilities.logger import get_module_logger
from startScan.models import DNSRecord, Domain, DomainInfo
from targetApp.models import Target


PREFIX_DNS_REPO = "[DNS_REPO]"
logger = get_module_logger(__name__)


class DnsRepository:
    """Repository for DNS record-related database operations."""

    # Valid DNS record types
    VALID_DNS_TYPES = {
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "TXT",
        "NS",
        "SOA",
        "PTR",
        "SRV",
        "CAA",
        "DS",
        "DNSKEY",
        "NSEC",
        "NSEC3",
        "AXFR",  # Zone transfer - security finding
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
        except Exception as e:
            logger.log_line(
                PREFIX_DNS_REPO,
                "SAVE",
                "Error saving DNS record from Secator: %s" % (e,),
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
        if not domain and is_valid_domain(record_name):
            domain = get_or_create_domain_for_target(scan_history_id, record_name)
        if not domain:
            logger.log_line(
                PREFIX_DNS_REPO,
                "SAVE",
                "Could not resolve domain for target_id=%s, record name=%s" % (target_id, record_name),
                level="warning",
            )
            return None

        # Extract data from item
        name_value = record_name
        extra_data = item.get("extra_data", {}) or {}

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
                if existing_record.name != name_value:
                    existing_record.name = name_value
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
                self._update_dns_record_extra_data(extra_data, existing_record)
                return existing_record

            dns_record = DNSRecord.objects.create(name=name_value, type=record_type, extra_data=extra_data)
            domain_info.dns_records.add(dns_record)
            logger.log_line(
                PREFIX_DNS_REPO,
                "SAVE",
                "Created DNS record: %s (%s)" % (name_value, record_type),
                level="info",
            )
            return dns_record

    def _update_dns_record_extra_data(self, extra_data: Dict[str, Any], dns_record: DNSRecord) -> None:
        """
        Update extra data for an existing DNS record.

        Args:
            extra_data: Extra data dictionary to update
            dns_record: DNS record to update
        """
        dns_record.extra_data = extra_data
        dns_record.save()

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

    def parse_extra_data(self, extra_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse extra data from Secator DNS record.

        Args:
            extra_data: Extra data dictionary

        Returns:
            dict: Parsed extra data
        """
        try:
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
