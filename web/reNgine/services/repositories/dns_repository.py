"""
DNS Repository - Data access for DNS record operations.
Handles DNSRecord database operations from Secator Record type.
"""

from typing import Any, Dict, List, Optional, Tuple

from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError, transaction

from reNgine.utilities.logger import get_module_logger
from targetApp.models import DNSRecord, Domain, DomainInfo


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
        domain_id: int,
        rengine_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[DNSRecord]:
        """
        Save DNS record from Secator result (Secator Record format: name, type, host).

        Args:
            item: Secator record item
            scan_history_id: ID of the scan history
            domain_id: ID of the domain
            rengine_context: Optional context (unused for DNS records)

        Returns:
            DNSRecord: Saved DNS record object or None
        """
        try:
            return self._process_secator_dns_record_item(item, domain_id)
        except ObjectDoesNotExist as e:
            logger.error(f"Object not found when saving DNS record: {e}")
            return None
        except IntegrityError as e:
            logger.error(f"Integrity error saving DNS record: {e}")
            return None
        except Exception as e:
            logger.error(f"Error saving DNS record from Secator: {e}")
            return None

    def _process_secator_dns_record_item(self, item: Dict[str, Any], domain_id: int) -> Optional[DNSRecord]:
        record_name = item.get("name")
        record_type = (item.get("type") or "").upper()
        host = item.get("host")

        if not record_name:
            logger.warning("DNS record item missing name field")
            return None

        if not record_type:
            logger.warning("DNS record item missing type field")
            return None

        if not host:
            logger.warning("DNS record item missing host/value field")
            return None

        # Validate DNS record type
        if record_type not in self.VALID_DNS_TYPES:
            logger.warning(f"Invalid DNS record type: {record_type}, skipping")
            return None

        # Extract data from item
        name_value = record_name
        extra_data = item.get("extra_data", {}) or {}

        # Get or create domain info and DNS record atomically to prevent race conditions.
        # select_for_update locks the domain row until the transaction commits.
        with transaction.atomic():
            domain = Domain.objects.select_for_update().get(id=domain_id)
            domain_info = domain.domain_info if hasattr(domain, "domain_info") and domain.domain_info else None
            if not domain_info:
                domain_info = DomainInfo()
                domain_info.save()
                domain.domain_info = domain_info
                domain.save()
                logger.debug(f"Created domain info for domain {domain.name}")

            if existing_record := (
                domain_info.dns_records.filter(type=record_type, name=name_value).first()
                or domain_info.dns_records.filter(type=record_type, name=host).first()
            ):
                if existing_record.name != name_value:
                    existing_record.name = name_value
                    logger.info(f"Updated DNS record name from {host} to {name_value} ({record_type})")
                else:
                    logger.debug(f"Updated DNS record: {name_value} ({record_type})")
                self._update_dns_record_extra_data(extra_data, existing_record)
                return existing_record

            dns_record = DNSRecord.objects.create(name=name_value, type=record_type, extra_data=extra_data)
            domain_info.dns_records.add(dns_record)
            logger.info(f"Created DNS record: {name_value} ({record_type})")
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
                logger.warning("DNS record name is empty")
                return None, False

            if not record_type or not record_type.strip():
                logger.warning("DNS record type is empty")
                return None, False

            record_type = record_type.upper().strip()
            if record_type not in self.VALID_DNS_TYPES:
                logger.warning(f"Invalid DNS record type: {record_type}")
                return None, False

            dns_record, created = DNSRecord.objects.get_or_create(name=name.strip(), type=record_type)

            return dns_record, created

        except Exception as e:
            logger.error(f"Error in get_or_create DNS record: {e}")
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
                logger.info(f"Bulk created {len(created)} DNS records")
                return created

            return []

        except Exception as e:
            logger.error(f"Error in bulk create DNS records: {e}")
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
            domain = Domain.objects.get(id=domain_id)
            if domain.domain_info:
                return list(domain.domain_info.dns_records.all())
            logger.warning(f"No domain info found for domain {domain.name}")
            return []

        except ObjectDoesNotExist:
            logger.error(f"Domain with ID {domain_id} not found")
            return []
        except Exception as e:
            logger.error(f"Error getting DNS records for domain: {e}")
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
                logger.warning(f"Invalid DNS record type: {record_type}")
                return []

            if domain_id:
                domain = Domain.objects.get(id=domain_id)
                if domain.domain_info:
                    # Filter DNS records by type that are associated with this domain's domain_info
                    queryset = domain.domain_info.dns_records.filter(type=record_type)
                else:
                    logger.warning(f"No domain info found for domain {domain.name}")
                    return []
            else:
                queryset = DNSRecord.objects.filter(type=record_type)

            return list(queryset)

        except ObjectDoesNotExist:
            logger.error(f"Domain with ID {domain_id} not found")
            return []
        except Exception as e:
            logger.error(f"Error getting DNS records by type: {e}")
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
            logger.error(f"Error parsing DNS record extra data: {e}")
            return {}
