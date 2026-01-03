"""
DNS Repository - Data access for DNS record operations.
Handles DNSRecord database operations from Secator Record type.
"""

from typing import Any, Dict, List, Optional, Tuple

from celery.utils.log import get_task_logger
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError

from targetApp.models import DNSRecord, Domain, DomainInfo


logger = get_task_logger(__name__)


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
    }

    def save_from_secator(self, item: Dict[str, Any], scan_history_id: int, domain_id: int) -> Optional[DNSRecord]:
        """
        Save DNS record from Secator result.

        Args:
            item: Secator record item
            scan_history_id: ID of the scan history
            domain_id: ID of the domain

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
        record_type = item.get("type", "").upper()
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
            logger.warning(f"Invalid DNS record type: {record_type}, using INVALID")
            record_type = "INVALID"

        domain = Domain.objects.get(id=domain_id)

        # Get or create DNS record
        dns_record, created = DNSRecord.objects.get_or_create(name=record_name, type=record_type, defaults={})

        if created:
            logger.info(f"Created DNS record: {record_name} ({record_type})")
        else:
            logger.debug(f"DNS record already exists: {record_name} ({record_type})")

        # Associate with domain info if available
        self._associate_with_domain_info(dns_record, domain, host, item)

        return dns_record

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
            if domain_info := DomainInfo.objects.filter(domain=domain).first():
                return list(domain_info.dns_records.all())
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

            queryset = DNSRecord.objects.filter(type=record_type)

            if domain_id:
                domain = Domain.objects.get(id=domain_id)
                if domain_info := DomainInfo.objects.filter(domain=domain).first():
                    queryset = queryset.filter(domaininfo=domain_info)
                else:
                    logger.warning(f"No domain info found for domain {domain.name}")
                    return []

            return list(queryset)

        except ObjectDoesNotExist:
            logger.error(f"Domain with ID {domain_id} not found")
            return []
        except Exception as e:
            logger.error(f"Error getting DNS records by type: {e}")
            return []

    def _associate_with_domain_info(
        self, dns_record: DNSRecord, domain: Domain, host: str = None, item: Dict[str, Any] = None
    ) -> None:
        """
        Associate DNS record with domain info.

        Args:
            dns_record: DNS record object
            domain: Domain object
            host: Optional host information
            item: Optional Secator item with extra_data
        """
        try:
            # Get or create domain info
            domain_info, created = DomainInfo.objects.get_or_create(domain=domain)

            if created:
                logger.debug(f"Created domain info for domain {domain.name}")

            # Store extra_data from Secator item in DomainInfo
            if item and "extra_data" in item:
                self._store_extra_data_in_domain_info(domain_info, dns_record, item)
            # Associate DNS record with domain info
            domain_info.dns_records.add(dns_record)
            logger.debug(f"Associated DNS record {dns_record.name} ({dns_record.type}) with domain {domain.name}")

        except Exception as e:
            logger.error(f"Error associating DNS record with domain info: {e}")

    def _store_extra_data_in_domain_info(
        self, domain_info: DomainInfo, dns_record: DNSRecord, item: Dict[str, Any]
    ) -> None:
        if domain_info.extra_data is None:
            domain_info.extra_data = {}
        # Merge extra_data, using record name and type as key
        record_key = f"{dns_record.name}_{dns_record.type}"
        if record_key not in domain_info.extra_data:
            domain_info.extra_data[record_key] = {}
        domain_info.extra_data[record_key].update(item["extra_data"])
        domain_info.save(update_fields=["extra_data"])
        logger.debug(f"Stored extra_data for DNS record {dns_record.name} ({dns_record.type}) in domain info")

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
