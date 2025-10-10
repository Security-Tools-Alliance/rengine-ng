"""
Distributed database operations utilities.

This module provides distributed database operation capabilities that can be
reused across different task types while following SOLID, KISS, and DRY principles.

Key components:
1. DistributedDatabaseProcessor - Base class for distributed database operations
2. DistributedEndpointProcessor - Endpoint operations with distributed support
3. DistributedSubdomainProcessor - Subdomain operations with distributed support
4. DistributedIPProcessor - IP address operations with distributed support
5. DistributedVulnerabilityProcessor - Vulnerability operations with distributed support
"""

import threading
import time
from typing import Any, Dict, List, Optional

from celery.utils.log import get_task_logger
from django.utils import timezone

from reNgine.utilities.core.validation import is_valid_ipv4, is_valid_ipv6
from reNgine.utilities.database_interface import DatabaseInterface, DatabaseRecord, QueryFilter
from reNgine.utilities.distributed.base import (
    DistributedConfig,
    DistributedDatabaseProcessor,
    DistributedResult,
    ProcessingStatus,
    aggregate_distributed_results,
    create_batch_tasks,
    create_distributed_config,
    validate_distributed_input,
)
from reNgine.utilities.url import get_domain_from_subdomain, sanitize_url


logger = get_task_logger(__name__)

# Thread-local storage for IP collection
_thread_local = threading.local()


class DistributedDatabaseResult(DistributedResult[Dict[str, Any]]):
    """Result container for distributed database operations"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.objects_created: List[Any] = []
        self.objects_updated: List[Any] = []
        self.objects_skipped: List[Any] = []
        self.db_operations: List[str] = []

    def add_created_object(self, obj: Any) -> None:
        """Add a created object to the result"""
        self.objects_created.append(obj)

    def add_updated_object(self, obj: Any) -> None:
        """Add an updated object to the result"""
        self.objects_updated.append(obj)

    def add_skipped_object(self, obj: Any) -> None:
        """Add a skipped object to the result"""
        self.objects_skipped.append(obj)

    def add_db_operation(self, operation: str) -> None:
        """Add a database operation to the result"""
        self.db_operations.append(operation)

    def get_queue_name(self) -> str:
        """Get the queue name for this processor."""
        return getattr(self, "queue_name", "default_queue")

    def get_task_name(self) -> str:
        """Get the task name for this processor."""
        return f"{self.__class__.__name__.lower()}_batch"

    def process_batch(self, batch: List[Any], batch_id: str, **kwargs) -> "DistributedResult":
        """Process a batch of database operations."""
        # This is a placeholder implementation
        # Subclasses should override this method
        from .base import DistributedResult, ProcessingStatus

        return DistributedResult(
            data=batch,
            status=ProcessingStatus.COMPLETED,
            processing_time=0.0,
            errors=[],
            metadata={"batch_id": batch_id},
        )


class DistributedEndpointProcessor(DistributedDatabaseProcessor):
    """Distributed processor for endpoint operations"""

    def __init__(self, config: Optional[DistributedConfig] = None, db_interface: Optional[DatabaseInterface] = None):
        super().__init__(config)
        self.db_interface = db_interface
        self.endpoint_cache: Dict[str, DatabaseRecord] = {}
        self.subdomain_cache: Dict[str, DatabaseRecord] = {}

    def get_task_name(self) -> str:
        return "distributed_endpoint_processor"

    def process_endpoints_batch(
        self, endpoints_data: List[Dict[str, Any]], batch_id: str, ctx: Optional[Dict[str, Any]] = None, **kwargs
    ) -> DistributedDatabaseResult:
        """Process a batch of endpoints"""
        start_time = time.time()
        self.log_processing_start(batch_id, len(endpoints_data))

        result = DistributedDatabaseResult(data={}, status=ProcessingStatus.IN_PROGRESS, batch_id=batch_id)

        try:
            with self.safe_execution():
                created_endpoints = []
                updated_endpoints = []
                skipped_endpoints = []
                errors = []

                for endpoint_data in endpoints_data:
                    try:
                        endpoint_result = self._process_single_endpoint(endpoint_data, ctx=ctx, **kwargs)

                        if endpoint_result["created"]:
                            created_endpoints.append(endpoint_result["endpoint"])
                            result.add_created_object(endpoint_result["endpoint"])
                        elif endpoint_result["updated"]:
                            updated_endpoints.append(endpoint_result["endpoint"])
                            result.add_updated_object(endpoint_result["endpoint"])
                        else:
                            skipped_endpoints.append(endpoint_result["endpoint"])
                            result.add_skipped_object(endpoint_result["endpoint"])

                        self.record_db_operation(
                            batch_id, f"Processed endpoint: {endpoint_data.get('http_url', 'unknown')}"
                        )

                    except Exception as e:
                        error_msg = f"Error processing endpoint {endpoint_data.get('http_url', 'unknown')}: {str(e)}"
                        errors.append(error_msg)
                        logger.error(error_msg)

                # Update result
                result.data = {
                    "created_count": len(created_endpoints),
                    "updated_count": len(updated_endpoints),
                    "skipped_count": len(skipped_endpoints),
                    "total_processed": len(endpoints_data),
                }

                result.errors = errors
                result.status = ProcessingStatus.COMPLETED if not errors else ProcessingStatus.FAILED
                result.processing_time = time.time() - start_time

        except Exception as e:
            result.status = ProcessingStatus.FAILED
            result.errors = [str(e)]
            result.processing_time = time.time() - start_time
            logger.error(f"Batch endpoint processing failed for {batch_id}: {e}")

        self.log_processing_completion(batch_id, result.is_successful, result.processing_time)
        return result

    def _process_single_endpoint(
        self, endpoint_data: Dict[str, Any], ctx: Optional[Dict[str, Any]] = None, **kwargs
    ) -> Dict[str, Any]:
        """Process a single endpoint"""
        http_url = endpoint_data.get("http_url")
        if not http_url:
            raise ValueError("http_url is required")

        # Sanitize URL
        http_url = sanitize_url(http_url)

        # Get or create subdomain
        subdomain_name = get_domain_from_subdomain(http_url)
        subdomain = self._get_or_create_subdomain(subdomain_name, ctx)

        if not subdomain:
            raise ValueError(f"Could not create subdomain for {subdomain_name}")

        # Check if endpoint already exists
        if not self.db_interface:
            raise ValueError("Database interface not provided")

        filters = [
            QueryFilter("http_url", "exact", http_url),
            QueryFilter("scan_history_id", "exact", ctx.get("scan_history_id") if ctx else None),
        ]
        existing_endpoints = self.db_interface.filter_records("endpoint", filters)
        existing_endpoint = existing_endpoints[0] if existing_endpoints else None

        if existing_endpoint:
            # Update existing endpoint
            updated = self._update_endpoint(existing_endpoint, endpoint_data)
            return {"endpoint": existing_endpoint, "created": False, "updated": updated, "skipped": not updated}
        else:
            # Create new endpoint
            new_endpoint = self._create_endpoint(endpoint_data, subdomain, ctx)
            return {"endpoint": new_endpoint, "created": True, "updated": False, "skipped": False}

    def _get_or_create_subdomain(
        self, subdomain_name: str, ctx: Optional[Dict[str, Any]] = None
    ) -> Optional[DatabaseRecord]:
        """Get or create subdomain with caching"""
        if subdomain_name in self.subdomain_cache:
            return self.subdomain_cache[subdomain_name]

        if not self.db_interface:
            logger.error("Database interface not provided")
            return None

        try:
            # Check if subdomain exists
            filters = [
                QueryFilter("name", "exact", subdomain_name),
                QueryFilter("target_domain_id", "exact", ctx.get("domain_id") if ctx else None),
                QueryFilter("scan_history_id", "exact", ctx.get("scan_history_id") if ctx else None),
            ]
            existing_subdomains = self.db_interface.filter_records("subdomain", filters)

            if existing_subdomains:
                subdomain = existing_subdomains[0]
            else:
                # Create new subdomain
                subdomain_data = {
                    "name": subdomain_name,
                    "target_domain_id": ctx.get("domain_id") if ctx else None,
                    "scan_history_id": ctx.get("scan_history_id") if ctx else None,
                    "is_important": False,
                    "is_archived": False,
                    "discovered_date": timezone.now().isoformat(),
                }
                subdomain = self.db_interface.create_record("subdomain", subdomain_data)

            self.subdomain_cache[subdomain_name] = subdomain
            return subdomain

        except Exception as e:
            logger.error(f"Error creating subdomain {subdomain_name}: {e}")
            return None

    def _create_endpoint(
        self, endpoint_data: Dict[str, Any], subdomain: DatabaseRecord, ctx: Optional[Dict[str, Any]] = None
    ) -> DatabaseRecord:
        """Create a new endpoint"""
        if not self.db_interface:
            raise ValueError("Database interface not provided")

        endpoint_data_clean = {
            "http_url": endpoint_data.get("http_url"),
            "http_status": endpoint_data.get("http_status", 0),
            "page_title": endpoint_data.get("page_title", ""),
            "content_length": endpoint_data.get("content_length", 0),
            "content_type": endpoint_data.get("content_type", ""),
            "webserver": endpoint_data.get("webserver", ""),
            "response_time": endpoint_data.get("response_time", -1),
            "subdomain_id": subdomain.id if subdomain else None,
            "scan_history_id": ctx.get("scan_history_id") if ctx else None,
            "is_default": endpoint_data.get("is_default", False),
            "discovered_date": timezone.now().isoformat(),
        }

        endpoint = self.db_interface.create_record("endpoint", endpoint_data_clean)

        # Add technologies if provided
        technologies = endpoint_data.get("technologies", [])
        if technologies and endpoint:
            for tech_name in technologies:
                if tech_name:
                    # Create technology record
                    tech_data = {"name": tech_name}
                    self.db_interface.create_record("technology", tech_data)
                    # Note: The relationship would be handled by the database interface implementation

        return endpoint

    def _update_endpoint(self, endpoint: DatabaseRecord, endpoint_data: Dict[str, Any]) -> bool:
        """Update an existing endpoint"""
        if not self.db_interface or not endpoint:
            return False

        updated = False
        update_data = {}

        # Check fields that need updating
        if "http_status" in endpoint_data and endpoint_data["http_status"] != endpoint.data.get("http_status"):
            update_data["http_status"] = endpoint_data["http_status"]
            updated = True

        if "page_title" in endpoint_data and endpoint_data["page_title"] != endpoint.data.get("page_title"):
            update_data["page_title"] = endpoint_data["page_title"]
            updated = True

        if "content_length" in endpoint_data and endpoint_data["content_length"] != endpoint.data.get("content_length"):
            update_data["content_length"] = endpoint_data["content_length"]
            updated = True

        if "content_type" in endpoint_data and endpoint_data["content_type"] != endpoint.data.get("content_type"):
            update_data["content_type"] = endpoint_data["content_type"]
            updated = True

        if "webserver" in endpoint_data and endpoint_data["webserver"] != endpoint.data.get("webserver"):
            update_data["webserver"] = endpoint_data["webserver"]
            updated = True

        if "response_time" in endpoint_data and endpoint_data["response_time"] != endpoint.data.get("response_time"):
            update_data["response_time"] = endpoint_data["response_time"]
            updated = True

        if updated:
            self.db_interface.update_record("endpoint", endpoint.id, update_data)

        # Update technologies
        technologies = endpoint_data.get("technologies", [])
        if technologies:
            for tech_name in technologies:
                if tech_name:
                    # Create technology record
                    tech_data = {"name": tech_name}
                    self.db_interface.create_record("technology", tech_data)
                    # Note: The relationship would be handled by the database interface implementation
            updated = True

        return updated


class DistributedSubdomainProcessor(DistributedDatabaseProcessor):
    """Distributed processor for subdomain operations"""

    def __init__(self, config: Optional[DistributedConfig] = None, db_interface: Optional[DatabaseInterface] = None):
        super().__init__(config)
        self.db_interface = db_interface
        self.domain_cache: Dict[int, DatabaseRecord] = {}

    def get_task_name(self) -> str:
        return "distributed_subdomain_processor"

    def process_subdomains_batch(
        self, subdomains_data: List[Dict[str, Any]], batch_id: str, ctx: Optional[Dict[str, Any]] = None, **kwargs
    ) -> DistributedDatabaseResult:
        """Process a batch of subdomains"""
        start_time = time.time()
        self.log_processing_start(batch_id, len(subdomains_data))

        result = DistributedDatabaseResult(data={}, status=ProcessingStatus.IN_PROGRESS, batch_id=batch_id)

        try:
            with self.safe_execution():
                created_subdomains = []
                updated_subdomains = []
                skipped_subdomains = []
                errors = []

                for subdomain_data in subdomains_data:
                    try:
                        subdomain_result = self._process_single_subdomain(subdomain_data, ctx=ctx, **kwargs)

                        if subdomain_result["created"]:
                            created_subdomains.append(subdomain_result["subdomain"])
                            result.add_created_object(subdomain_result["subdomain"])
                        elif subdomain_result["updated"]:
                            updated_subdomains.append(subdomain_result["subdomain"])
                            result.add_updated_object(subdomain_result["subdomain"])
                        else:
                            skipped_subdomains.append(subdomain_result["subdomain"])
                            result.add_skipped_object(subdomain_result["subdomain"])

                        self.record_db_operation(
                            batch_id, f"Processed subdomain: {subdomain_data.get('name', 'unknown')}"
                        )

                    except Exception as e:
                        error_msg = f"Error processing subdomain {subdomain_data.get('name', 'unknown')}: {str(e)}"
                        errors.append(error_msg)
                        logger.error(error_msg)

                # Update result
                result.data = {
                    "created_count": len(created_subdomains),
                    "updated_count": len(updated_subdomains),
                    "skipped_count": len(skipped_subdomains),
                    "total_processed": len(subdomains_data),
                }

                result.errors = errors
                result.status = ProcessingStatus.COMPLETED if not errors else ProcessingStatus.FAILED
                result.processing_time = time.time() - start_time

        except Exception as e:
            result.status = ProcessingStatus.FAILED
            result.errors = [str(e)]
            result.processing_time = time.time() - start_time
            logger.error(f"Batch subdomain processing failed for {batch_id}: {e}")

        self.log_processing_completion(batch_id, result.is_successful, result.processing_time)
        return result

    def _process_single_subdomain(
        self, subdomain_data: Dict[str, Any], ctx: Optional[Dict[str, Any]] = None, **kwargs
    ) -> Dict[str, Any]:
        """Process a single subdomain"""
        subdomain_name = subdomain_data.get("name")
        if not subdomain_name:
            raise ValueError("subdomain name is required")

        # Check if subdomain already exists
        if not self.db_interface:
            raise ValueError("Database interface not provided")

        filters = [
            QueryFilter("name", "exact", subdomain_name),
            QueryFilter("target_domain_id", "exact", ctx.get("domain_id") if ctx else None),
            QueryFilter("scan_history_id", "exact", ctx.get("scan_history_id") if ctx else None),
        ]
        existing_subdomains = self.db_interface.filter_records("subdomain", filters)
        existing_subdomain = existing_subdomains[0] if existing_subdomains else None

        if existing_subdomain:
            # Update existing subdomain
            updated = self._update_subdomain(existing_subdomain, subdomain_data)
            return {"subdomain": existing_subdomain, "created": False, "updated": updated, "skipped": not updated}
        else:
            # Create new subdomain
            new_subdomain = self._create_subdomain(subdomain_data, ctx)
            return {"subdomain": new_subdomain, "created": True, "updated": False, "skipped": False}

    def _create_subdomain(self, subdomain_data: Dict[str, Any], ctx: Optional[Dict[str, Any]] = None) -> DatabaseRecord:
        """Create a new subdomain"""
        if not self.db_interface:
            raise ValueError("Database interface not provided")

        subdomain_data_clean = {
            "name": subdomain_data.get("name"),
            "target_domain_id": ctx.get("domain_id") if ctx else None,
            "scan_history_id": ctx.get("scan_history_id") if ctx else None,
            "is_important": subdomain_data.get("is_important", False),
            "is_archived": subdomain_data.get("is_archived", False),
            "discovered_date": timezone.now().isoformat(),
        }

        return self.db_interface.create_record("subdomain", subdomain_data_clean)

    def _update_subdomain(self, subdomain: DatabaseRecord, subdomain_data: Dict[str, Any]) -> bool:
        """Update an existing subdomain"""
        if not self.db_interface or not subdomain:
            return False

        updated = False
        update_data = {}

        # Update fields if they have new values
        if "is_important" in subdomain_data and subdomain_data["is_important"] != subdomain.data.get("is_important"):
            update_data["is_important"] = subdomain_data["is_important"]
            updated = True

        if "is_archived" in subdomain_data and subdomain_data["is_archived"] != subdomain.data.get("is_archived"):
            update_data["is_archived"] = subdomain_data["is_archived"]
            updated = True

        if updated:
            self.db_interface.update_record("subdomain", subdomain.id, update_data)

        return updated


class DistributedIPProcessor(DistributedDatabaseProcessor):
    """Distributed processor for IP address operations"""

    def __init__(self, config: Optional[DistributedConfig] = None, db_interface: Optional[DatabaseInterface] = None):
        super().__init__(config)
        self.db_interface = db_interface
        self.ip_cache: Dict[str, DatabaseRecord] = {}

    def get_task_name(self) -> str:
        return "distributed_ip_processor"

    def process_ips_batch(
        self, ips_data: List[Dict[str, Any]], batch_id: str, ctx: Optional[Dict[str, Any]] = None, **kwargs
    ) -> DistributedDatabaseResult:
        """Process a batch of IP addresses"""
        start_time = time.time()
        self.log_processing_start(batch_id, len(ips_data))

        result = DistributedDatabaseResult(data={}, status=ProcessingStatus.IN_PROGRESS, batch_id=batch_id)

        try:
            with self.safe_execution():
                created_ips = []
                updated_ips = []
                skipped_ips = []
                errors = []

                for ip_data in ips_data:
                    try:
                        ip_result = self._process_single_ip(ip_data, ctx=ctx, **kwargs)

                        if ip_result["created"]:
                            created_ips.append(ip_result["ip"])
                            result.add_created_object(ip_result["ip"])
                        elif ip_result["updated"]:
                            updated_ips.append(ip_result["ip"])
                            result.add_updated_object(ip_result["ip"])
                        else:
                            skipped_ips.append(ip_result["ip"])
                            result.add_skipped_object(ip_result["ip"])

                        self.record_db_operation(batch_id, f"Processed IP: {ip_data.get('address', 'unknown')}")

                    except Exception as e:
                        error_msg = f"Error processing IP {ip_data.get('address', 'unknown')}: {str(e)}"
                        errors.append(error_msg)
                        logger.error(error_msg)

                # Update result
                result.data = {
                    "created_count": len(created_ips),
                    "updated_count": len(updated_ips),
                    "skipped_count": len(skipped_ips),
                    "total_processed": len(ips_data),
                }

                result.errors = errors
                result.status = ProcessingStatus.COMPLETED if not errors else ProcessingStatus.FAILED
                result.processing_time = time.time() - start_time

        except Exception as e:
            result.status = ProcessingStatus.FAILED
            result.errors = [str(e)]
            result.processing_time = time.time() - start_time
            logger.error(f"Batch IP processing failed for {batch_id}: {e}")

        self.log_processing_completion(batch_id, result.is_successful, result.processing_time)
        return result

    def _process_single_ip(
        self, ip_data: Dict[str, Any], ctx: Optional[Dict[str, Any]] = None, **kwargs
    ) -> Dict[str, Any]:
        """Process a single IP address"""
        ip_address = ip_data.get("address")
        if not ip_address:
            raise ValueError("IP address is required")

        # Validate IP address
        if not is_valid_ipv4(ip_address) and not is_valid_ipv6(ip_address):
            raise ValueError(f"Invalid IP address: {ip_address}")

        # Check if IP already exists
        if not self.db_interface:
            raise ValueError("Database interface not provided")

        filters = [
            QueryFilter("address", "exact", ip_address),
            QueryFilter("scan_history_id", "exact", ctx.get("scan_history_id") if ctx else None),
        ]
        existing_ips = self.db_interface.filter_records("ip_address", filters)
        existing_ip = existing_ips[0] if existing_ips else None

        if existing_ip:
            # Update existing IP
            updated = self._update_ip(existing_ip, ip_data)
            return {"ip": existing_ip, "created": False, "updated": updated, "skipped": not updated}
        else:
            # Create new IP
            new_ip = self._create_ip(ip_data, ctx)
            return {"ip": new_ip, "created": True, "updated": False, "skipped": False}

    def _create_ip(self, ip_data: Dict[str, Any], ctx: Optional[Dict[str, Any]] = None) -> DatabaseRecord:
        """Create a new IP address"""
        if not self.db_interface:
            raise ValueError("Database interface not provided")

        ip_data_clean = {
            "address": ip_data.get("address"),
            "scan_history_id": ctx.get("scan_history_id") if ctx else None,
            "is_cdn": ip_data.get("is_cdn", False),
            "is_private": ip_data.get("is_private", False),
            "discovered_date": timezone.now().isoformat(),
        }

        return self.db_interface.create_record("ip_address", ip_data_clean)

    def _update_ip(self, ip: DatabaseRecord, ip_data: Dict[str, Any]) -> bool:
        """Update an existing IP address"""
        if not self.db_interface or not ip:
            return False

        updated = False
        update_data = {}

        # Update fields if they have new values
        if "is_cdn" in ip_data and ip_data["is_cdn"] != ip.data.get("is_cdn"):
            update_data["is_cdn"] = ip_data["is_cdn"]
            updated = True

        if "is_private" in ip_data and ip_data["is_private"] != ip.data.get("is_private"):
            update_data["is_private"] = ip_data["is_private"]
            updated = True

        if updated:
            self.db_interface.update_record("ip_address", ip.id, update_data)

        return updated


# Utility functions for distributed database operations


def create_distributed_endpoint_processor(
    batch_size: int = 15, worker_timeout: int = 300, db_interface: Optional[DatabaseInterface] = None, **kwargs
) -> DistributedEndpointProcessor:
    """Create a distributed endpoint processor with common defaults"""
    config = create_distributed_config(batch_size=batch_size, worker_timeout=worker_timeout, **kwargs)
    return DistributedEndpointProcessor(config, db_interface)


def create_distributed_subdomain_processor(
    batch_size: int = 15, worker_timeout: int = 300, db_interface: Optional[DatabaseInterface] = None, **kwargs
) -> DistributedSubdomainProcessor:
    """Create a distributed subdomain processor with common defaults"""
    config = create_distributed_config(batch_size=batch_size, worker_timeout=worker_timeout, **kwargs)
    return DistributedSubdomainProcessor(config, db_interface)


def create_distributed_ip_processor(
    batch_size: int = 15, worker_timeout: int = 300, db_interface: Optional[DatabaseInterface] = None, **kwargs
) -> DistributedIPProcessor:
    """Create a distributed IP processor with common defaults"""
    config = create_distributed_config(batch_size=batch_size, worker_timeout=worker_timeout, **kwargs)
    return DistributedIPProcessor(config, db_interface)


def process_endpoints_distributed(
    endpoints_data: List[Dict[str, Any]],
    processor: Optional[DistributedEndpointProcessor] = None,
    ctx: Optional[Dict[str, Any]] = None,
    db_interface: Optional[DatabaseInterface] = None,
    **kwargs,
) -> Dict[str, Any]:
    """Process endpoints in a distributed manner"""
    if not validate_distributed_input(endpoints_data):
        return {"success": False, "error": "Invalid input"}

    if processor is None:
        processor = create_distributed_endpoint_processor(db_interface=db_interface)

    # Create batch tasks
    batch_tasks = create_batch_tasks(
        endpoints_data, processor.process_endpoints_batch, processor.config.batch_size, ctx=ctx, **kwargs
    )

    if not batch_tasks:
        return {"success": False, "error": "No batch tasks created"}

    # Execute batches in parallel
    try:
        from reNgine.utilities.deadlock_prevention import safe_group_execution

        results = safe_group_execution(batch_tasks, processor.config.worker_timeout * len(batch_tasks))

        # Aggregate results
        return aggregate_distributed_results(results)
    except Exception as e:
        logger.error(f"Distributed endpoint processing failed: {e}")
        return {"success": False, "error": str(e)}


def process_subdomains_distributed(
    subdomains_data: List[Dict[str, Any]],
    processor: Optional[DistributedSubdomainProcessor] = None,
    ctx: Optional[Dict[str, Any]] = None,
    db_interface: Optional[DatabaseInterface] = None,
    **kwargs,
) -> Dict[str, Any]:
    """Process subdomains in a distributed manner"""
    if not validate_distributed_input(subdomains_data):
        return {"success": False, "error": "Invalid input"}

    if processor is None:
        processor = create_distributed_subdomain_processor(db_interface=db_interface)

    # Create batch tasks
    batch_tasks = create_batch_tasks(
        subdomains_data, processor.process_subdomains_batch, processor.config.batch_size, ctx=ctx, **kwargs
    )

    if not batch_tasks:
        return {"success": False, "error": "No batch tasks created"}

    # Execute batches in parallel
    try:
        from reNgine.utilities.deadlock_prevention import safe_group_execution

        results = safe_group_execution(batch_tasks, processor.config.worker_timeout * len(batch_tasks))

        # Aggregate results
        return aggregate_distributed_results(results)
    except Exception as e:
        logger.error(f"Distributed subdomain processing failed: {e}")
        return {"success": False, "error": str(e)}


def process_ips_distributed(
    ips_data: List[Dict[str, Any]],
    processor: Optional[DistributedIPProcessor] = None,
    ctx: Optional[Dict[str, Any]] = None,
    db_interface: Optional[DatabaseInterface] = None,
    **kwargs,
) -> Dict[str, Any]:
    """Process IP addresses in a distributed manner"""
    if not validate_distributed_input(ips_data):
        return {"success": False, "error": "Invalid input"}

    if processor is None:
        processor = create_distributed_ip_processor(db_interface=db_interface)

    # Create batch tasks
    batch_tasks = create_batch_tasks(
        ips_data, processor.process_ips_batch, processor.config.batch_size, ctx=ctx, **kwargs
    )

    if not batch_tasks:
        return {"success": False, "error": "No batch tasks created"}

    # Execute batches in parallel
    try:
        from reNgine.utilities.deadlock_prevention import safe_group_execution

        results = safe_group_execution(batch_tasks, processor.config.worker_timeout * len(batch_tasks))

        # Aggregate results
        return aggregate_distributed_results(results)
    except Exception as e:
        logger.error(f"Distributed IP processing failed: {e}")
        return {"success": False, "error": str(e)}
