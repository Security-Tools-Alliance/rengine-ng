"""
Database interface abstraction layer.

This module provides abstract interfaces for database operations without
direct Django dependencies. This allows utilities to work with any
database implementation while maintaining separation of concerns.

Key principles:
1. No direct Django imports
2. Abstract interfaces only
3. Dependency injection pattern
4. Testable and mockable
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class DatabaseRecord:
    """Generic database record representation"""

    id: Optional[int] = None
    data: Dict[str, Any] = None

    def __post_init__(self):
        if self.data is None:
            self.data = {}


@dataclass
class QueryFilter:
    """Database query filter representation"""

    field: str
    operator: str = "exact"  # exact, contains, in, gt, lt, etc.
    value: Any = None


class DatabaseInterface(ABC):
    """Abstract database interface"""

    @abstractmethod
    def create_record(self, model_name: str, data: Dict[str, Any]) -> DatabaseRecord:
        """Create a new record"""
        pass

    @abstractmethod
    def get_record(self, model_name: str, record_id: int) -> Optional[DatabaseRecord]:
        """Get a record by ID"""
        pass

    @abstractmethod
    def filter_records(self, model_name: str, filters: List[QueryFilter]) -> List[DatabaseRecord]:
        """Filter records by criteria"""
        pass

    @abstractmethod
    def update_record(self, model_name: str, record_id: int, data: Dict[str, Any]) -> bool:
        """Update a record"""
        pass

    @abstractmethod
    def delete_record(self, model_name: str, record_id: int) -> bool:
        """Delete a record"""
        pass

    @abstractmethod
    def bulk_create(self, model_name: str, records: List[Dict[str, Any]]) -> List[DatabaseRecord]:
        """Bulk create records"""
        pass


class DatabaseOperation:
    """Database operation context"""

    def __init__(self, interface: DatabaseInterface):
        self.interface = interface

    def save_endpoint(self, endpoint_data: Dict[str, Any]) -> DatabaseRecord:
        """Save endpoint data"""
        return self.interface.create_record("endpoint", endpoint_data)

    def save_subdomain(self, subdomain_data: Dict[str, Any]) -> DatabaseRecord:
        """Save subdomain data"""
        return self.interface.create_record("subdomain", subdomain_data)

    def save_vulnerability(self, vuln_data: Dict[str, Any]) -> DatabaseRecord:
        """Save vulnerability data"""
        return self.interface.create_record("vulnerability", vuln_data)

    def get_endpoints_by_domain(self, domain_id: int) -> List[DatabaseRecord]:
        """Get endpoints by domain"""
        filters = [QueryFilter("target_domain", "exact", domain_id)]
        return self.interface.filter_records("endpoint", filters)

    def get_subdomains_by_domain(self, domain_id: int) -> List[DatabaseRecord]:
        """Get subdomains by domain"""
        filters = [QueryFilter("target_domain", "exact", domain_id)]
        return self.interface.filter_records("subdomain", filters)


class DatabaseContext:
    """Database context manager"""

    def __init__(self, interface: DatabaseInterface):
        self.interface = interface
        self.operations = DatabaseOperation(interface)

    def __enter__(self):
        return self.operations

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


# Factory function for dependency injection
def create_database_context(interface: Optional[DatabaseInterface] = None) -> DatabaseContext:
    """
    Create database context with dependency injection.

    Args:
        interface: Database interface implementation (injected at runtime)

    Returns:
        DatabaseContext: Database context for operations
    """
    if interface is None:
        # Default implementation will be injected by the calling layer
        raise ValueError("Database interface must be provided")

    return DatabaseContext(interface)
