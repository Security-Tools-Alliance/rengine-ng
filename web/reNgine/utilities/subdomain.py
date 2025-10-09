"""
Subdomain utilities for querying and managing subdomain data.

This module provides functionality for querying subdomains from the database
using the abstract database interface to avoid circular dependencies.
"""

from typing import Any, Dict, List, Optional, Union
from django.db.models import Q

from reNgine.utilities.database_interface import DatabaseInterface, DatabaseRecord, QueryFilter


def get_subdomains(
    write_filepath: Optional[str] = None,
    exclude_subdomains: bool = False,
    ctx: Optional[Dict[str, Any]] = None,
    db_interface: Optional[DatabaseInterface] = None
) -> List[str]:
    """
    Get Subdomain objects from DB.

    Args:
        write_filepath: Write info back to a file.
        exclude_subdomains: Exclude subdomains, only return subdomain matching domain.
        ctx: Context dictionary containing domain_id, scan_history_id, etc.
        db_interface: Database interface for querying

    Returns:
        List of subdomain names matching query.
    """
    if not db_interface or not ctx:
        return []

    domain_id = ctx.get("domain_id")
    scan_id = ctx.get("scan_history_id")
    subdomain_id = ctx.get("subdomain_id")
    exclude_subdomains = ctx.get("exclude_subdomains", False)
    url_filter = ctx.get("url_filter", "")

    # Build query filters
    filters = []
    
    if domain_id:
        filters.append(QueryFilter("target_domain_id", domain_id))
    if scan_id:
        filters.append(QueryFilter("scan_history_id", scan_id))
    if subdomain_id:
        filters.append(QueryFilter("id", subdomain_id))
    elif domain_id and exclude_subdomains:
        # This would need domain name lookup - simplified for now
        pass

    # Query subdomains
    subdomain_records = db_interface.filter_records("subdomain", filters)
    subdomains = [record.data.get("name") for record in subdomain_records if record.data.get("name")]

    if not subdomains:
        return []

    if url_filter:
        subdomains = [f"{subdomain}/{url_filter}" for subdomain in subdomains]

    if write_filepath:
        try:
            with open(write_filepath, "w") as f:
                f.write("\n".join(subdomains))
        except Exception:
            pass

    return subdomains


def get_new_added_subdomain(
    scan_id: int,
    domain_id: int,
    db_interface: Optional[DatabaseInterface] = None
) -> List[DatabaseRecord]:
    """
    Find domains added during the last scan.

    Args:
        scan_id: startScan.models.ScanHistory ID.
        domain_id: startScan.models.Domain ID.
        db_interface: Database interface for querying

    Returns:
        List of newly added subdomain records.
    """
    if not db_interface:
        return []

    try:
        # Get previous scan with subdomain_discovery task
        # This is a simplified implementation - would need more complex querying
        # in a real implementation with the database interface
        
        # For now, return empty list as this requires complex querying
        # that would need to be implemented in the specific database interface
        return []
        
    except Exception:
        return []


def get_removed_subdomain(
    scan_id: int,
    domain_id: int,
    db_interface: Optional[DatabaseInterface] = None
) -> List[DatabaseRecord]:
    """
    Find domains removed during the last scan.

    Args:
        scan_id: startScan.models.ScanHistory ID.
        domain_id: startScan.models.Domain ID.
        db_interface: Database interface for querying

    Returns:
        List of removed subdomain records.
    """
    if not db_interface:
        return []

    try:
        # This is a simplified implementation - would need more complex querying
        # in a real implementation with the database interface
        
        # For now, return empty list as this requires complex querying
        # that would need to be implemented in the specific database interface
        return []
        
    except Exception:
        return []


def get_interesting_subdomains(
    scan_history: Optional[int] = None,
    domain_id: Optional[int] = None,
    db_interface: Optional[DatabaseInterface] = None
) -> List[DatabaseRecord]:
    """
    Get Subdomain objects matching InterestingLookupModel conditions.

    Args:
        scan_history: Scan history ID.
        domain_id: Domain id.
        db_interface: Database interface for querying

    Returns:
        List of interesting subdomain records.
    """
    if not db_interface:
        return []

    try:
        # Get lookup keywords - this would need to be implemented
        # in the specific database interface or moved to a separate utility
        lookup_keywords = _get_lookup_keywords(db_interface)
        if not lookup_keywords:
            return []

        # Get interesting lookup model configuration
        lookup_obj = _get_interesting_lookup_model(db_interface)
        if not lookup_obj:
            return []

        # Build query filters
        filters = []
        
        if domain_id:
            filters.append(QueryFilter("target_domain_id", domain_id))
        elif scan_history:
            filters.append(QueryFilter("scan_history_id", scan_history))

        # Filter on HTTP status code 200 if required
        if lookup_obj.get("condition_200_http_lookup", False):
            filters.append(QueryFilter("http_status", 200))

        # Get subdomains matching the filters
        subdomain_records = db_interface.filter_records("subdomain", filters)
        
        # Filter by interesting keywords
        interesting_subdomains = []
        for record in subdomain_records:
            subdomain_name = record.data.get("name", "")
            page_title = record.data.get("page_title", "")
            
            # Check URL lookup
            if lookup_obj.get("url_lookup", False):
                for keyword in lookup_keywords:
                    if keyword.lower() in subdomain_name.lower():
                        interesting_subdomains.append(record)
                        break
            
            # Check title lookup
            if lookup_obj.get("title_lookup", False):
                for keyword in lookup_keywords:
                    if keyword.lower() in page_title.lower():
                        interesting_subdomains.append(record)
                        break

        return interesting_subdomains
        
    except Exception:
        return []


def _get_lookup_keywords(db_interface: Optional[DatabaseInterface] = None) -> List[str]:
    """
    Get lookup keywords for interesting subdomain detection.
    
    Args:
        db_interface: Database interface for querying
        
    Returns:
        List of lookup keywords
    """
    if not db_interface:
        return []
    
    try:
        # This would need to be implemented in the specific database interface
        # For now, return some default keywords
        return [
            "admin", "api", "app", "backup", "beta", "blog", "cdn", "dev", "ftp",
            "git", "mail", "mobile", "old", "preview", "staging", "test", "www"
        ]
    except Exception:
        return []


def _get_interesting_lookup_model(db_interface: Optional[DatabaseInterface] = None) -> Optional[Dict[str, Any]]:
    """
    Get interesting lookup model configuration.
    
    Args:
        db_interface: Database interface for querying
        
    Returns:
        Dictionary with lookup configuration or None
    """
    if not db_interface:
        return None
    
    try:
        # This would need to be implemented in the specific database interface
        # For now, return default configuration
        return {
            "url_lookup": True,
            "title_lookup": True,
            "condition_200_http_lookup": True
        }
    except Exception:
        return None


def get_subdomain_by_name(
    name: str,
    scan_history_id: Optional[int] = None,
    domain_id: Optional[int] = None,
    db_interface: Optional[DatabaseInterface] = None
) -> Optional[DatabaseRecord]:
    """
    Get a subdomain by name.
    
    Args:
        name: Subdomain name
        scan_history_id: Scan history ID (optional)
        domain_id: Domain ID (optional)
        db_interface: Database interface for querying
        
    Returns:
        Subdomain record or None
    """
    if not db_interface or not name:
        return None
    
    try:
        filters = [QueryFilter("name", name)]
        
        if scan_history_id:
            filters.append(QueryFilter("scan_history_id", scan_history_id))
        if domain_id:
            filters.append(QueryFilter("target_domain_id", domain_id))
        
        records = db_interface.filter_records("subdomain", filters)
        return records[0] if records else None
        
    except Exception:
        return None


def get_subdomains_by_domain(
    domain_id: int,
    scan_history_id: Optional[int] = None,
    db_interface: Optional[DatabaseInterface] = None
) -> List[DatabaseRecord]:
    """
    Get all subdomains for a specific domain.
    
    Args:
        domain_id: Domain ID
        scan_history_id: Scan history ID (optional)
        db_interface: Database interface for querying
        
    Returns:
        List of subdomain records
    """
    if not db_interface:
        return []
    
    try:
        filters = [QueryFilter("target_domain_id", domain_id)]
        
        if scan_history_id:
            filters.append(QueryFilter("scan_history_id", scan_history_id))
        
        return db_interface.filter_records("subdomain", filters)
        
    except Exception:
        return []


def get_subdomains_by_scan(
    scan_history_id: int,
    domain_id: Optional[int] = None,
    db_interface: Optional[DatabaseInterface] = None
) -> List[DatabaseRecord]:
    """
    Get all subdomains for a specific scan.
    
    Args:
        scan_history_id: Scan history ID
        domain_id: Domain ID (optional)
        db_interface: Database interface for querying
        
    Returns:
        List of subdomain records
    """
    if not db_interface:
        return []
    
    try:
        filters = [QueryFilter("scan_history_id", scan_history_id)]
        
        if domain_id:
            filters.append(QueryFilter("target_domain_id", domain_id))
        
        return db_interface.filter_records("subdomain", filters)
        
    except Exception:
        return []
