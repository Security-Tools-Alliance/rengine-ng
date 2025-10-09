"""
Database utilities for saving and managing scan results.

This module provides functionality for saving various types of scan results
to the database using distributed database processors.
"""

from typing import Any, Dict, List, Optional, Tuple

from reNgine.utilities.distributed.utilities import get_distributed_utilities
from reNgine.utilities.distributed.database import DistributedEndpointProcessor
from reNgine.utilities.core.validation import is_valid_url
from reNgine.utilities.core.data import chunk_list
from reNgine.utilities.database_interface import DatabaseInterface, DatabaseRecord, QueryFilter

# Import settings for cache key generation
try:
    from reNgine.settings import RENGINE_TASK_IGNORE_CACHE_KWARGS
except ImportError:
    # Fallback if setting is not available
    RENGINE_TASK_IGNORE_CACHE_KWARGS = set()


class DatabaseProcessor:
    """Database processor using distributed utilities"""
    
    def __init__(self, config=None, db_interface: Optional[DatabaseInterface] = None):
        self.distributed_utils = get_distributed_utilities(config)
        self.db_interface = db_interface
        self.endpoint_processor = self.distributed_utils.get_endpoint_processor()
        self.subdomain_processor = self.distributed_utils.get_subdomain_processor()
    
    def save_endpoint(
        self,
        http_url: str,
        subdomain_id: Optional[int] = None,
        scan_history_id: Optional[int] = None,
        **kwargs
    ) -> Tuple[Optional[DatabaseRecord], bool]:
        """Save endpoint to database using distributed processor"""
        if not self.db_interface:
            return None, False
            
        try:
            endpoint_data = {
                "http_url": http_url,
                "subdomain_id": subdomain_id,
                "scan_history_id": scan_history_id,
                **kwargs
            }
            
            endpoint_record = self.db_interface.create_record("endpoint", endpoint_data)
            return endpoint_record, True
                
        except Exception as e:
            return None, False
    
    def save_endpoints_batch(
        self,
        endpoints_data: List[Dict[str, Any]],
        batch_id: str = "batch"
    ) -> Dict[str, Any]:
        """Save multiple endpoints using distributed processor"""
        if not self.db_interface:
            return {
                "success": False,
                "saved_count": 0,
                "skipped_count": 0,
                "errors": ["Database interface not provided"]
            }
            
        try:
            saved_count = 0
            skipped_count = 0
            errors = []
            
            for endpoint_data in endpoints_data:
                try:
                    self.db_interface.create_record("endpoint", endpoint_data)
                    saved_count += 1
                except Exception as e:
                    errors.append(f"Failed to save endpoint {endpoint_data.get('http_url', 'unknown')}: {str(e)}")
                    skipped_count += 1
            
            return {
                "success": len(errors) == 0,
                "saved_count": saved_count,
                "skipped_count": skipped_count,
                "errors": errors
            }
            
        except Exception as e:
            return {
                "success": False,
                "saved_count": 0,
                "skipped_count": 0,
                "errors": [str(e)]
            }
    
    def save_subdomain(
        self,
        name: str,
        scan_history_id: Optional[int] = None,
        **kwargs
    ) -> Tuple[Optional[DatabaseRecord], bool]:
        """Save subdomain to database using distributed processor"""
        if not self.db_interface:
            return None, False
            
        try:
            subdomain_data = {
                "name": name,
                "scan_history_id": scan_history_id,
                **kwargs
            }
            
            subdomain_record = self.db_interface.create_record("subdomain", subdomain_data)
            return subdomain_record, True
                
        except Exception as e:
            return None, False
    
    def save_vulnerability(
        self,
        name: str,
        http_url: str,
        scan_history_id: Optional[int] = None,
        **kwargs
    ) -> Tuple[Optional[DatabaseRecord], bool]:
        """Save vulnerability to database"""
        if not self.db_interface:
            return None, False
            
        try:
            vulnerability_data = {
                "name": name,
                "http_url": http_url,
                "scan_history_id": scan_history_id,
                **kwargs
            }
            
            vulnerability_record = self.db_interface.create_record("vulnerability", vulnerability_data)
            return vulnerability_record, True
                
        except Exception as e:
            return None, False


def save_endpoint(
    http_url: str,
    subdomain_id: Optional[int] = None,
    scan_history_id: Optional[int] = None,
    db_interface: Optional[DatabaseInterface] = None,
    **kwargs
) -> Tuple[Optional[DatabaseRecord], bool]:
    """
    Save endpoint to database.
    
    Args:
        http_url: HTTP URL of the endpoint
        subdomain_id: Associated subdomain ID
        scan_history_id: Associated scan history ID
        db_interface: Database interface
        **kwargs: Additional endpoint fields
        
    Returns:
        Tuple of (endpoint_record, created)
    """
    processor = DatabaseProcessor(db_interface=db_interface)
    return processor.save_endpoint(
        http_url=http_url,
        subdomain_id=subdomain_id,
        scan_history_id=scan_history_id,
        **kwargs
    )


def save_subdomain(
    name: str,
    scan_history_id: Optional[int] = None,
    db_interface: Optional[DatabaseInterface] = None,
    **kwargs
) -> Tuple[Optional[DatabaseRecord], bool]:
    """
    Save subdomain to database.
    
    Args:
        name: Subdomain name
        scan_history_id: Associated scan history ID
        db_interface: Database interface
        **kwargs: Additional subdomain fields
        
    Returns:
        Tuple of (subdomain_record, created)
    """
    processor = DatabaseProcessor(db_interface=db_interface)
    return processor.save_subdomain(
        name=name,
        scan_history_id=scan_history_id,
        **kwargs
    )


def validate_and_save_subdomain(
    subdomain_name: str,
    ctx: Dict[str, Any] = None,
    db_interface: Optional[DatabaseInterface] = None
) -> Tuple[Optional[DatabaseRecord], bool]:
    """
    Validate and save subdomain to database.
    
    Args:
        subdomain_name: Name of the subdomain
        ctx: Context dictionary containing scan_history_id
        db_interface: Database interface
        
    Returns:
        Tuple of (subdomain_record, created)
    """
    if not subdomain_name or not isinstance(subdomain_name, str):
        return None, False
    
    scan_history_id = ctx.get("scan_history_id") if ctx else None
    if not scan_history_id:
        return None, False
    
    if not db_interface:
        return None, False
    
    try:
        # Check if subdomain already exists
        existing = db_interface.filter_records("subdomain", [
            QueryFilter("name", subdomain_name),
            QueryFilter("scan_history_id", scan_history_id)
        ])
        
        if existing:
            return existing[0], False
        
        # Create new subdomain
        subdomain_data = {
            "name": subdomain_name,
            "scan_history_id": scan_history_id
        }
        subdomain_record = db_interface.create_record("subdomain", subdomain_data)
        return subdomain_record, True
    except Exception:
        return None, False


def save_vulnerability(
    name: str,
    http_url: str,
    scan_history_id: Optional[int] = None,
    db_interface: Optional[DatabaseInterface] = None,
    **kwargs
) -> Tuple[Optional[DatabaseRecord], bool]:
    """
    Save vulnerability to database.
    
    Args:
        name: Vulnerability name
        http_url: HTTP URL where vulnerability was found
        scan_history_id: Associated scan history ID
        db_interface: Database interface
        **kwargs: Additional vulnerability fields
        
    Returns:
        Tuple of (vulnerability_record, created)
    """
    processor = DatabaseProcessor(db_interface=db_interface)
    return processor.save_vulnerability(
        name=name,
        http_url=http_url,
        scan_history_id=scan_history_id,
        **kwargs
    )


def save_technology(
    name: str,
    endpoint_id: Optional[int] = None,
    subdomain_id: Optional[int] = None,
    db_interface: Optional[DatabaseInterface] = None,
    **kwargs
) -> Tuple[Optional[DatabaseRecord], bool]:
    """
    Save technology to database.
    
    Args:
        name: Technology name
        endpoint_id: Associated endpoint ID
        subdomain_id: Associated subdomain ID
        db_interface: Database interface
        **kwargs: Additional technology fields
        
    Returns:
        Tuple of (technology_record, created)
    """
    if not db_interface:
        return None, False
        
    try:
        # Check if technology already exists
        existing = db_interface.filter_records("technology", [
            QueryFilter("name", name)
        ])
        
        if existing:
            technology_record = existing[0]
            created = False
        else:
            # Create new technology
            technology_data = {
                "name": name,
                **kwargs
            }
            technology_record = db_interface.create_record("technology", technology_data)
            created = True
        
        # Note: Many-to-many relationships would need to be handled separately
        # in the calling code using the appropriate database interface methods
        
        return technology_record, created
            
    except Exception:
        return None, False


def save_waf(
    name: str,
    manufacturer: str = "",
    db_interface: Optional[DatabaseInterface] = None,
    **kwargs
) -> Tuple[Optional[DatabaseRecord], bool]:
    """
    Save WAF to database.
    
    Args:
        name: WAF name
        manufacturer: WAF manufacturer
        db_interface: Database interface
        **kwargs: Additional WAF fields
        
    Returns:
        Tuple of (waf_record, created)
    """
    if not db_interface:
        return None, False
        
    try:
        # Check if WAF already exists
        existing = db_interface.filter_records("waf", [
            QueryFilter("name", name),
            QueryFilter("manufacturer", manufacturer)
        ])
        
        if existing:
            waf_record = existing[0]
            created = False
        else:
            # Create new WAF
            waf_data = {
                "name": name,
                "manufacturer": manufacturer,
                **kwargs
            }
            waf_record = db_interface.create_record("waf", waf_data)
            created = True
        
        return waf_record, created
            
    except Exception:
        return None, False


def validate_database_input(
    data: Dict[str, Any],
    required_fields: List[str] = None
) -> Dict[str, Any]:
    """
    Validate database input data.
    
    Args:
        data: Data to validate
        required_fields: List of required fields
        
    Returns:
        Validation result
    """
    validation_result = {
        "valid": True,
        "errors": [],
        "warnings": []
    }
    
    if not data or not isinstance(data, dict):
        validation_result["valid"] = False
        validation_result["errors"].append("Data must be a non-empty dictionary")
        return validation_result
    
    if required_fields:
        for field in required_fields:
            if field not in data:
                validation_result["valid"] = False
                validation_result["errors"].append(f"Required field '{field}' is missing")
    
    return validation_result


def get_database_statistics(
    scan_history_id: Optional[int] = None,
    db_interface: Optional[DatabaseInterface] = None
) -> Dict[str, Any]:
    """
    Get database statistics for a scan.
    
    Args:
        scan_history_id: Scan history ID to get statistics for
        db_interface: Database interface
        
    Returns:
        Statistics dictionary
    """
    if not db_interface:
        return {
            "endpoints": 0,
            "subdomains": 0,
            "vulnerabilities": 0,
            "technologies": 0,
            "wafs": 0
        }
        
    try:
        if not scan_history_id:
            return {
                "endpoints": 0,
                "subdomains": 0,
                "vulnerabilities": 0,
                "technologies": 0,
                "wafs": 0
            }
        
        endpoints = len(db_interface.filter_records("endpoint", [
            QueryFilter("scan_history_id", scan_history_id)
        ]))
        
        subdomains = len(db_interface.filter_records("subdomain", [
            QueryFilter("scan_history_id", scan_history_id)
        ]))
        
        vulnerabilities = len(db_interface.filter_records("vulnerability", [
            QueryFilter("scan_history_id", scan_history_id)
        ]))
        
        # Note: Complex queries like distinct counts would need to be handled
        # by the specific database interface implementation
        technologies = 0  # Would need specific implementation
        wafs = 0  # Would need specific implementation
        
        return {
            "endpoints": endpoints,
            "subdomains": subdomains,
            "vulnerabilities": vulnerabilities,
            "technologies": technologies,
            "wafs": wafs
        }
        
    except Exception:
        return {
            "endpoints": 0,
            "subdomains": 0,
            "vulnerabilities": 0,
            "technologies": 0,
            "wafs": 0
        }


def save_fuzzing_file(
    name: str,
    url: str,
    http_status: int,
    length: int,
    words: int,
    lines: int,
    content_type: str,
    scan_history_id: Optional[int] = None,
    db_interface: Optional[DatabaseInterface] = None,
    **kwargs
) -> Tuple[Optional[DatabaseRecord], bool]:
    """
    Save fuzzing file result to database.
    
    Args:
        name: Name of the file/directory
        url: URL of the file/directory
        http_status: HTTP status code
        length: Content length
        words: Number of words
        lines: Number of lines
        content_type: Content type
        scan_history_id: Associated scan history ID
        db_interface: Database interface
        **kwargs: Additional fields
        
    Returns:
        Tuple of (directory_file_record, created)
    """
    if not db_interface:
        return None, False
        
    try:
        # Check if directory file already exists
        existing = db_interface.filter_records("directory_file", [
            QueryFilter("name", name),
            QueryFilter("url", url),
            QueryFilter("http_status", http_status)
        ])
        
        if existing:
            return existing[0], False
        
        # Create new directory file
        directory_file_data = {
            "name": name,
            "url": url,
            "http_status": http_status,
            "length": length,
            "words": words,
            "lines": lines,
            "content_type": content_type,
            **kwargs
        }
        
        directory_file_record = db_interface.create_record("directory_file", directory_file_data)
        return directory_file_record, True
        
    except Exception:
        return None, False


def get_task_cache_key(func_name: str, *args, **kwargs) -> str:
    """
    Generate a cache key for a task function.
    
    Args:
        func_name: Name of the function
        *args: Function arguments
        **kwargs: Function keyword arguments
        
    Returns:
        Cache key string
    """
    args_str = "_".join([str(arg) for arg in args])
    kwargs_str = "_".join([f"{k}={v}" for k, v in kwargs.items() if k not in RENGINE_TASK_IGNORE_CACHE_KWARGS])
    return f"{func_name}__{args_str}__{kwargs_str}"


def create_scan_object(host_id, engine_id, initiated_by_id=None):
    """
    Create task with pending status so that celery task will execute when
    threads are free
    
    Args:
        host_id: int: id of Domain model
        engine_id: int: id of EngineType model
        initiated_by_id: int : id of User model (Optional)
        
    Returns:
        int: Scan ID
    """
    from reNgine.definitions import INITIATED_TASK
    from scanEngine.models import EngineType
    from startScan.models import Domain, ScanHistory
    from django.contrib.auth.models import User
    from django.utils import timezone

    # get current time
    current_scan_time = timezone.now()
    # fetch engine and domain object
    engine = EngineType.objects.get(pk=engine_id)
    domain = Domain.objects.get(pk=host_id)
    scan = ScanHistory()
    scan.scan_status = INITIATED_TASK
    scan.domain = domain
    scan.scan_type = engine
    scan.start_scan_date = current_scan_time
    if initiated_by_id:
        user = User.objects.get(pk=initiated_by_id)
        scan.initiated_by = user
    scan.save()
    # save last scan date for domain model
    domain.start_scan_date = current_scan_time
    domain.save()
    return scan.id


def create_scan_activity(scan_history_id, message, status):
    """
    Create scan activity record.
    
    Args:
        scan_history_id: int: ID of scan history
        message: str: Activity message
        status: str: Activity status
        
    Returns:
        int: Activity ID
    """
    from startScan.models import ScanActivity, ScanHistory
    from django.utils import timezone
    
    scan_activity = ScanActivity()
    scan_activity.scan_of = ScanHistory.objects.get(pk=scan_history_id)
    scan_activity.title = message
    scan_activity.time = timezone.now()
    scan_activity.status = status
    scan_activity.save()
    return scan_activity.id
