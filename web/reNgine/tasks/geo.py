"""
Geolocation tasks for IP address geolocation.

This module provides functionality for geolocating IP addresses
using various geolocation services and databases.
"""

from typing import Any, Dict, List, Optional, Tuple

from celery.utils.log import get_task_logger
import validators

from reNgine.celery import app
from reNgine.utilities.distributed.utilities import (
    get_distributed_utilities,
    ProcessorType,
    create_balanced_config
)
from reNgine.utilities.distributed.database import (
    DistributedIPProcessor
)
from reNgine.utilities.core.data import (
    is_iterable,
    chunk_list,
    remove_duplicates
)
from reNgine.utilities.core.validation import (
    is_valid_ip,
    is_valid_domain
)
from reNgine.utilities.core.formatting import (
    format_duration,
    format_bytes
)
from reNgine.utilities.core import geoiplookup, get_ip_info
from startScan.models import CountryISO, IpAddress


logger = get_task_logger(__name__)


class GeolocationProcessor:
    """Geolocation processor using distributed utilities"""
    
    def __init__(self, config=None):
        self.distributed_utils = get_distributed_utilities(config)
        self.network_processor = self.distributed_utils.get_network_processor()
        self.ip_processor = self.distributed_utils.get_ip_processor()
    
    def geolocate_ips_batch(
        self,
        ip_addresses: List[str],
        batch_id: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Geolocate multiple IP addresses using distributed network processor"""
        try:
            # Filter valid IPs
            valid_ips = [ip for ip in ip_addresses if is_valid_ip(ip) and not validators.ipv6(ip)]
            
            if not valid_ips:
                return {
                    "success": True,
                    "batch_id": batch_id,
                    "total_ips": len(ip_addresses),
                    "geolocated_ips": [],
                    "skipped_ips": ip_addresses,
                    "errors": ["No valid IPv4 addresses found"]
                }
            
            # Use distributed network processor for geolocation
            result = self.network_processor.geolocate_ips_batch(
                valid_ips, batch_id, **kwargs
            )
            
            return {
                "success": result.is_successful,
                "batch_id": batch_id,
                "total_ips": len(ip_addresses),
                "valid_ips": len(valid_ips),
                "geolocated_ips": result.data.get("geolocated_ips", []),
                "failed_ips": result.data.get("failed_ips", []),
                "skipped_ips": [ip for ip in ip_addresses if ip not in valid_ips],
                "errors": result.errors,
                "processing_time": result.processing_time
            }
            
        except Exception as e:
            logger.error(f"Geolocation batch processing failed for batch {batch_id}: {e}")
            return {
                "success": False,
                "batch_id": batch_id,
                "error": str(e),
                "total_ips": len(ip_addresses)
            }
    
    def geolocate_single_ip(
        self,
        ip_address: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Geolocate a single IP address"""
        try:
            # Validate IP
            if not is_valid_ip(ip_address):
                return {
                    "success": False,
                    "ip_address": ip_address,
                    "error": "Invalid IP address"
                }
            
            # Skip IPv6 addresses
            if validators.ipv6(ip_address):
                return {
                    "success": False,
                    "ip_address": ip_address,
                    "error": "IPv6 addresses are not supported by geoiplookup"
                }
            
            # Use geoiplookup function with robust parsing
            success, country_iso, country_name, error = geoiplookup(ip_address)
            
            if not success:
                return {
                    "success": False,
                    "ip_address": ip_address,
                    "error": error
                }
            
            if country_iso and country_name:
                return {
                    "success": True,
                    "ip_address": ip_address,
                    "country_iso": country_iso,
                    "country_name": country_name
                }
            else:
                return {
                    "success": False,
                    "ip_address": ip_address,
                    "error": "No geolocation data found"
                }
                
        except Exception as e:
            logger.error(f"Geolocation failed for {ip_address}: {e}")
            return {
                "success": False,
                "ip_address": ip_address,
                "error": str(e)
            }
    
    def update_ip_geolocation(
        self,
        ip_address: str,
        country_iso: str,
        country_name: str,
        ip_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Update IP geolocation in database using distributed database processor"""
        try:
            # Create or get CountryISO object
            geo_object, created = CountryISO.objects.get_or_create(
                iso=country_iso, 
                name=country_name
            )
            
            # Update IP object if ip_id provided
            if ip_id:
                ip = IpAddress.objects.get(pk=ip_id)
                ip.geo_iso = geo_object
                ip.save()
            
            return {
                "success": True,
                "ip_address": ip_address,
                "country_iso": country_iso,
                "country_name": country_name,
                "geo_object_created": created,
                "ip_updated": ip_id is not None
            }
            
        except Exception as e:
            logger.error(f"Failed to update IP geolocation for {ip_address}: {e}")
            return {
                "success": False,
                "ip_address": ip_address,
                "error": str(e)
            }


# Celery tasks

@app.task(name="geo_localize", bind=False, queue="io_queue")
def geo_localize(host, ip_id=None):
    """Uses geoiplookup to find location associated with host.

    Args:
        host (str): Hostname.
        ip_id (int): IpAddress object id.

    Returns:
        startScan.models.CountryISO: CountryISO object from DB or None.
    """
    if validators.ipv6(host):
        logger.info(f'Ipv6 "{host}" is not supported by geoiplookup. Skipping.')
        return None

    # Use distributed geolocation processor
    processor = GeolocationProcessor()
    
    # Geolocate the host
    result = processor.geolocate_single_ip(host)
    
    if not result["success"]:
        logger.warning(f"Failed to geolocalize {host}: {result.get('error', 'Unknown error')}")
        return None

    # Update database
    update_result = processor.update_ip_geolocation(
        host,
        result["country_iso"],
        result["country_name"],
        ip_id
    )
    
    if update_result["success"]:
        geo_json = {
            "iso": result["country_iso"], 
            "name": result["country_name"]
        }
        return geo_json
    else:
        logger.error(f"Failed to update geolocation for {host}: {update_result.get('error', 'Unknown error')}")
        return None


@app.task(name="geo_localize_batch", bind=False, queue="io_queue")
def geo_localize_batch(ip_addresses):
    """Batch geolocalization for multiple IP addresses.

    Args:
        ip_addresses (list): List of IP addresses to geolocalize.

    Returns:
        dict: Results of geolocalization with success/failure counts.
    """
    if not ip_addresses:
        logger.info("No IP addresses provided for batch geolocalization")
        return {"success": 0, "failed": 0, "skipped": 0}

    logger.info(f"Starting batch geolocalization for {len(ip_addresses)} IP addresses")

    # Use distributed geolocation processor
    processor = GeolocationProcessor()
    
    # Process in batches for better performance
    batch_size = 50  # Process 50 IPs at a time
    ip_batches = chunk_list(ip_addresses, batch_size)
    
    total_success = 0
    total_failed = 0
    total_skipped = 0
    
    for i, batch in enumerate(ip_batches):
        logger.info(f"Processing batch {i + 1}/{len(ip_batches)} with {len(batch)} IPs")
        
        # Geolocate batch
        result = processor.geolocate_ips_batch(batch, f"geo_batch_{i}")
        
        if result["success"]:
            # Process geolocated IPs
            for geo_data in result.get("geolocated_ips", []):
                try:
                    # Get the IP object from database
                    ip_obj = IpAddress.objects.filter(address=geo_data["ip_address"]).first()
                    if not ip_obj:
                        logger.warning(f"IP object not found for address: {geo_data['ip_address']}")
                        total_failed += 1
                        continue

                    # Skip if already geolocalized
                    if ip_obj.geo_iso:
                        logger.debug(f"IP {geo_data['ip_address']} already geolocalized, skipping")
                        total_skipped += 1
                        continue

                    # Update IP object
                    update_result = processor.update_ip_geolocation(
                        geo_data["ip_address"],
                        geo_data["country_iso"],
                        geo_data["country_name"],
                        ip_obj.id
                    )
                    
                    if update_result["success"]:
                        logger.debug(f"Successfully geolocalized {geo_data['ip_address']} -> {geo_data['country_name']}")
                        total_success += 1
                    else:
                        logger.error(f"Failed to update geolocation for {geo_data['ip_address']}: {update_result.get('error', 'Unknown error')}")
                        total_failed += 1
                        
                except Exception as e:
                    logger.error(f"Error processing geolocation for {geo_data['ip_address']}: {str(e)}")
                    total_failed += 1
            
            # Count skipped IPs
            total_skipped += len(result.get("skipped_ips", []))
            total_failed += len(result.get("failed_ips", []))
        else:
            logger.error(f"Batch geolocation failed: {result.get('error', 'Unknown error')}")
            total_failed += len(batch)

    result = {
        "success": total_success, 
        "failed": total_failed, 
        "skipped": total_skipped, 
        "total": len(ip_addresses)
    }

    logger.info(f"Batch geolocalization completed: {result}")
    return result


# Utility functions for easy access

def geolocate_ips_distributed(
    ip_addresses: List[str],
    **kwargs
) -> Dict[str, Any]:
    """
    Geolocate IP addresses using distributed processing.
    """
    processor = GeolocationProcessor()
    return processor.geolocate_ips_batch(
        ip_addresses, "distributed_geolocation", **kwargs
    )


def geolocate_single_ip_distributed(
    ip_address: str,
    **kwargs
) -> Dict[str, Any]:
    """
    Geolocate a single IP address using distributed processing.
    """
    processor = GeolocationProcessor()
    return processor.geolocate_single_ip(ip_address, **kwargs)


def validate_geolocation_input(ip_addresses: List[str]) -> Dict[str, Any]:
    """
    Validate IP addresses for geolocation.
    
    Args:
        ip_addresses: List of IP addresses to validate
        
    Returns:
        Validation result
    """
    validation_result = {
        "valid": True,
        "valid_ips": [],
        "invalid_ips": [],
        "ipv6_ips": [],
        "private_ips": [],
        "errors": []
    }
    
    for ip in ip_addresses:
        if not is_valid_ip(ip):
            validation_result["invalid_ips"].append(ip)
            continue
        
        if validators.ipv6(ip):
            validation_result["ipv6_ips"].append(ip)
            continue
        
        # Check if IP is private
        try:
            ip_info = get_ip_info(ip)
            if ip_info and ip_info.is_private:
                validation_result["private_ips"].append(ip)
                continue
        except Exception:
            pass
        
        validation_result["valid_ips"].append(ip)
    
    if not validation_result["valid_ips"]:
        validation_result["valid"] = False
        validation_result["errors"].append("No valid public IPv4 addresses found")
    
    return validation_result


def get_geolocation_statistics(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get statistics from geolocation results.
    
    Args:
        results: Geolocation results
        
    Returns:
        Statistics dictionary
    """
    if not results:
        return {
            "total_processed": 0,
            "successful_geolocations": 0,
            "failed_geolocations": 0,
            "skipped_geolocations": 0,
            "success_rate": 0
        }
    
    total_processed = results.get("total_ips", 0)
    successful = len(results.get("geolocated_ips", []))
    failed = len(results.get("failed_ips", []))
    skipped = len(results.get("skipped_ips", []))
    
    success_rate = (successful / total_processed * 100) if total_processed > 0 else 0
    
    return {
        "total_processed": total_processed,
        "successful_geolocations": successful,
        "failed_geolocations": failed,
        "skipped_geolocations": skipped,
        "success_rate": success_rate
    }


def get_country_statistics(geolocated_ips: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Get country statistics from geolocated IPs.
    
    Args:
        geolocated_ips: List of geolocated IP data
        
    Returns:
        Country statistics
    """
    if not geolocated_ips:
        return {
            "total_countries": 0,
            "country_distribution": {},
            "top_countries": []
        }
    
    country_counts = {}
    for ip_data in geolocated_ips:
        country = ip_data.get("country_name", "Unknown")
        country_counts[country] = country_counts.get(country, 0) + 1
    
    # Sort countries by count
    top_countries = sorted(
        country_counts.items(), 
        key=lambda x: x[1], 
        reverse=True
    )[:10]  # Top 10 countries
    
    return {
        "total_countries": len(country_counts),
        "country_distribution": country_counts,
        "top_countries": top_countries
    }


def filter_geolocation_results(
    results: Dict[str, Any],
    country_filter: Optional[List[str]] = None,
    exclude_private: bool = True
) -> Dict[str, Any]:
    """
    Filter geolocation results based on criteria.
    
    Args:
        results: Geolocation results
        country_filter: List of countries to include (None for all)
        exclude_private: Whether to exclude private IPs
        
    Returns:
        Filtered results
    """
    filtered_results = results.copy()
    
    if "geolocated_ips" in results:
        geolocated_ips = results["geolocated_ips"]
        
        # Filter by country
        if country_filter:
            geolocated_ips = [
                ip for ip in geolocated_ips 
                if ip.get("country_name") in country_filter
            ]
        
        # Filter private IPs
        if exclude_private:
            filtered_ips = []
            for ip_data in geolocated_ips:
                try:
                    ip_info = get_ip_info(ip_data["ip_address"])
                    if not (ip_info and ip_info.is_private):
                        filtered_ips.append(ip_data)
                except Exception:
                    # If we can't determine if it's private, include it
                    filtered_ips.append(ip_data)
            geolocated_ips = filtered_ips
        
        filtered_results["geolocated_ips"] = geolocated_ips
    
    return filtered_results
