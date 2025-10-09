"""
Distributed network utilities.

This module provides distributed network operation capabilities that can be
reused across different task types while following SOLID, KISS, and DRY principles.

Key components:
1. DistributedNetworkProcessor - Base class for distributed network operations
2. DistributedDNSProcessor - DNS resolution with distributed support
3. DistributedURLProcessor - URL processing with distributed support
4. DistributedPortProcessor - Port scanning with distributed support
5. DistributedProxyProcessor - Proxy management with distributed support
"""

import socket
import time
from typing import Any, Dict, List, Optional, Union, Tuple
from reNgine.utilities.core.network import parse_url, extract_domain_from_url, resolve_hostname
from reNgine.utilities.core.validation import is_valid_ipv4, is_valid_ipv6
import tldextract

from celery.utils.log import get_task_logger
from django.core.exceptions import ValidationError

from reNgine.utilities.distributed.base import (
    DistributedTaskBase,
    DistributedResult,
    ProcessingStatus,
    DistributedConfig,
    create_distributed_config,
    validate_distributed_input,
    create_batch_tasks,
    aggregate_distributed_results
)
from reNgine.utilities.dns import resolve_subdomain_ips
from reNgine.utilities.url import (
    get_domain_from_subdomain,
    is_target_allowed_for_domain,
    is_valid_url,
    sanitize_url
)

logger = get_task_logger(__name__)


class DistributedNetworkResult(DistributedResult[Dict[str, Any]]):
    """Result container for distributed network operations"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.resolved_domains: List[str] = []
        self.resolved_ips: List[str] = []
        self.validated_urls: List[str] = []
        self.invalid_urls: List[str] = []
        self.network_errors: List[str] = []
    
    def add_resolved_domain(self, domain: str) -> None:
        """Add a resolved domain to the result"""
        self.resolved_domains.append(domain)
    
    def add_resolved_ip(self, ip: str) -> None:
        """Add a resolved IP to the result"""
        self.resolved_ips.append(ip)
    
    def add_validated_url(self, url: str) -> None:
        """Add a validated URL to the result"""
        self.validated_urls.append(url)
    
    def add_invalid_url(self, url: str) -> None:
        """Add an invalid URL to the result"""
        self.invalid_urls.append(url)
    
    def add_network_error(self, error: str) -> None:
        """Add a network error to the result"""
        self.network_errors.append(error)


class DistributedDNSProcessor(DistributedTaskBase):
    """Distributed processor for DNS operations"""
    
    def __init__(self, config: Optional[DistributedConfig] = None):
        super().__init__(config)
        self.dns_cache: Dict[str, List[str]] = {}
        self.resolution_history: Dict[str, List[Dict[str, Any]]] = {}
    
    def get_task_name(self) -> str:
        return "distributed_dns_processor"
    
    def get_queue_name(self) -> str:
        return "io_queue"
    
    def resolve_domains_batch(
        self, 
        domains: List[str], 
        batch_id: str,
        record_types: List[str] = None,
        **kwargs
    ) -> DistributedNetworkResult:
        """Resolve a batch of domains"""
        start_time = time.time()
        self.log_processing_start(batch_id, len(domains))
        
        result = DistributedNetworkResult(
            data={},
            status=ProcessingStatus.IN_PROGRESS,
            batch_id=batch_id
        )
        
        if record_types is None:
            record_types = ["A", "AAAA"]
        
        try:
            with self.safe_execution():
                resolved_domains = []
                resolved_ips = []
                network_errors = []
                
                for domain in domains:
                    try:
                        # Check cache first
                        if domain in self.dns_cache:
                            cached_ips = self.dns_cache[domain]
                            resolved_domains.append(domain)
                            resolved_ips.extend(cached_ips)
                            result.add_resolved_domain(domain)
                            for ip in cached_ips:
                                result.add_resolved_ip(ip)
                            continue
                        
                        # Resolve domain
                        resolution_result = self._resolve_domain(domain, record_types)
                        
                        if resolution_result['success']:
                            resolved_domains.append(domain)
                            resolved_ips.extend(resolution_result['ips'])
                            
                            # Cache the result
                            self.dns_cache[domain] = resolution_result['ips']
                            
                            result.add_resolved_domain(domain)
                            for ip in resolution_result['ips']:
                                result.add_resolved_ip(ip)
                            
                            # Record resolution history
                            self.resolution_history[domain] = resolution_result
                        else:
                            network_errors.append(f"Failed to resolve {domain}: {resolution_result['error']}")
                            result.add_network_error(f"Failed to resolve {domain}: {resolution_result['error']}")
                        
                    except Exception as e:
                        error_msg = f"Error resolving domain {domain}: {str(e)}"
                        network_errors.append(error_msg)
                        result.add_network_error(error_msg)
                        logger.error(error_msg)
                
                # Update result
                result.data = {
                    "resolved_domains": len(resolved_domains),
                    "resolved_ips": len(resolved_ips),
                    "network_errors": len(network_errors),
                    "total_domains": len(domains)
                }
                
                result.network_errors = network_errors
                result.status = ProcessingStatus.FAILED if network_errors else ProcessingStatus.COMPLETED
                result.processing_time = time.time() - start_time
                
        except Exception as e:
            result.status = ProcessingStatus.FAILED
            result.network_errors = [str(e)]
            result.processing_time = time.time() - start_time
            logger.error(f"Batch DNS resolution failed for {batch_id}: {e}")
        
        self.log_processing_completion(batch_id, result.is_successful, result.processing_time)
        return result
    
    def _resolve_domain(self, domain: str, record_types: List[str]) -> Dict[str, Any]:
        """Resolve a single domain"""
        try:
            ips = []
            
            for record_type in record_types:
                if record_type in ["A", "AAAA"]:
                    # Resolve IP addresses using core network function
                    resolved_ips = resolve_hostname(domain)
                    ips.extend([ip for ip in resolved_ips if is_valid_ipv4(ip) or is_valid_ipv6(ip)])
            
            # Remove duplicates
            ips = list(set(ips))
            
            return {
                "success": len(ips) > 0,
                "ips": ips,
                "domain": domain,
                "record_types": record_types
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "ips": [],
                "domain": domain,
                "record_types": record_types
            }
    
    def get_resolution_history(self, domain: str) -> List[Dict[str, Any]]:
        """Get resolution history for a domain"""
        return self.resolution_history.get(domain, [])
    
    def reverse_dns_lookup_batch(
        self, 
        ips: List[str], 
        batch_id: str,
        **kwargs
    ) -> DistributedNetworkResult:
        """Perform reverse DNS lookup for a batch of IP addresses"""
        start_time = time.time()
        self.log_processing_start(batch_id, len(ips))
        
        result = DistributedNetworkResult(
            data={},
            status=ProcessingStatus.IN_PROGRESS,
            batch_id=batch_id
        )
        
        try:
            with self.safe_execution():
                resolved_hostnames = []
                network_errors = []
                
                for ip in ips:
                    try:
                        # Perform reverse DNS lookup
                        hostname = socket.gethostbyaddr(ip)[0]
                        resolved_hostnames.append({
                            "ip": ip,
                            "hostname": hostname,
                            "timestamp": time.time()
                        })
                        result.add_resolved_ip(ip)
                        result.add_resolved_domain(hostname)
                        
                    except (socket.herror, socket.gaierror) as e:
                        error_msg = f"DNS lookup failed for {ip}: {str(e)}"
                        network_errors.append({
                            "ip": ip,
                            "error": str(e),
                            "timestamp": time.time()
                        })
                        result.add_network_error(error_msg)
                    except Exception as e:
                        error_msg = f"Unexpected error for {ip}: {str(e)}"
                        network_errors.append({
                            "ip": ip,
                            "error": f"Unexpected error: {str(e)}",
                            "timestamp": time.time()
                        })
                        result.add_network_error(error_msg)
                
                # Convert to format expected by ip_range_discovery task
                resolved_ips = []
                
                # Add successfully resolved IPs with hostnames
                for hostname_info in resolved_hostnames:
                    resolved_ips.append({
                        "ip": hostname_info["ip"],
                        "domain": hostname_info["hostname"],
                        "domains": [hostname_info["hostname"]],
                        "ips": [],
                        "resolved_by": "distributed_dns_processor",
                        "is_alive": False  # Will be updated by ping task
                    })
                
                # Add IPs that failed DNS resolution (but still exist)
                for error_info in network_errors:
                    resolved_ips.append({
                        "ip": error_info["ip"],
                        "domain": error_info["ip"],  # Use IP as domain if no hostname
                        "domains": [],
                        "ips": [],
                        "resolved_by": None,
                        "is_alive": False
                    })
                
                # Add IPs that were processed but had no DNS errors (no hostname found)
                processed_ips = {h["ip"] for h in resolved_hostnames} | {e["ip"] for e in network_errors}
                for ip in ips:
                    if ip not in processed_ips:
                        resolved_ips.append({
                            "ip": ip,
                            "domain": ip,  # Use IP as domain if no hostname
                            "domains": [],
                            "ips": [],
                            "resolved_by": None,
                            "is_alive": False
                        })
                
                # Update result
                result.data = {
                    "resolved_hostnames": resolved_hostnames,
                    "network_errors": network_errors,
                    "total_ips": len(ips),
                    "resolved_count": len(resolved_hostnames),
                    "error_count": len(network_errors)
                }
                result.status = ProcessingStatus.COMPLETED
                
                processing_time = time.time() - start_time
                self.log_processing_completion(batch_id, True, processing_time)
                
                # Log results for debugging
                logger.info(f"DNS batch {batch_id}: {len(resolved_hostnames)} hostnames resolved, {len(network_errors)} failed, {len(resolved_ips)} total IPs returned")
                if resolved_hostnames:
                    logger.info(f"Resolved hostnames: {[h['hostname'] for h in resolved_hostnames[:5]]}")  # Log first 5
                else:
                    logger.info(f"No hostnames resolved for {len(ips)} IPs, returning IPs as domains")
                
                # Return format expected by ip_range_discovery task
                return {
                    "success": True,
                    "resolved_ips": resolved_ips,
                    "total_processed": len(ips),
                    "successful_resolutions": len(resolved_hostnames),
                    "failed_resolutions": len(network_errors)
                }
                
        except Exception as e:
            processing_time = time.time() - start_time
            self.log_processing_error(batch_id, str(e), processing_time)
            
            # Return format expected by ip_range_discovery task
            return {
                "success": False,
                "error": str(e),
                "resolved_ips": [],
                "total_processed": len(ips),
                "successful_resolutions": 0,
                "failed_resolutions": len(ips)
            }

    def ping_hosts_batch(
        self, 
        ips: List[str], 
        batch_id: str,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Ping multiple hosts in parallel using distributed processing
        
        Args:
            ips: List of IP addresses to ping
            batch_id: Unique batch identifier
            **kwargs: Additional parameters
            
        Returns:
            dict: Ping results in format expected by ping_hosts_task
        """
        import time
        from reNgine.utilities.dns import check_host_alive
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        start_time = time.time()
        self.log_processing_start(batch_id, len(ips))
        
        try:
            with self.safe_execution():
                results = {}
                alive_count = 0
                
                # Use ThreadPoolExecutor for parallel ping operations
                with ThreadPoolExecutor(max_workers=min(len(ips), 20)) as executor:
                    # Submit all ping tasks
                    future_to_ip = {executor.submit(check_host_alive, ip): ip for ip in ips}
                    
                    # Collect results as they complete
                    for future in as_completed(future_to_ip):
                        ip = future_to_ip[future]
                        try:
                            is_alive = future.result(timeout=10)
                            results[ip] = is_alive
                            if is_alive:
                                alive_count += 1
                        except Exception as e:
                            logger.debug(f"Ping failed for {ip}: {e}")
                            results[ip] = False
                
                processing_time = time.time() - start_time
                self.log_processing_completion(batch_id, True, processing_time)
                
                # Return format expected by ping_hosts_task
                return {
                    "success": True,
                    "ping_results": results,
                    "alive_count": alive_count,
                    "total_count": len(ips),
                    "processing_time": processing_time
                }
                
        except Exception as e:
            processing_time = time.time() - start_time
            self.log_processing_error(batch_id, str(e), processing_time)
            
            # Return format expected by ping_hosts_task
            return {
                "success": False,
                "error": str(e),
                "ping_results": {},
                "alive_count": 0,
                "total_count": len(ips),
                "processing_time": processing_time
            }

    def reverse_dns_lookup_batch_result(
        self, 
        ips: List[str], 
        batch_id: str,
        **kwargs
    ) -> DistributedNetworkResult:
        """
        Reverse DNS lookup for multiple IPs - returns DistributedNetworkResult object
        
        Args:
            ips: List of IP addresses to resolve
            batch_id: Unique batch identifier
            **kwargs: Additional parameters
            
        Returns:
            DistributedNetworkResult: Result object with detailed information
        """
        import time
        import socket
        
        start_time = time.time()
        self.log_processing_start(batch_id, len(ips))
        
        result = DistributedNetworkResult(
            data={}, 
            status=ProcessingStatus.IN_PROGRESS, 
            batch_id=batch_id
        )
        
        try:
            with self.safe_execution():
                resolved_hostnames = []
                network_errors = []
                
                for ip in ips:
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                        resolved_hostnames.append({
                            "ip": ip,
                            "hostname": hostname,
                            "timestamp": time.time()
                        })
                        result.add_resolved_ip(ip)
                        result.add_resolved_domain(hostname)
                        
                    except (socket.herror, socket.gaierror) as e:
                        error_msg = f"DNS lookup failed for {ip}: {str(e)}"
                        network_errors.append({
                            "ip": ip,
                            "error": str(e),
                            "timestamp": time.time()
                        })
                        result.add_network_error(error_msg)
                    except Exception as e:
                        error_msg = f"Unexpected error for {ip}: {str(e)}"
                        network_errors.append({
                            "ip": ip,
                            "error": f"Unexpected error: {str(e)}",
                            "timestamp": time.time()
                        })
                        result.add_network_error(error_msg)
                
                # Update result
                result.data = {
                    "resolved_hostnames": resolved_hostnames,
                    "network_errors": network_errors,
                    "total_ips": len(ips),
                    "resolved_count": len(resolved_hostnames),
                    "error_count": len(network_errors)
                }
                result.status = ProcessingStatus.COMPLETED
                
                processing_time = time.time() - start_time
                self.log_processing_completion(batch_id, True, processing_time)
                
                return result
                
        except Exception as e:
            processing_time = time.time() - start_time
            self.log_processing_error(batch_id, str(e), processing_time)
            
            result.status = ProcessingStatus.FAILED
            result.data = {
                "error": str(e),
                "resolved_hostnames": [],
                "network_errors": [],
                "total_ips": len(ips),
                "resolved_count": 0,
                "error_count": len(ips)
            }
            return result

    def clear_cache(self) -> None:
        """Clear DNS cache"""
        self.dns_cache.clear()
        self.resolution_history.clear()


class DistributedURLProcessor(DistributedTaskBase):
    """Distributed processor for URL operations"""
    
    def __init__(self, config: Optional[DistributedConfig] = None):
        super().__init__(config)
        self.url_cache: Dict[str, Dict[str, Any]] = {}
        self.validation_history: Dict[str, List[Dict[str, Any]]] = {}
    
    def get_task_name(self) -> str:
        return "distributed_url_processor"
    
    def get_queue_name(self) -> str:
        return "cpu_queue"
    
    def validate_urls_batch(
        self, 
        urls: List[str], 
        batch_id: str,
        allowed_domains: Optional[List[str]] = None,
        **kwargs
    ) -> DistributedNetworkResult:
        """Validate a batch of URLs"""
        start_time = time.time()
        self.log_processing_start(batch_id, len(urls))
        
        result = DistributedNetworkResult(
            data={},
            status=ProcessingStatus.IN_PROGRESS,
            batch_id=batch_id
        )
        
        try:
            with self.safe_execution():
                validated_urls = []
                invalid_urls = []
                network_errors = []
                
                for url in urls:
                    try:
                        # Check cache first
                        if url in self.url_cache:
                            cached_result = self.url_cache[url]
                            if cached_result['valid']:
                                validated_urls.append(url)
                                result.add_validated_url(url)
                            else:
                                invalid_urls.append(url)
                                result.add_invalid_url(url)
                            continue
                        
                        # Validate URL
                        validation_result = self._validate_url(url, allowed_domains)
                        
                        if validation_result['valid']:
                            validated_urls.append(url)
                            result.add_validated_url(url)
                        else:
                            invalid_urls.append(url)
                            result.add_invalid_url(url)
                        
                        # Cache the result
                        self.url_cache[url] = validation_result
                        
                        # Record validation history
                        if url not in self.validation_history:
                            self.validation_history[url] = []
                        self.validation_history[url].append(validation_result)
                        
                    except Exception as e:
                        error_msg = f"Error validating URL {url}: {str(e)}"
                        network_errors.append(error_msg)
                        result.add_network_error(error_msg)
                        logger.error(error_msg)
                
                # Update result
                result.data = {
                    "validated_urls": len(validated_urls),
                    "invalid_urls": len(invalid_urls),
                    "network_errors": len(network_errors),
                    "total_urls": len(urls)
                }
                
                result.network_errors = network_errors
                result.status = ProcessingStatus.FAILED if network_errors else ProcessingStatus.COMPLETED
                result.processing_time = time.time() - start_time
                
        except Exception as e:
            result.status = ProcessingStatus.FAILED
            result.network_errors = [str(e)]
            result.processing_time = time.time() - start_time
            logger.error(f"Batch URL validation failed for {batch_id}: {e}")
        
        self.log_processing_completion(batch_id, result.is_successful, result.processing_time)
        return result
    
    def _validate_url(self, url: str, allowed_domains: Optional[List[str]] = None) -> Dict[str, Any]:
        """Validate a single URL"""
        try:
            # Sanitize URL
            sanitized_url = sanitize_url(url)
            
            # Basic URL validation
            if not is_valid_url(sanitized_url):
                return {
                    "valid": False,
                    "url": url,
                    "sanitized_url": sanitized_url,
                    "error": "Invalid URL format"
                }
            
            # Parse URL
            parsed_url = parse_url(sanitized_url)
            domain = parsed_url['netloc'] if parsed_url else None
            
            # Check if domain is allowed
            if allowed_domains and not is_target_allowed_for_domain(domain, allowed_domains):
                return {
                    "valid": False,
                    "url": url,
                    "sanitized_url": sanitized_url,
                    "domain": domain,
                    "error": "Domain not allowed"
                }
            
            # Extract domain information
            extracted = tldextract.extract(domain)
            
            return {
                "valid": True,
                "url": url,
                "sanitized_url": sanitized_url,
                "domain": domain,
                "subdomain": extracted.subdomain,
                "domain_name": extracted.domain,
                "suffix": extracted.suffix,
                "scheme": parsed_url.scheme,
                "path": parsed_url.path,
                "query": parsed_url.query,
                "fragment": parsed_url.fragment
            }
            
        except Exception as e:
            return {
                "valid": False,
                "url": url,
                "error": str(e)
            }
    
    def get_validation_history(self, url: str) -> List[Dict[str, Any]]:
        """Get validation history for a URL"""
        return self.validation_history.get(url, [])
    
    def clear_cache(self) -> None:
        """Clear URL cache"""
        self.url_cache.clear()
        self.validation_history.clear()


class DistributedPortProcessor(DistributedTaskBase):
    """Distributed processor for port operations"""
    
    def __init__(self, config: Optional[DistributedConfig] = None):
        super().__init__(config)
        self.port_cache: Dict[str, List[int]] = {}
        self.scan_history: Dict[str, List[Dict[str, Any]]] = {}
    
    def get_task_name(self) -> str:
        return "distributed_port_processor"
    
    def get_queue_name(self) -> str:
        return "io_queue"
    
    def scan_ports_batch(
        self, 
        targets: List[Dict[str, Any]], 
        batch_id: str,
        ports: Optional[List[int]] = None,
        timeout: float = 1.0,
        **kwargs
    ) -> DistributedNetworkResult:
        """Scan ports for a batch of targets"""
        start_time = time.time()
        self.log_processing_start(batch_id, len(targets))
        
        result = DistributedNetworkResult(
            data={},
            status=ProcessingStatus.IN_PROGRESS,
            batch_id=batch_id
        )
        
        if ports is None:
            ports = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995]
        
        try:
            with self.safe_execution():
                open_ports = []
                closed_ports = []
                network_errors = []
                
                for target in targets:
                    try:
                        host = target.get('host')
                        if not host:
                            continue
                        
                        # Check cache first
                        cache_key = f"{host}:{','.join(map(str, ports))}"
                        if cache_key in self.port_cache:
                            cached_ports = self.port_cache[cache_key]
                            open_ports.extend([{"host": host, "port": port} for port in cached_ports])
                            continue
                        
                        # Scan ports for this host
                        scan_result = self._scan_host_ports(host, ports, timeout)
                        
                        if scan_result['success']:
                            open_ports.extend(scan_result['open_ports'])
                            closed_ports.extend(scan_result['closed_ports'])
                            
                            # Cache the result
                            self.port_cache[cache_key] = [port['port'] for port in scan_result['open_ports']]
                            
                            # Record scan history
                            self.scan_history[host] = scan_result
                        else:
                            network_errors.append(f"Failed to scan {host}: {scan_result['error']}")
                            result.add_network_error(f"Failed to scan {host}: {scan_result['error']}")
                        
                    except Exception as e:
                        error_msg = f"Error scanning target {target}: {str(e)}"
                        network_errors.append(error_msg)
                        result.add_network_error(error_msg)
                        logger.error(error_msg)
                
                # Update result
                result.data = {
                    "open_ports": len(open_ports),
                    "closed_ports": len(closed_ports),
                    "network_errors": len(network_errors),
                    "total_targets": len(targets)
                }
                
                result.network_errors = network_errors
                result.status = ProcessingStatus.FAILED if network_errors else ProcessingStatus.COMPLETED
                result.processing_time = time.time() - start_time
                
        except Exception as e:
            result.status = ProcessingStatus.FAILED
            result.network_errors = [str(e)]
            result.processing_time = time.time() - start_time
            logger.error(f"Batch port scanning failed for {batch_id}: {e}")
        
        self.log_processing_completion(batch_id, result.is_successful, result.processing_time)
        return result
    
    def _scan_host_ports(self, host: str, ports: List[int], timeout: float) -> Dict[str, Any]:
        """Scan ports for a single host"""
        try:
            open_ports = []
            closed_ports = []
            
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    result = sock.connect_ex((host, port))
                    sock.close()
                    
                    if result == 0:
                        open_ports.append({"host": host, "port": port, "status": "open"})
                    else:
                        closed_ports.append({"host": host, "port": port, "status": "closed"})
                        
                except Exception as e:
                    closed_ports.append({"host": host, "port": port, "status": "error", "error": str(e)})
            
            return {
                "success": True,
                "host": host,
                "open_ports": open_ports,
                "closed_ports": closed_ports,
                "total_ports": len(ports)
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "host": host,
                "open_ports": [],
                "closed_ports": []
            }
    
    def get_scan_history(self, host: str) -> List[Dict[str, Any]]:
        """Get scan history for a host"""
        return self.scan_history.get(host, [])
    
    def clear_cache(self) -> None:
        """Clear port cache"""
        self.port_cache.clear()
        self.scan_history.clear()


# Utility functions for distributed network operations

def create_distributed_dns_processor(
    batch_size: int = 15,
    worker_timeout: int = 300,
    **kwargs
) -> DistributedDNSProcessor:
    """Create a distributed DNS processor with common defaults"""
    config = create_distributed_config(
        batch_size=batch_size,
        worker_timeout=worker_timeout,
        **kwargs
    )
    return DistributedDNSProcessor(config)


def create_distributed_url_processor(
    batch_size: int = 15,
    worker_timeout: int = 300,
    **kwargs
) -> DistributedURLProcessor:
    """Create a distributed URL processor with common defaults"""
    config = create_distributed_config(
        batch_size=batch_size,
        worker_timeout=worker_timeout,
        **kwargs
    )
    return DistributedURLProcessor(config)


def create_distributed_port_processor(
    batch_size: int = 15,
    worker_timeout: int = 300,
    **kwargs
) -> DistributedPortProcessor:
    """Create a distributed port processor with common defaults"""
    config = create_distributed_config(
        batch_size=batch_size,
        worker_timeout=worker_timeout,
        **kwargs
    )
    return DistributedPortProcessor(config)


def resolve_domains_distributed(
    domains: List[str],
    processor: Optional[DistributedDNSProcessor] = None,
    record_types: List[str] = None,
    **kwargs
) -> Dict[str, Any]:
    """Resolve domains in a distributed manner"""
    if not validate_distributed_input(domains):
        return {"success": False, "error": "Invalid input"}
    
    if processor is None:
        processor = create_distributed_dns_processor()
    
    if record_types is None:
        record_types = ["A", "AAAA"]
    
    # Create batch tasks
    batch_tasks = create_batch_tasks(
        domains,
        processor.resolve_domains_batch,
        processor.config.batch_size,
        record_types=record_types,
        **kwargs
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
        logger.error(f"Distributed DNS resolution failed: {e}")
        return {"success": False, "error": str(e)}


def validate_urls_distributed(
    urls: List[str],
    processor: Optional[DistributedURLProcessor] = None,
    allowed_domains: Optional[List[str]] = None,
    **kwargs
) -> Dict[str, Any]:
    """Validate URLs in a distributed manner"""
    if not validate_distributed_input(urls):
        return {"success": False, "error": "Invalid input"}
    
    if processor is None:
        processor = create_distributed_url_processor()
    
    # Create batch tasks
    batch_tasks = create_batch_tasks(
        urls,
        processor.validate_urls_batch,
        processor.config.batch_size,
        allowed_domains=allowed_domains,
        **kwargs
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
        logger.error(f"Distributed URL validation failed: {e}")
        return {"success": False, "error": str(e)}


def scan_ports_distributed(
    targets: List[Dict[str, Any]],
    processor: Optional[DistributedPortProcessor] = None,
    ports: Optional[List[int]] = None,
    timeout: float = 1.0,
    **kwargs
) -> Dict[str, Any]:
    """Scan ports in a distributed manner"""
    if not validate_distributed_input(targets):
        return {"success": False, "error": "Invalid input"}
    
    if processor is None:
        processor = create_distributed_port_processor()
    
    # Create batch tasks
    batch_tasks = create_batch_tasks(
        targets,
        processor.scan_ports_batch,
        processor.config.batch_size,
        ports=ports,
        timeout=timeout,
        **kwargs
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
        logger.error(f"Distributed port scanning failed: {e}")
        return {"success": False, "error": str(e)}
