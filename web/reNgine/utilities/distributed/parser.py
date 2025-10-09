"""
Distributed parsing utilities.

This module provides distributed parsing capabilities that can be
reused across different task types while following SOLID, KISS, and DRY principles.

Key components:
1. DistributedParserProcessor - Base class for distributed parsing operations
2. DistributedNmapParser - Nmap XML/JSON parsing with distributed support
3. DistributedNucleiParser - Nuclei JSON parsing with distributed support
4. DistributedHttpxParser - Httpx JSON parsing with distributed support
5. DistributedSubfinderParser - Subfinder JSON parsing with distributed support
"""

from reNgine.utilities.core.file import write_json_file
import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Union, Callable
from reNgine.utilities.core.file import join_path, ensure_directory_exists, get_filename_without_extension, file_exists

from celery.utils.log import get_task_logger
import xmltodict

from reNgine.utilities.distributed.base import (
    DistributedParserProcessor,
    DistributedResult,
    ProcessingStatus,
    DistributedConfig,
    create_distributed_config,
    validate_distributed_input,
    create_batch_tasks,
    aggregate_distributed_results
)
from reNgine.definitions import NMAP, NUCLEI_SEVERITY_MAP
from reNgine.utilities.url import sanitize_url

logger = get_task_logger(__name__)


class DistributedParserResult(DistributedResult[Dict[str, Any]]):
    """Result container for distributed parsing operations"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.parsed_items: List[Any] = []
        self.parse_errors: List[str] = []
        self.input_files: List[str] = []
        self.output_files: List[str] = []
    
    def add_parsed_item(self, item: Any) -> None:
        """Add a parsed item to the result"""
        self.parsed_items.append(item)
    
    def add_parse_error(self, error: str) -> None:
        """Add a parse error to the result"""
        self.parse_errors.append(error)
    
    def add_input_file(self, file_path: str) -> None:
        """Add an input file to the result"""
        self.input_files.append(file_path)
    
    def add_output_file(self, file_path: str) -> None:
        """Add an output file to the result"""
        self.output_files.append(file_path)


class DistributedNmapParser(DistributedParserProcessor):
    """Distributed parser for Nmap XML/JSON results"""
    
    def __init__(self, config: Optional[DistributedConfig] = None):
        super().__init__(config)
        self.parsed_hosts: Dict[str, List[Dict[str, Any]]] = {}
    
    def get_task_name(self) -> str:
        return "distributed_nmap_parser"
    
    def parse_nmap_files_batch(
        self, 
        nmap_files: List[str], 
        batch_id: str,
        parse_type: str = "vulnerabilities",
        output_dir: Optional[str] = None,
        **kwargs
    ) -> DistributedParserResult:
        """Parse a batch of Nmap files"""
        start_time = time.time()
        self.log_processing_start(batch_id, len(nmap_files))
        
        result = DistributedParserResult(
            data={},
            status=ProcessingStatus.IN_PROGRESS,
            batch_id=batch_id
        )
        
        try:
            with self.safe_execution():
                parsed_results = []
                parse_errors = []
                
                for nmap_file in nmap_files:
                    try:
                        if not file_exists(nmap_file):
                            error_msg = f"Nmap file not found: {nmap_file}"
                            parse_errors.append(error_msg)
                            result.add_parse_error(error_msg)
                            continue
                        
                        result.add_input_file(nmap_file)
                        
                        # Parse the file
                        file_results = self._parse_nmap_file(nmap_file, parse_type, output_dir)
                        parsed_results.extend(file_results)
                        
                        # Record parsed items
                        for item in file_results:
                            result.add_parsed_item(item)
                        
                        self.record_parsed_item(batch_id, f"Parsed {len(file_results)} items from {nmap_file}")
                        
                    except Exception as e:
                        error_msg = f"Error parsing Nmap file {nmap_file}: {str(e)}"
                        parse_errors.append(error_msg)
                        result.add_parse_error(error_msg)
                        logger.error(error_msg)
                
                # Update result
                result.data = {
                    "parsed_files": len(nmap_files),
                    "parsed_items": len(parsed_results),
                    "parse_errors": len(parse_errors),
                    "parse_type": parse_type
                }
                
                result.parse_errors = parse_errors
                result.status = ProcessingStatus.COMPLETED if not parse_errors else ProcessingStatus.FAILED
                result.processing_time = time.time() - start_time
                
        except Exception as e:
            result.status = ProcessingStatus.FAILED
            result.parse_errors = [str(e)]
            result.processing_time = time.time() - start_time
            logger.error(f"Batch Nmap parsing failed for {batch_id}: {e}")
        
        self.log_processing_completion(batch_id, result.is_successful, result.processing_time)
        return result
    
    def _parse_nmap_file(self, xml_file: str, parse_type: str, output_dir: Optional[str] = None) -> List[Dict[str, Any]]:
        """Parse a single Nmap XML file"""
        try:
            with open(xml_file, encoding="utf8") as f:
                content = f.read()
                nmap_results = xmltodict.parse(content)
        except Exception as e:
            logger.error(f"Cannot parse {xml_file} to valid JSON: {e}")
            return []
        
        # Save parsed JSON if output directory is specified
        if output_dir:
            output_file = join_path(output_dir, f"{get_filename_without_extension(xml_file)}_parsed.json")
            ensure_directory_exists(output_dir)
            write_json_file(output_file, nmap_results, indent=4)
        
        hosts = nmap_results.get("nmaprun", {}).get("host", {})
        if not hosts:
            return []
        
        # Ensure hosts is a list
        hosts = [hosts] if not isinstance(hosts, list) else hosts
        
        results = []
        for host in hosts:
            if parse_type == "vulnerabilities":
                results.extend(self._parse_nmap_vulnerabilities(host))
            elif parse_type == "services":
                results.extend(self._parse_nmap_services(host))
            elif parse_type == "ports":
                results.extend(self._parse_nmap_ports(host))
            else:
                logger.warning(f"Unknown parse type: {parse_type}")
        
        return results
    
    def _parse_nmap_vulnerabilities(self, host: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse vulnerabilities from Nmap host data"""
        vulnerabilities = []
        
        address_info = host.get("address", {})
        address_info = [address_info] if not isinstance(address_info, list) else address_info
        
        host_ip = None
        for addr in address_info:
            if addr.get("@addrtype") == "ipv4":
                host_ip = addr.get("@addr")
                break
        
        if not host_ip:
            return vulnerabilities
        
        ports = host.get("ports", {}).get("port", [])
        ports = [ports] if not isinstance(ports, list) else ports
        
        for port in ports:
            port_id = port.get("@portid")
            port_protocol = port.get("@protocol")
            
            scripts = port.get("script", [])
            scripts = [scripts] if not isinstance(scripts, list) else scripts
            
            for script in scripts:
                script_id = script.get("@id")
                script_output = script.get("@output", "")
                
                if script_id in ["vuln", "vulners", "exploit"]:
                    vuln_data = {
                        "host": host_ip,
                        "port": port_id,
                        "protocol": port_protocol,
                        "script_id": script_id,
                        "output": script_output,
                        "type": "nmap_vulnerability"
                    }
                    vulnerabilities.append(vuln_data)
        
        return vulnerabilities
    
    def _parse_nmap_services(self, host: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse services from Nmap host data"""
        services = []
        
        address_info = host.get("address", {})
        address_info = [address_info] if not isinstance(address_info, list) else address_info
        
        host_ip = None
        for addr in address_info:
            if addr.get("@addrtype") == "ipv4":
                host_ip = addr.get("@addr")
                break
        
        if not host_ip:
            return services
        
        ports = host.get("ports", {}).get("port", [])
        ports = [ports] if not isinstance(ports, list) else ports
        
        for port in ports:
            port_id = port.get("@portid")
            port_protocol = port.get("@protocol")
            port_state = port.get("state", {}).get("@state")
            
            if port_state == "open":
                service = port.get("service", {})
                service_data = {
                    "host": host_ip,
                    "port": port_id,
                    "protocol": port_protocol,
                    "state": port_state,
                    "service_name": service.get("@name", ""),
                    "service_product": service.get("@product", ""),
                    "service_version": service.get("@version", ""),
                    "service_extra_info": service.get("@extrainfo", ""),
                    "type": "nmap_service"
                }
                services.append(service_data)
        
        return services
    
    def _parse_nmap_ports(self, host: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse ports from Nmap host data"""
        ports = []
        
        address_info = host.get("address", {})
        address_info = [address_info] if not isinstance(address_info, list) else address_info
        
        host_ip = None
        for addr in address_info:
            if addr.get("@addrtype") == "ipv4":
                host_ip = addr.get("@addr")
                break
        
        if not host_ip:
            return ports
        
        port_list = host.get("ports", {}).get("port", [])
        if not isinstance(port_list, list):
            port_list = [port_list]
        
        for port in port_list:
            port_id = port.get("@portid")
            port_protocol = port.get("@protocol")
            port_state = port.get("state", {}).get("@state")
            
            port_data = {
                "host": host_ip,
                "port": port_id,
                "protocol": port_protocol,
                "state": port_state,
                "type": "nmap_port"
            }
            ports.append(port_data)
        
        return ports


class DistributedNucleiParser(DistributedParserProcessor):
    """Distributed parser for Nuclei JSON results"""
    
    def __init__(self, config: Optional[DistributedConfig] = None):
        super().__init__(config)
        self.parsed_vulnerabilities: Dict[str, List[Dict[str, Any]]] = {}
    
    def get_task_name(self) -> str:
        return "distributed_nuclei_parser"
    
    def parse_nuclei_files_batch(
        self, 
        nuclei_files: List[str], 
        batch_id: str,
        output_dir: Optional[str] = None,
        **kwargs
    ) -> DistributedParserResult:
        """Parse a batch of Nuclei JSON files"""
        start_time = time.time()
        self.log_processing_start(batch_id, len(nuclei_files))
        
        result = DistributedParserResult(
            data={},
            status=ProcessingStatus.IN_PROGRESS,
            batch_id=batch_id
        )
        
        try:
            with self.safe_execution():
                parsed_results = []
                parse_errors = []
                
                for nuclei_file in nuclei_files:
                    try:
                        if not file_exists(nuclei_file):
                            error_msg = f"Nuclei file not found: {nuclei_file}"
                            parse_errors.append(error_msg)
                            result.add_parse_error(error_msg)
                            continue
                        
                        result.add_input_file(nuclei_file)
                        
                        # Parse the file
                        file_results = self._parse_nuclei_file(nuclei_file, output_dir)
                        parsed_results.extend(file_results)
                        
                        # Record parsed items
                        for item in file_results:
                            result.add_parsed_item(item)
                        
                        self.record_parsed_item(batch_id, f"Parsed {len(file_results)} vulnerabilities from {nuclei_file}")
                        
                    except Exception as e:
                        error_msg = f"Error parsing Nuclei file {nuclei_file}: {str(e)}"
                        parse_errors.append(error_msg)
                        result.add_parse_error(error_msg)
                        logger.error(error_msg)
                
                # Update result
                result.data = {
                    "parsed_files": len(nuclei_files),
                    "parsed_vulnerabilities": len(parsed_results),
                    "parse_errors": len(parse_errors)
                }
                
                result.parse_errors = parse_errors
                result.status = ProcessingStatus.COMPLETED if not parse_errors else ProcessingStatus.FAILED
                result.processing_time = time.time() - start_time
                
        except Exception as e:
            result.status = ProcessingStatus.FAILED
            result.parse_errors = [str(e)]
            result.processing_time = time.time() - start_time
            logger.error(f"Batch Nuclei parsing failed for {batch_id}: {e}")
        
        self.log_processing_completion(batch_id, result.is_successful, result.processing_time)
        return result
    
    def _parse_nuclei_file(self, json_file: str, output_dir: Optional[str] = None) -> List[Dict[str, Any]]:
        """Parse a single Nuclei JSON file"""
        vulnerabilities = []
        
        try:
            with open(json_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        import json
                        vuln_data = json.loads(line)
                        parsed_vuln = self._parse_nuclei_vulnerability(vuln_data)
                        if parsed_vuln:
                            vulnerabilities.append(parsed_vuln)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logger.error(f"Error reading Nuclei file {json_file}: {e}")
            return []
        
        # Save parsed results if output directory is specified
        if output_dir and vulnerabilities:
            output_file = join_path(output_dir, f"{get_filename_without_extension(json_file)}_parsed.json")
            ensure_directory_exists(output_dir)
            write_json_file(output_file, vulnerabilities, indent=4)
        
        return vulnerabilities
    
    def _parse_nuclei_vulnerability(self, vuln_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a single Nuclei vulnerability"""
        try:
            # Extract basic information
            template_id = vuln_data.get("template-id", "")
            template_name = vuln_data.get("info", {}).get("name", "")
            severity = vuln_data.get("info", {}).get("severity", "info")
            description = vuln_data.get("info", {}).get("description", "")
            
            # Extract target information
            matched_at = vuln_data.get("matched-at", "")
            host = vuln_data.get("host", "")
            url = vuln_data.get("url", "")
            
            # Extract request/response information
            request = vuln_data.get("request", "")
            response = vuln_data.get("response", "")
            
            # Extract metadata
            metadata = vuln_data.get("info", {}).get("metadata", {})
            tags = vuln_data.get("info", {}).get("tags", [])
            
            # Create vulnerability data
            vulnerability = {
                "template_id": template_id,
                "template_name": template_name,
                "severity": severity,
                "description": description,
                "matched_at": matched_at,
                "host": host,
                "url": url,
                "request": request,
                "response": response,
                "metadata": metadata,
                "tags": tags,
                "type": "nuclei_vulnerability"
            }
            
            return vulnerability
            
        except Exception as e:
            logger.error(f"Error parsing Nuclei vulnerability: {e}")
            return None


class DistributedHttpxParser(DistributedParserProcessor):
    """Distributed parser for Httpx JSON results"""
    
    def __init__(self, config: Optional[DistributedConfig] = None):
        super().__init__(config)
        self.parsed_endpoints: Dict[str, List[Dict[str, Any]]] = {}
    
    def get_task_name(self) -> str:
        return "distributed_httpx_parser"
    
    def parse_httpx_files_batch(
        self, 
        httpx_files: List[str], 
        batch_id: str,
        output_dir: Optional[str] = None,
        **kwargs
    ) -> DistributedParserResult:
        """Parse a batch of Httpx JSON files"""
        start_time = time.time()
        self.log_processing_start(batch_id, len(httpx_files))
        
        result = DistributedParserResult(
            data={},
            status=ProcessingStatus.IN_PROGRESS,
            batch_id=batch_id
        )
        
        try:
            with self.safe_execution():
                parsed_results = []
                parse_errors = []
                
                for httpx_file in httpx_files:
                    try:
                        if not file_exists(httpx_file):
                            error_msg = f"Httpx file not found: {httpx_file}"
                            parse_errors.append(error_msg)
                            result.add_parse_error(error_msg)
                            continue
                        
                        result.add_input_file(httpx_file)
                        
                        # Parse the file
                        file_results = self._parse_httpx_file(httpx_file, output_dir)
                        parsed_results.extend(file_results)
                        
                        # Record parsed items
                        for item in file_results:
                            result.add_parsed_item(item)
                        
                        self.record_parsed_item(batch_id, f"Parsed {len(file_results)} endpoints from {httpx_file}")
                        
                    except Exception as e:
                        error_msg = f"Error parsing Httpx file {httpx_file}: {str(e)}"
                        parse_errors.append(error_msg)
                        result.add_parse_error(error_msg)
                        logger.error(error_msg)
                
                # Update result
                result.data = {
                    "parsed_files": len(httpx_files),
                    "parsed_endpoints": len(parsed_results),
                    "parse_errors": len(parse_errors)
                }
                
                result.parse_errors = parse_errors
                result.status = ProcessingStatus.COMPLETED if not parse_errors else ProcessingStatus.FAILED
                result.processing_time = time.time() - start_time
                
        except Exception as e:
            result.status = ProcessingStatus.FAILED
            result.parse_errors = [str(e)]
            result.processing_time = time.time() - start_time
            logger.error(f"Batch Httpx parsing failed for {batch_id}: {e}")
        
        self.log_processing_completion(batch_id, result.is_successful, result.processing_time)
        return result
    
    def _parse_httpx_file(self, json_file: str, output_dir: Optional[str] = None) -> List[Dict[str, Any]]:
        """Parse a single Httpx JSON file"""
        endpoints = []
        
        try:
            with open(json_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        import json
                        endpoint_data = json.loads(line)
                        parsed_endpoint = self._parse_httpx_endpoint(endpoint_data)
                        if parsed_endpoint:
                            endpoints.append(parsed_endpoint)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logger.error(f"Error reading Httpx file {json_file}: {e}")
            return []
        
        # Save parsed results if output directory is specified
        if output_dir and endpoints:
            output_file = join_path(output_dir, f"{get_filename_without_extension(json_file)}_parsed.json")
            ensure_directory_exists(output_dir)
            write_json_file(output_file, endpoints, indent=4)
        
        return endpoints
    
    def _parse_httpx_endpoint(self, endpoint_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a single Httpx endpoint"""
        try:
            # Extract basic information
            url = endpoint_data.get("url", "")
            host = endpoint_data.get("host", "")
            port = endpoint_data.get("port", "")
            status_code = endpoint_data.get("status-code", 0)
            
            # Extract content information
            content_length = endpoint_data.get("content-length", 0)
            content_type = endpoint_data.get("content-type", "")
            title = endpoint_data.get("title", "")
            
            # Extract server information
            webserver = endpoint_data.get("webserver", "")
            tech = endpoint_data.get("tech", [])
            
            # Extract network information
            response_time = endpoint_data.get("time", "")
            cname = endpoint_data.get("cname", [])
            asn = endpoint_data.get("asn", "")
            cdn = endpoint_data.get("cdn", False)
            
            # Extract IP information
            ip = endpoint_data.get("ip", "")
            a_records = endpoint_data.get("a", [])
            
            # Create endpoint data
            endpoint = {
                "url": url,
                "host": host,
                "port": port,
                "status_code": status_code,
                "content_length": content_length,
                "content_type": content_type,
                "title": title,
                "webserver": webserver,
                "tech": tech,
                "response_time": response_time,
                "cname": cname,
                "asn": asn,
                "cdn": cdn,
                "ip": ip,
                "a_records": a_records,
                "type": "httpx_endpoint"
            }
            
            return endpoint
            
        except Exception as e:
            logger.error(f"Error parsing Httpx endpoint: {e}")
            return None


# Utility functions for distributed parsing

def create_distributed_nmap_parser(
    batch_size: int = 15,
    worker_timeout: int = 300,
    **kwargs
) -> DistributedNmapParser:
    """Create a distributed Nmap parser with common defaults"""
    config = create_distributed_config(
        batch_size=batch_size,
        worker_timeout=worker_timeout,
        **kwargs
    )
    return DistributedNmapParser(config)


def create_distributed_nuclei_parser(
    batch_size: int = 15,
    worker_timeout: int = 300,
    **kwargs
) -> DistributedNucleiParser:
    """Create a distributed Nuclei parser with common defaults"""
    config = create_distributed_config(
        batch_size=batch_size,
        worker_timeout=worker_timeout,
        **kwargs
    )
    return DistributedNucleiParser(config)


def create_distributed_httpx_parser(
    batch_size: int = 15,
    worker_timeout: int = 300,
    **kwargs
) -> DistributedHttpxParser:
    """Create a distributed Httpx parser with common defaults"""
    config = create_distributed_config(
        batch_size=batch_size,
        worker_timeout=worker_timeout,
        **kwargs
    )
    return DistributedHttpxParser(config)


def parse_nmap_files_distributed(
    nmap_files: List[str],
    parser: Optional[DistributedNmapParser] = None,
    parse_type: str = "vulnerabilities",
    output_dir: Optional[str] = None,
    **kwargs
) -> Dict[str, Any]:
    """Parse Nmap files in a distributed manner"""
    if not validate_distributed_input(nmap_files):
        return {"success": False, "error": "Invalid input"}
    
    if parser is None:
        parser = create_distributed_nmap_parser()
    
    # Create batch tasks
    batch_tasks = create_batch_tasks(
        nmap_files,
        parser.parse_nmap_files_batch,
        parser.config.batch_size,
        parse_type=parse_type,
        output_dir=output_dir,
        **kwargs
    )
    
    if not batch_tasks:
        return {"success": False, "error": "No batch tasks created"}
    
    # Execute batches in parallel
    try:
        from reNgine.utilities.deadlock_prevention import safe_group_execution
        results = safe_group_execution(batch_tasks, parser.config.worker_timeout * len(batch_tasks))
        
        # Aggregate results
        return aggregate_distributed_results(results)
    except Exception as e:
        logger.error(f"Distributed Nmap parsing failed: {e}")
        return {"success": False, "error": str(e)}


def parse_nuclei_files_distributed(
    nuclei_files: List[str],
    parser: Optional[DistributedNucleiParser] = None,
    output_dir: Optional[str] = None,
    **kwargs
) -> Dict[str, Any]:
    """Parse Nuclei files in a distributed manner"""
    if not validate_distributed_input(nuclei_files):
        return {"success": False, "error": "Invalid input"}
    
    if parser is None:
        parser = create_distributed_nuclei_parser()
    
    # Create batch tasks
    batch_tasks = create_batch_tasks(
        nuclei_files,
        parser.parse_nuclei_files_batch,
        parser.config.batch_size,
        output_dir=output_dir,
        **kwargs
    )
    
    if not batch_tasks:
        return {"success": False, "error": "No batch tasks created"}
    
    # Execute batches in parallel
    try:
        from reNgine.utilities.deadlock_prevention import safe_group_execution
        results = safe_group_execution(batch_tasks, parser.config.worker_timeout * len(batch_tasks))
        
        # Aggregate results
        return aggregate_distributed_results(results)
    except Exception as e:
        logger.error(f"Distributed Nuclei parsing failed: {e}")
        return {"success": False, "error": str(e)}


def parse_httpx_files_distributed(
    httpx_files: List[str],
    parser: Optional[DistributedHttpxParser] = None,
    output_dir: Optional[str] = None,
    **kwargs
) -> Dict[str, Any]:
    """Parse Httpx files in a distributed manner"""
    if not validate_distributed_input(httpx_files):
        return {"success": False, "error": "Invalid input"}
    
    if parser is None:
        parser = create_distributed_httpx_parser()
    
    # Create batch tasks
    batch_tasks = create_batch_tasks(
        httpx_files,
        parser.parse_httpx_files_batch,
        parser.config.batch_size,
        output_dir=output_dir,
        **kwargs
    )
    
    if not batch_tasks:
        return {"success": False, "error": "No batch tasks created"}
    
    # Execute batches in parallel
    try:
        from reNgine.utilities.deadlock_prevention import safe_group_execution
        results = safe_group_execution(batch_tasks, parser.config.worker_timeout * len(batch_tasks))
        
        # Aggregate results
        return aggregate_distributed_results(results)
    except Exception as e:
        logger.error(f"Distributed Httpx parsing failed: {e}")
        return {"success": False, "error": str(e)}
