"""
Main distributed utilities module.

This module provides a unified interface for all distributed utilities,
making it easy to use distributed processing across different task types
while following SOLID, KISS, and DRY principles.

Key components:
1. DistributedUtilities - Main class for accessing all distributed utilities
2. Utility factory functions for easy creation of distributed processors
3. Unified configuration management
4. Common utility functions for distributed operations
"""

from typing import Any, Dict, List, Optional, Union, Type, TypeVar
from enum import Enum

from reNgine.utilities.distributed.base import (
    DistributedConfig,
    DistributedTaskBase,
    create_distributed_config,
    validate_distributed_input,
    create_batch_tasks,
    aggregate_distributed_results
)
from reNgine.utilities.distributed.command import (
    DistributedCommandExecutor,
    create_distributed_command_executor,
    execute_commands_distributed,
    execute_nmap_distributed,
    execute_httpx_distributed,
    execute_subfinder_distributed
)
from reNgine.utilities.distributed.database import (
    DistributedEndpointProcessor,
    DistributedSubdomainProcessor,
    DistributedIPProcessor,
    create_distributed_endpoint_processor,
    create_distributed_subdomain_processor,
    create_distributed_ip_processor,
    process_endpoints_distributed,
    process_subdomains_distributed,
    process_ips_distributed
)
from reNgine.utilities.distributed.parser import (
    DistributedNmapParser,
    DistributedNucleiParser,
    DistributedHttpxParser,
    create_distributed_nmap_parser,
    create_distributed_nuclei_parser,
    create_distributed_httpx_parser,
    parse_nmap_files_distributed,
    parse_nuclei_files_distributed,
    parse_httpx_files_distributed
)
from reNgine.utilities.distributed.network import (
    DistributedDNSProcessor,
    DistributedURLProcessor,
    DistributedPortProcessor,
    create_distributed_dns_processor,
    create_distributed_url_processor,
    create_distributed_port_processor,
    resolve_domains_distributed,
    validate_urls_distributed,
    scan_ports_distributed
)

T = TypeVar('T', bound=DistributedTaskBase)


class ProcessorType(Enum):
    """Types of distributed processors"""
    COMMAND = "command"
    ENDPOINT = "endpoint"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    NMAP_PARSER = "nmap_parser"
    NUCLEI_PARSER = "nuclei_parser"
    HTTPX_PARSER = "httpx_parser"
    DNS = "dns"
    URL = "url"
    PORT = "port"


class DistributedUtilities:
    """Main class for accessing all distributed utilities"""
    
    def __init__(self, config: Optional[DistributedConfig] = None):
        self.config = config or create_distributed_config()
        self._processors: Dict[ProcessorType, DistributedTaskBase] = {}
        self._initialized = False
    
    def initialize(self) -> None:
        """Initialize all distributed processors"""
        if self._initialized:
            return
        
        # Initialize command processors
        self._processors[ProcessorType.COMMAND] = create_distributed_command_executor(
            batch_size=self.config.batch_size,
            worker_timeout=self.config.worker_timeout
        )
        
        # Initialize database processors
        self._processors[ProcessorType.ENDPOINT] = create_distributed_endpoint_processor(
            batch_size=self.config.batch_size,
            worker_timeout=self.config.worker_timeout
        )
        
        self._processors[ProcessorType.SUBDOMAIN] = create_distributed_subdomain_processor(
            batch_size=self.config.batch_size,
            worker_timeout=self.config.worker_timeout
        )
        
        self._processors[ProcessorType.IP] = create_distributed_ip_processor(
            batch_size=self.config.batch_size,
            worker_timeout=self.config.worker_timeout
        )
        
        # Initialize parser processors
        self._processors[ProcessorType.NMAP_PARSER] = create_distributed_nmap_parser(
            batch_size=self.config.batch_size,
            worker_timeout=self.config.worker_timeout
        )
        
        self._processors[ProcessorType.NUCLEI_PARSER] = create_distributed_nuclei_parser(
            batch_size=self.config.batch_size,
            worker_timeout=self.config.worker_timeout
        )
        
        self._processors[ProcessorType.HTTPX_PARSER] = create_distributed_httpx_parser(
            batch_size=self.config.batch_size,
            worker_timeout=self.config.worker_timeout
        )
        
        # Initialize network processors
        self._processors[ProcessorType.DNS] = create_distributed_dns_processor(
            batch_size=self.config.batch_size,
            worker_timeout=self.config.worker_timeout
        )
        
        self._processors[ProcessorType.URL] = create_distributed_url_processor(
            batch_size=self.config.batch_size,
            worker_timeout=self.config.worker_timeout
        )
        
        self._processors[ProcessorType.PORT] = create_distributed_port_processor(
            batch_size=self.config.batch_size,
            worker_timeout=self.config.worker_timeout
        )
        
        self._initialized = True
    
    def get_processor(self, processor_type: ProcessorType) -> Optional[DistributedTaskBase]:
        """Get a specific processor"""
        if not self._initialized:
            self.initialize()
        
        return self._processors.get(processor_type)
    
    def get_command_processor(self) -> DistributedCommandExecutor:
        """Get the command processor"""
        processor = self.get_processor(ProcessorType.COMMAND)
        if not isinstance(processor, DistributedCommandExecutor):
            raise ValueError("Command processor not available")
        return processor
    
    def get_endpoint_processor(self) -> DistributedEndpointProcessor:
        """Get the endpoint processor"""
        processor = self.get_processor(ProcessorType.ENDPOINT)
        if not isinstance(processor, DistributedEndpointProcessor):
            raise ValueError("Endpoint processor not available")
        return processor
    
    def get_subdomain_processor(self) -> DistributedSubdomainProcessor:
        """Get the subdomain processor"""
        processor = self.get_processor(ProcessorType.SUBDOMAIN)
        if not isinstance(processor, DistributedSubdomainProcessor):
            raise ValueError("Subdomain processor not available")
        return processor
    
    def get_ip_processor(self) -> DistributedIPProcessor:
        """Get the IP processor"""
        processor = self.get_processor(ProcessorType.IP)
        if not isinstance(processor, DistributedIPProcessor):
            raise ValueError("IP processor not available")
        return processor
    
    def get_nmap_parser(self) -> DistributedNmapParser:
        """Get the Nmap parser"""
        processor = self.get_processor(ProcessorType.NMAP_PARSER)
        if not isinstance(processor, DistributedNmapParser):
            raise ValueError("Nmap parser not available")
        return processor
    
    def get_nuclei_parser(self) -> DistributedNucleiParser:
        """Get the Nuclei parser"""
        processor = self.get_processor(ProcessorType.NUCLEI_PARSER)
        if not isinstance(processor, DistributedNucleiParser):
            raise ValueError("Nuclei parser not available")
        return processor
    
    def get_httpx_parser(self) -> DistributedHttpxParser:
        """Get the Httpx parser"""
        processor = self.get_processor(ProcessorType.HTTPX_PARSER)
        if not isinstance(processor, DistributedHttpxParser):
            raise ValueError("Httpx parser not available")
        return processor
    
    def get_dns_processor(self) -> DistributedDNSProcessor:
        """Get the DNS processor"""
        processor = self.get_processor(ProcessorType.DNS)
        if not isinstance(processor, DistributedDNSProcessor):
            raise ValueError("DNS processor not available")
        return processor
    
    def get_url_processor(self) -> DistributedURLProcessor:
        """Get the URL processor"""
        processor = self.get_processor(ProcessorType.URL)
        if not isinstance(processor, DistributedURLProcessor):
            raise ValueError("URL processor not available")
        return processor
    
    def get_port_processor(self) -> DistributedPortProcessor:
        """Get the port processor"""
        processor = self.get_processor(ProcessorType.PORT)
        if not isinstance(processor, DistributedPortProcessor):
            raise ValueError("Port processor not available")
        return processor
    
    def update_config(self, new_config: DistributedConfig) -> None:
        """Update configuration for all processors"""
        self.config = new_config
        self._initialized = False  # Force re-initialization
        self.initialize()
    
    def get_config(self) -> DistributedConfig:
        """Get current configuration"""
        return self.config
    
    def clear_all_caches(self) -> None:
        """Clear all processor caches"""
        for processor in self._processors.values():
            if hasattr(processor, 'clear_cache'):
                processor.clear_cache()
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get metrics summary from all processors"""
        summary = {
            "total_processors": len(self._processors),
            "config": {
                "batch_size": self.config.batch_size,
                "worker_timeout": self.config.worker_timeout,
                "max_retries": self.config.max_retries
            },
            "processors": {}
        }
        
        for processor_type, processor in self._processors.items():
            if hasattr(processor, 'metrics') and processor.metrics:
                summary["processors"][processor_type.value] = processor.metrics.get_summary()
        
        return summary


# Global instance for easy access
_distributed_utilities: Optional[DistributedUtilities] = None


def get_distributed_utilities(config: Optional[DistributedConfig] = None) -> DistributedUtilities:
    """Get the global distributed utilities instance"""
    global _distributed_utilities
    
    if _distributed_utilities is None:
        _distributed_utilities = DistributedUtilities(config)
        _distributed_utilities.initialize()
    
    return _distributed_utilities


def reset_distributed_utilities() -> None:
    """Reset the global distributed utilities instance"""
    global _distributed_utilities
    _distributed_utilities = None


# Factory functions for easy processor creation

def create_processor(
    processor_type: ProcessorType,
    config: Optional[DistributedConfig] = None
) -> DistributedTaskBase:
    """Create a specific processor with the given configuration"""
    if config is None:
        config = create_distributed_config()
    
    if processor_type == ProcessorType.COMMAND:
        return create_distributed_command_executor(
            batch_size=config.batch_size,
            worker_timeout=config.worker_timeout
        )
    elif processor_type == ProcessorType.ENDPOINT:
        return create_distributed_endpoint_processor(
            batch_size=config.batch_size,
            worker_timeout=config.worker_timeout
        )
    elif processor_type == ProcessorType.SUBDOMAIN:
        return create_distributed_subdomain_processor(
            batch_size=config.batch_size,
            worker_timeout=config.worker_timeout
        )
    elif processor_type == ProcessorType.IP:
        return create_distributed_ip_processor(
            batch_size=config.batch_size,
            worker_timeout=config.worker_timeout
        )
    elif processor_type == ProcessorType.NMAP_PARSER:
        return create_distributed_nmap_parser(
            batch_size=config.batch_size,
            worker_timeout=config.worker_timeout
        )
    elif processor_type == ProcessorType.NUCLEI_PARSER:
        return create_distributed_nuclei_parser(
            batch_size=config.batch_size,
            worker_timeout=config.worker_timeout
        )
    elif processor_type == ProcessorType.HTTPX_PARSER:
        return create_distributed_httpx_parser(
            batch_size=config.batch_size,
            worker_timeout=config.worker_timeout
        )
    elif processor_type == ProcessorType.DNS:
        return create_distributed_dns_processor(
            batch_size=config.batch_size,
            worker_timeout=config.worker_timeout
        )
    elif processor_type == ProcessorType.URL:
        return create_distributed_url_processor(
            batch_size=config.batch_size,
            worker_timeout=config.worker_timeout
        )
    elif processor_type == ProcessorType.PORT:
        return create_distributed_port_processor(
            batch_size=config.batch_size,
            worker_timeout=config.worker_timeout
        )
    else:
        raise ValueError(f"Unknown processor type: {processor_type}")


# Convenience functions for common operations

def execute_distributed_commands(
    commands: List[str],
    config: Optional[DistributedConfig] = None,
    **kwargs
) -> Dict[str, Any]:
    """Execute commands in a distributed manner"""
    return execute_commands_distributed(commands, **kwargs)


def process_distributed_endpoints(
    endpoints_data: List[Dict[str, Any]],
    config: Optional[DistributedConfig] = None,
    ctx: Optional[Dict[str, Any]] = None,
    **kwargs
) -> Dict[str, Any]:
    """Process endpoints in a distributed manner"""
    return process_endpoints_distributed(endpoints_data, ctx=ctx, **kwargs)


def parse_distributed_nmap_files(
    nmap_files: List[str],
    config: Optional[DistributedConfig] = None,
    parse_type: str = "vulnerabilities",
    **kwargs
) -> Dict[str, Any]:
    """Parse Nmap files in a distributed manner"""
    return parse_nmap_files_distributed(nmap_files, parse_type=parse_type, **kwargs)


def resolve_distributed_domains(
    domains: List[str],
    config: Optional[DistributedConfig] = None,
    record_types: List[str] = None,
    **kwargs
) -> Dict[str, Any]:
    """Resolve domains in a distributed manner"""
    return resolve_domains_distributed(domains, record_types=record_types, **kwargs)


def validate_distributed_urls(
    urls: List[str],
    config: Optional[DistributedConfig] = None,
    allowed_domains: Optional[List[str]] = None,
    **kwargs
) -> Dict[str, Any]:
    """Validate URLs in a distributed manner"""
    return validate_urls_distributed(urls, allowed_domains=allowed_domains, **kwargs)


# Configuration helpers

def create_high_performance_config() -> DistributedConfig:
    """Create a high-performance configuration"""
    return DistributedConfig(
        batch_size=25,
        max_batch_size=50,
        min_batch_size=10,
        worker_timeout=600,
        max_retries=5,
        retry_delay=15,
        parallel_workers=10,
        enable_retry=True,
        enable_metrics=True
    )


def create_balanced_config() -> DistributedConfig:
    """Create a balanced configuration"""
    return DistributedConfig(
        batch_size=15,
        max_batch_size=25,
        min_batch_size=5,
        worker_timeout=300,
        max_retries=3,
        retry_delay=30,
        parallel_workers=5,
        enable_retry=True,
        enable_metrics=True
    )


def create_conservative_config() -> DistributedConfig:
    """Create a conservative configuration"""
    return DistributedConfig(
        batch_size=10,
        max_batch_size=15,
        min_batch_size=3,
        worker_timeout=180,
        max_retries=2,
        retry_delay=60,
        parallel_workers=3,
        enable_retry=True,
        enable_metrics=True
    )


# Utility functions for common distributed operations

def batch_process_items(
    items: List[Any],
    processor_func: callable,
    batch_size: int = 15,
    **kwargs
) -> List[Any]:
    """Process items in batches using a processor function"""
    if not validate_distributed_input(items):
        return []
    
    results = []
    for i in range(0, len(items), batch_size):
        batch = items[i:i + batch_size]
        batch_result = processor_func(batch, **kwargs)
        results.extend(batch_result if isinstance(batch_result, list) else [batch_result])
    
    return results


def parallel_process_items(
    items: List[Any],
    processor_func: callable,
    config: Optional[DistributedConfig] = None,
    **kwargs
) -> Dict[str, Any]:
    """Process items in parallel using distributed processing"""
    if not validate_distributed_input(items):
        return {"success": False, "error": "Invalid input"}
    
    if config is None:
        config = create_distributed_config()
    
    # Create batch tasks
    batch_tasks = create_batch_tasks(
        items,
        processor_func,
        config.batch_size,
        **kwargs
    )
    
    if not batch_tasks:
        return {"success": False, "error": "No batch tasks created"}
    
    # Execute batches in parallel
    try:
        from reNgine.utilities.deadlock_prevention import safe_group_execution
        results = safe_group_execution(batch_tasks, config.worker_timeout * len(batch_tasks))
        
        # Aggregate results
        return aggregate_distributed_results(results)
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_processor_recommendations(
    item_count: int,
    item_type: str = "generic"
) -> Dict[str, Any]:
    """Get processor recommendations based on item count and type"""
    recommendations = {
        "batch_size": 15,
        "worker_timeout": 300,
        "max_retries": 3,
        "parallel_workers": 5
    }
    
    if item_count < 50:
        recommendations.update({
            "batch_size": 10,
            "worker_timeout": 180,
            "max_retries": 2,
            "parallel_workers": 3
        })
    elif item_count > 1000:
        recommendations.update({
            "batch_size": 25,
            "worker_timeout": 600,
            "max_retries": 5,
            "parallel_workers": 10
        })
    
    # Adjust based on item type
    if item_type == "command":
        recommendations["worker_timeout"] = min(recommendations["worker_timeout"], 300)
    elif item_type == "database":
        recommendations["batch_size"] = min(recommendations["batch_size"], 20)
    elif item_type == "network":
        recommendations["worker_timeout"] = min(recommendations["worker_timeout"], 180)
    
    return recommendations
