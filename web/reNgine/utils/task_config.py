import yaml

from pathlib import Path
from typing import Any, Dict

from reNgine.definitions import (
    CUSTOM_HEADER,
    DEFAULT_SCAN_INTENSITY,
    FETCH_GPT_REPORT,
    FOLLOW_REDIRECT,
    INTENSITY,
    RATE_LIMIT,
    TIMEOUT,
    THREADS,
)
from reNgine.settings import (
    DEFAULT_GET_GPT_REPORT,
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_RATE_LIMIT,
    DEFAULT_THREADS,
)
from reNgine.utils.http import get_http_crawl_value
from reNgine.utils.parsers import parse_custom_header
from reNgine.utils.db import get_random_proxy
from reNgine.utils.command_builder import generate_header_param

class TaskConfig:
    """Helper class to manage configuration for scan tasks"""

    def __init__(self, yaml_configuration, results_dir: str, scan_id: int = None, filename: str = None):
        """Initialize with task configuration
        
        Args:
            yaml_configuration: Configuration dictionary from YAML or YAML string
            results_dir: Directory to store results
            scan_id: Scan history ID
            filename: Base filename for outputs
        """
        # Si c'est une chaîne, parser en YAML
        if isinstance(yaml_configuration, str):
            self.yaml_configuration = yaml.safe_load(yaml_configuration)
        else:
            self.yaml_configuration = yaml_configuration
            
        self.results_dir = results_dir
        self.scan_id = scan_id
        self.filename = filename
    
    def get_config(self, config_key: str) -> Dict[str, Any]:
        """Get configuration for a specific section
        
        Args:
            config_key: Key in YAML config to retrieve
            
        Returns:
            Configuration dictionary or empty dict if not found
        """
        return self.yaml_configuration.get(config_key) or {}
    
    def get_value(self, config_section: str, key: str, default_value: Any = None) -> Any:
        """Get a value from a specific configuration section with fallback
        
        Args:
            config_section: Section name in YAML config
            key: Key to retrieve from section
            default_value: Default value if not found
            
        Returns:
            Value from config or default
        """
        config = self.get_config(config_section)

        # First try to get from section config
        value = config.get(key)
        if value is not None:
            return value

        # Then try from global config
        value = self.yaml_configuration.get(key)
        return value if value is not None else default_value

    def prepare_custom_header(self, config_section: str = None, header_type='common'):
        """Prepare custom header from configuration.
        
        Args:
            config (dict): Tool-specific configuration
            header_type (str): Header type (common, dalfox, etc.)
            
        Returns:
            str: Formatted custom header string or None
        """

        config = self.get_config(config_section)
        custom_header = config.get(CUSTOM_HEADER) or self.yaml_configuration.get(CUSTOM_HEADER)
        if custom_header:
            return generate_header_param(custom_header, header_type)
        return None

    def get_custom_header(self, config_section: str = None, header_type: str = None) -> Dict[str, str]:
        """Get custom headers for a section
        
        Args:
            config_section: Configuration section name
            header_type: Optional header type specifier
            
        Returns:
            Dictionary of custom headers
        """
        config = self.get_config(config_section) if config_section else self.yaml_configuration
        return parse_custom_header(config)
    
    def get_http_crawl_enabled(self, config_section: str = None) -> bool:
        """Check if HTTP crawl is enabled
        
        Args:
            config_section: Configuration section name
            
        Returns:
            Boolean indicating if HTTP crawl is enabled
        """
        config = self.get_config(config_section) if config_section else self.yaml_configuration
        return get_http_crawl_value(config, self.yaml_configuration)
    
    def get_threads(self, config_section: str = None) -> int:
        """Get thread count for a section
        
        Args:
            config_section: Configuration section name
            
        Returns:
            Thread count
        """
        return self.get_value(config_section, THREADS, DEFAULT_THREADS)
    
    def get_timeout(self, config_section: str = None) -> int:
        """Get timeout for a section
        
        Args:
            config_section: Configuration section name
            
        Returns:
            Timeout value
        """
        return self.get_value(config_section, TIMEOUT, DEFAULT_HTTP_TIMEOUT)
    
    def get_rate_limit(self, config_section: str = None, rate_key: str = RATE_LIMIT) -> int:
        """Get rate limit for a section
        
        Args:
            config_section: Configuration section name
            rate_key: Key to use for rate limit
            
        Returns:
            Rate limit value
        """
        return self.get_value(config_section, rate_key, DEFAULT_RATE_LIMIT)
    
    def get_follow_redirect(self, config_section: str = None, default: bool = False) -> bool:
        """Get follow redirect setting
        
        Args:
            config_section: Configuration section name
            default: Default value
            
        Returns:
            Follow redirect setting
        """
        return self.get_value(config_section, FOLLOW_REDIRECT, default)
    
    def get_intensity(self, config_section: str = None) -> str:
        """Get scan intensity
        
        Args:
            config_section: Configuration section name
            
        Returns:
            Intensity value
        """
        return self.get_value(config_section, INTENSITY, DEFAULT_SCAN_INTENSITY)
    
    def get_gpt_report_enabled(self, config_section: str = None) -> bool:
        """Check if GPT report generation is enabled
        
        Args:
            config_section: Configuration section name
            
        Returns:
            Boolean indicating if GPT report is enabled
        """
        return self.get_value(config_section, FETCH_GPT_REPORT, DEFAULT_GET_GPT_REPORT)
    
    def get_proxy(self) -> str:
        """Get a random proxy if enabled
        
        Returns:
            Proxy string or empty string
        """
        return get_random_proxy()
    
    def get_input_path(self, name: str) -> str:
        """Get standardized input path
        
        Args:
            name: Input file name
            
        Returns:
            Full path to input file
        """
        return str(Path(self.results_dir) / f'input_{name}.txt')
    
    def get_output_path(self, name: str = None) -> str:
        """Get standardized output path
        
        Args:
            name: Optional name suffix
            
        Returns:
            Full path to output file
        """
        if name:
            return str(Path(self.results_dir) / f'{self.filename}_{name}')
        return str(Path(self.results_dir) / f'{self.filename}')
    
    def calculate_delay(self, rate_limit: int, threads: int) -> float:
        """Calculate request delay based on rate limit and threads
        
        Args:
            rate_limit: Requests per second limit
            threads: Number of worker threads
            
        Returns:
            Delay in seconds between requests
        """
        return rate_limit / (threads * 100) 