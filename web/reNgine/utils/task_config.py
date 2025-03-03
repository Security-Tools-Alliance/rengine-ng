import yaml

from pathlib import Path
from typing import Any, Dict

from reNgine.definitions import (
    CUSTOM_HEADER,
    DEFAULT_SCAN_INTENSITY,
    ENABLE_HTTP_CRAWL,
    FETCH_GPT_REPORT,
    FFUF_DEFAULT_WORDLIST_NAME,
    FFUF_DEFAULT_WORDLIST_PATH,
    FOLLOW_REDIRECT,
    INTENSITY,
    RATE_LIMIT,
    TIMEOUT,
    THREADS,
    HTTP_CRAWL,
    PORT_SCAN,
    DIR_FILE_FUZZ,
    VULNERABILITY_SCAN,
    SUBDOMAIN_DISCOVERY,
    FETCH_URL,
    SCREENSHOT,
    OSINT,
    S3SCANNER,
    
    # Port scan specifics
    NAABU_DEFAULT_PORTS,
    NAABU_EXCLUDE_PORTS,
    NAABU_EXCLUDE_SUBDOMAINS,
    PORTS,
    NAABU_PASSIVE,
    USE_NAABU_CONFIG,
    ENABLE_NMAP,
    NMAP_COMMAND,
    NMAP_SCRIPT,
    NMAP_SCRIPT_ARGS,
    
    # Fuzzing specifics
    AUTO_CALIBRATION,
    EXTENSIONS,
    DEFAULT_DIR_FILE_FUZZ_EXTENSIONS,
    FFUF_DEFAULT_FOLLOW_REDIRECT,
    MAX_TIME,
    MATCH_HTTP_STATUS,
    FFUF_DEFAULT_MATCH_HTTP_STATUS,
    RECURSIVE_LEVEL,
    FFUF_DEFAULT_RECURSIVE_LEVEL,
    STOP_ON_ERROR,
    
    # URL Fetch specifics
    REMOVE_DUPLICATE_ENDPOINTS,
    DUPLICATE_REMOVAL_FIELDS,
    ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS,
    GF_PATTERNS,
    DEFAULT_GF_PATTERNS,
    IGNORE_FILE_EXTENSION,
    DEFAULT_IGNORE_FILE_EXTENSIONS,
    USES_TOOLS,
    ENDPOINT_SCAN_DEFAULT_TOOLS,
    EXCLUDED_SUBDOMAINS,
    
    # Vulnerability scan specifics
    RUN_NUCLEI,
    RUN_CRLFUZZ,
    RUN_DALFOX,
    RUN_S3SCANNER,
    RETRIES,
    USE_NUCLEI_CONFIG,
    NUCLEI_SEVERITY,
    NUCLEI_DEFAULT_SEVERITIES,
    NUCLEI_TAGS,
    NUCLEI_TEMPLATE,
    NUCLEI_CUSTOM_TEMPLATE,
    DALFOX,
    WAF_DETECTION,
    WAF_EVASION,
    BLIND_XSS_SERVER,
    USER_AGENT,
    DELAY,
    PROVIDERS,
    S3SCANNER_DEFAULT_PROVIDERS,
    
    # Subdomain specifics
    SUBDOMAIN_SCAN_DEFAULT_TOOLS,
    WORDLIST,
)
from reNgine.settings import (
    DEFAULT_ENABLE_HTTP_CRAWL,
    DEFAULT_GET_GPT_REPORT,
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_RATE_LIMIT,
    DEFAULT_RETRIES,
    DEFAULT_THREADS,
)
from reNgine.utils.parsers import parse_custom_header
from reNgine.utils.db import get_random_proxy
from reNgine.utils.utils import format_json_output, return_iterable
from reNgine.utils.logger import Logger

from scanEngine.models import InstalledExternalTool

logger = Logger(True)

class TaskConfig:
    """Helper class to manage configuration for scan tasks"""

    def __init__(self, ctx, task_type=None):
        """Initialize with task configuration
        
        Args:
            ctx: Context dictionary
            task_type: Type of task to configure (e.g., HTTP_CRAWL)
        """
        self.ctx = ctx
        self.results_dir = ctx.get('results_dir')
        self.scan_id = ctx.get('scan_id')
        self.filename = ctx.get('filename')
        self.task_type = task_type

        if isinstance(yaml_configuration := ctx.get('yaml_configuration'), str):
            self.yaml_configuration = yaml.safe_load(yaml_configuration)
        else:
            self.yaml_configuration = yaml_configuration
            
        # Generate config if task type is provided
        self.config = {}
        if task_type:
            self.config = self.generate_config()

    
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
    
    def get_http_crawl_enabled(self, config_section: str = None) -> bool:
        """Check if HTTP crawl is enabled for this section
        
        Args:
            config_section: Configuration section name
            
        Returns:
            Boolean indicating if HTTP crawl is enabled
        """
        return self.get_value(config_section, ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
    
    def get_rate_limit(self, config_section: str = None) -> int:
        """Get rate limit setting
        
        Args:
            config_section: Configuration section name
            
        Returns:
            Rate limit value
        """
        return self.get_value(config_section, RATE_LIMIT, DEFAULT_RATE_LIMIT)
    
    def get_threads(self, config_section: str = None) -> int:
        """Get thread count
        
        Args:
            config_section: Configuration section name
            
        Returns:
            Thread count
        """
        return self.get_value(config_section, THREADS, DEFAULT_THREADS)
    
    def get_timeout(self, config_section: str = None) -> int:
        """Get timeout setting
        
        Args:
            config_section: Configuration section name
            
        Returns:
            Timeout value in seconds
        """
        return self.get_value(config_section, TIMEOUT, DEFAULT_HTTP_TIMEOUT)
    
    def prepare_custom_header(self, config_section: str = None, tool: str = None) -> Dict[str, str]:
        """Prepare custom HTTP headers
        
        Args:
            config_section: Configuration section name
            tool: Optional tool name for specific headers
            
        Returns:
            Dictionary of headers
        """
        config = self.get_config(config_section) or {}
        custom_header = config.get(CUSTOM_HEADER, {})
        
        if tool and isinstance(custom_header, dict):
            # Look for tool-specific headers
            return custom_header.get(tool, {})
        
        return parse_custom_header(custom_header)
    
    def get_follow_redirect(self, config_section: str = None, default: bool = False) -> bool:
        """Check if redirects should be followed
        
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
        return self.get_working_dir(filename=f'input_{name}.txt')
    
    def get_working_dir(self, folder: str = None, filename: str = None) -> str:
        """Get standardized output path
        
        Args:
            folder: Optional folder name
            filename: Optional filename
            
        Returns:
            Full path to output file
        """
        if folder and filename:
            return str(Path(self.results_dir) / f'{folder}/{filename}')
        if filename:
            return str(Path(self.results_dir) / f'{filename}')
        if folder:
            return str(Path(self.results_dir) / f'{folder}')
        return str(Path(self.results_dir))
    
    def calculate_delay(self, rate_limit: int, threads: int) -> float:
        """Calculate request delay based on rate limit and threads
        
        Args:
            rate_limit: Requests per second limit
            threads: Number of worker threads
            
        Returns:
            Delay in seconds between requests
        """
        return rate_limit / (threads * 100)
        
    def get_port_scan_config(self, config_section: str = None) -> Dict[str, Any]:
        """Get port scan specific configuration
        
        Args:
            config_section: Configuration section name
            
        Returns:
            Dictionary with port scan configuration
        """
        port_config = self.get_config(config_section)
        return {
            'enable_http_crawl': self.get_http_crawl_enabled(config_section),
            'timeout': self.get_timeout(config_section),
            'exclude_ports': port_config.get(NAABU_EXCLUDE_PORTS, []),
            'exclude_subdomains': port_config.get(NAABU_EXCLUDE_SUBDOMAINS, False),
            'ports': [str(port) for port in port_config.get(PORTS, NAABU_DEFAULT_PORTS)],
            'rate_limit': self.get_rate_limit(config_section),
            'threads': self.get_threads(config_section),
            'passive': port_config.get(NAABU_PASSIVE, False),
            'use_naabu_config': port_config.get(USE_NAABU_CONFIG, False),
            'nmap_enabled': port_config.get(ENABLE_NMAP, False),
            'nmap_cmd': port_config.get(NMAP_COMMAND, ''),
            'nmap_script': ','.join(return_iterable(port_config.get(NMAP_SCRIPT, ''))),
            'nmap_script_args': port_config.get(NMAP_SCRIPT_ARGS),
            'input_path': self.get_input_path('subdomains_port_scan')
        }
        
    def get_http_crawl_config(self, config_section: str = None) -> Dict[str, Any]:
        """Get HTTP crawl specific configuration
        
        Args:
            config_section: Configuration section name
            
        Returns:
            Dictionary with HTTP crawl configuration
        """
        return {
            'custom_header': self.prepare_custom_header(config_section),
            'threads': self.get_threads(config_section),
            'follow_redirect': self.get_follow_redirect(config_section, False),
        }
        
    def get_fuzzing_config(self, config_section: str = None) -> Dict[str, Any]:
        """Get directory/file fuzzing specific configuration
        
        Args:
            config_section: Configuration section name
            
        Returns:
            Dictionary with fuzzing configuration
        """
        fuzz_config = self.get_config(config_section)
        extensions = fuzz_config.get(EXTENSIONS, DEFAULT_DIR_FILE_FUZZ_EXTENSIONS)
        extensions = [ext if ext.startswith('.') else f'.{ext}' for ext in extensions]
        match_http_status = fuzz_config.get(MATCH_HTTP_STATUS, FFUF_DEFAULT_MATCH_HTTP_STATUS)

        # Get wordlist
        wordlist = fuzz_config.get(WORDLIST)
        wordlist_name = FFUF_DEFAULT_WORDLIST_NAME if wordlist == 'default' else wordlist
        wordlist_path = str(Path(FFUF_DEFAULT_WORDLIST_PATH) / f'{wordlist_name}.txt')
        
        return {
            'custom_header': self.prepare_custom_header(config_section),
            'auto_calibration': self.get_value(config_section, AUTO_CALIBRATION, True),
            'enable_http_crawl': self.get_http_crawl_enabled(config_section),
            'rate_limit': self.get_rate_limit(config_section),
            'extensions': extensions,
            'extensions_str': ','.join(map(str, extensions)),
            'follow_redirect': self.get_follow_redirect(config_section, FFUF_DEFAULT_FOLLOW_REDIRECT),
            'max_time': self.get_value(config_section, MAX_TIME, 0),
            'match_http_status': match_http_status,
            'match_codes': ','.join([str(c) for c in match_http_status]),
            'recursive_level': self.get_value(config_section, RECURSIVE_LEVEL, FFUF_DEFAULT_RECURSIVE_LEVEL),
            'stop_on_error': self.get_value(config_section, STOP_ON_ERROR, False),
            'timeout': self.get_timeout(config_section),
            'threads': self.get_threads(config_section),
            'wordlist_name': wordlist_name,
            'wordlist_path': wordlist_path,
            'delay': self.calculate_delay(
                self.get_rate_limit(config_section),
                self.get_threads(config_section)
            ),
            'input_path': self.get_input_path('dir_file_fuzz'),
        }
        
    def get_subdomain_discovery_config(self, config_section: str = None) -> Dict[str, Any]:
        """Get subdomain discovery specific configuration
        
        Args:
            config_section: Configuration section name
            
        Returns:
            Dictionary with subdomain discovery configuration
        """
        subdomain_config = self.get_config(config_section)

        return {
            'subdomain_config': subdomain_config,
            'enable_http_crawl': self.get_http_crawl_enabled(config_section),
            'threads': self.get_threads(config_section),
            'timeout': self.get_timeout(config_section),
            'tools': subdomain_config.get(USES_TOOLS, SUBDOMAIN_SCAN_DEFAULT_TOOLS),
            'default_subdomain_tools': [tool.name.lower() for tool in InstalledExternalTool.objects.filter(is_default=True).filter(is_subdomain_gathering=True)],
            'custom_subdomain_tools': [tool.name.lower() for tool in InstalledExternalTool.objects.filter(is_default=False).filter(is_subdomain_gathering=True)],
        }
        
    def get_fetch_url_config(self, config_section: str = None) -> Dict[str, Any]:
        """Get URL fetch specific configuration
        
        Args:
            config_section: Configuration section name
            
        Returns:
            Dictionary with URL fetch configuration
        """
        fetch_url_config = self.get_config(config_section)
        return {
            'should_remove_duplicate_endpoints': fetch_url_config.get(REMOVE_DUPLICATE_ENDPOINTS, True),
            'duplicate_removal_fields': fetch_url_config.get(DUPLICATE_REMOVAL_FIELDS, ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS),
            'enable_http_crawl': self.get_http_crawl_enabled(config_section),
            'gf_patterns': fetch_url_config.get(GF_PATTERNS, DEFAULT_GF_PATTERNS),
            'ignore_file_extension': fetch_url_config.get(IGNORE_FILE_EXTENSION, DEFAULT_IGNORE_FILE_EXTENSIONS),
            'tools': fetch_url_config.get(USES_TOOLS, ENDPOINT_SCAN_DEFAULT_TOOLS),
            'threads': self.get_threads(config_section),
            'follow_redirect': self.get_follow_redirect(config_section, False),
            'exclude_subdomains': fetch_url_config.get(EXCLUDED_SUBDOMAINS, False),
            'input_path': self.get_input_path('endpoints_fetch_url')
        }
        
    def get_screenshot_config(self, config_section: str = None) -> Dict[str, Any]:
        """Get screenshot specific configuration
        
        Args:
            config_section: Configuration section name
            
        Returns:
            Dictionary with screenshot configuration
        """
        if self.results_dir is None:
            raise ValueError("results_dir must be set before calling get_screenshot_config")

        return {
            'screenshots_path': self.get_working_dir(folder='screenshots'),
            'alive_endpoints_file': self.get_working_dir(filename='endpoints_alive.txt'),
            'intensity': self.get_intensity(config_section),
            'timeout': self.get_timeout(config_section),
            'threads': self.get_threads(config_section)
        }
        
    def get_osint_config(self, config_section: str = None) -> Dict[str, Any]:
        """Get OSINT specific configuration
        
        Args:
            config_section: Configuration section name
            
        Returns:
            Dictionary with OSINT configuration
        """
        return self.get_config(config_section)
        
    def get_vulnerability_scan_config(self, config_section: str = None) -> Dict[str, Any]:
        """Get vulnerability scan specific configuration
        
        Args:
            config_section: Configuration section name
            
        Returns:
            Dictionary with vulnerability scan configuration
        """
        config = self.get_config(config_section) or {}
        nuclei_specific_config = config.get('nuclei', {})
        
        return {
            'should_run_nuclei': config.get(RUN_NUCLEI, True),
            'should_run_crlfuzz': config.get(RUN_CRLFUZZ, False),
            'should_run_dalfox': config.get(RUN_DALFOX, False),
            'should_run_s3scanner': config.get(RUN_S3SCANNER, True),
            'enable_http_crawl': self.get_http_crawl_enabled(config_section),
            'concurrency': self.get_threads(config_section),
            'intensity': self.get_intensity(config_section),
            'rate_limit': self.get_rate_limit(config_section),
            'retries': self.get_value(config_section, RETRIES, DEFAULT_RETRIES),
            'timeout': self.get_timeout(config_section),
            'custom_header': self.prepare_custom_header(config_section),
            'should_fetch_gpt_report': self.get_gpt_report_enabled(config_section),
            'input_path': self.get_input_path('endpoints_vulnerability_scan'),

            # Nuclei specific
            'use_nuclei_conf': nuclei_specific_config.get(USE_NUCLEI_CONFIG, False),
            'severities': nuclei_specific_config.get(NUCLEI_SEVERITY, NUCLEI_DEFAULT_SEVERITIES),
            'tags': ','.join(nuclei_specific_config.get(NUCLEI_TAGS, [])),
            'nuclei_templates': nuclei_specific_config.get(NUCLEI_TEMPLATE),
            'custom_nuclei_templates': nuclei_specific_config.get(NUCLEI_CUSTOM_TEMPLATE),
            
            # Dalfox specific
            'dalfox_config': config.get(DALFOX) or {},
            'dalfox_custom_header': self.prepare_custom_header(config_section, 'dalfox'),
            'is_waf_evasion': config.get(DALFOX, {}).get(WAF_EVASION, False),
            'blind_xss_server': config.get(DALFOX, {}).get(BLIND_XSS_SERVER),
            'user_agent': config.get(DALFOX, {}).get(USER_AGENT) or config.get(USER_AGENT),
            'dalfox_timeout': config.get(DALFOX, {}).get(TIMEOUT) or self.get_timeout(config_section),
            'delay': config.get(DALFOX, {}).get(DELAY),
            'dalfox_threads': config.get(DALFOX, {}).get(THREADS) or self.get_threads(config_section),
            'dalfox_input_path': self.get_input_path('endpoints_dalfox'),
            
            # CRLFUZZ specific
            'crlfuzz_custom_header': self.prepare_custom_header(config_section, 'crlfuzz'),
            'crlfuzz_input_path': self.get_input_path('endpoints_crlf'),
        }
        
    def get_s3scanner_config(self, config_section: str = None) -> Dict[str, Any]:
        """Get S3Scanner specific configuration
        
        Returns:
            Dictionary with S3Scanner configuration
        """
        config = self.get_config(S3SCANNER) or {}
        return {
            'threads': self.get_threads(config_section),
            'providers': config.get(PROVIDERS, S3SCANNER_DEFAULT_PROVIDERS),
            'input_path': self.get_working_dir(filename=f'{self.scan_id}_subdomain_discovery.txt'),
            'concurrency': self.get_threads(VULNERABILITY_SCAN),
        }

    def get_waf_detection_config(self, config_section: str = None) -> Dict[str, Any]:
        """Get WAF detection specific configuration
        
        Args:
            config_section: Configuration section name  
            
        Returns:
            Dictionary with WAF detection configuration
        """
        return {
            'input_path': self.get_input_path('endpoints_waf_detection'),
        }
        
    def generate_config(self) -> Dict[str, Any]:
        """Generate a complete configuration dictionary based on task type
        
        Returns:
            Dictionary with task configuration
        """
        # Common configuration for all tasks
        self.main_config = {
            'proxy': self.get_proxy(),
            'results_dir': self.results_dir,
            'scan_id': self.scan_id,
            'filename': self.filename,
            'working_dir': self.get_working_dir(),
        }
        
        # Task-specific configuration
        self.task_config = {}
        
        if self.task_type == HTTP_CRAWL:
            self.task_config = self.get_http_crawl_config(HTTP_CRAWL)
        elif self.task_type == PORT_SCAN:
            self.task_config = self.get_port_scan_config(PORT_SCAN)
        elif self.task_type == DIR_FILE_FUZZ:
            self.task_config = self.get_fuzzing_config(DIR_FILE_FUZZ)
        elif self.task_type == VULNERABILITY_SCAN:
            self.task_config = self.get_vulnerability_scan_config(VULNERABILITY_SCAN)
        elif self.task_type == SUBDOMAIN_DISCOVERY:
            self.task_config = self.get_subdomain_discovery_config(SUBDOMAIN_DISCOVERY)
        elif self.task_type == FETCH_URL:
            self.task_config = self.get_fetch_url_config(FETCH_URL)
        elif self.task_type == SCREENSHOT:
            self.task_config = self.get_screenshot_config(SCREENSHOT)
        elif self.task_type == OSINT:
            self.task_config = self.get_osint_config(OSINT)
        elif self.task_type == S3SCANNER:
            self.task_config = self.get_s3scanner_config(VULNERABILITY_SCAN)
        elif self.task_type == WAF_DETECTION:
            self.task_config = self.get_waf_detection_config(WAF_DETECTION)

        return {
            'main_config': self.main_config,
            'task_config': self.task_config
        } 
    
    def get_main_config(self) -> Dict[str, Any]:
        """Get main configuration
        
        Returns:
            Dictionary with main configuration
        """
        logger.debug(f"⚙️  Main config: {format_json_output(self.config['main_config'], indent=2)}")
        return self.config['main_config']
    
    def get_task_config(self) -> Dict[str, Any]:
        """Get task configuration
        
        Returns:
            Dictionary with task configuration
        """
        logger.debug(f"⚙️  Task {self.task_type} config: {format_json_output(self.config['task_config'], indent=2)}")
        return self.config['task_config']
