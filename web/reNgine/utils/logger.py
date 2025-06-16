import logging
import os
from celery.utils.log import get_task_logger
from celery import current_task
from .colors import Colors

# Force colors even in Docker
FORCE_COLOR = os.environ.get('FORCE_COLOR', 'true').lower() != 'false'

class CustomFormatter(logging.Formatter):
    """Custom formatter that adds colors to logs"""
    
    FORMAT = "%(levelname)s | %(message)s"
    
    FORMATS = {
        logging.DEBUG: Colors.BLUE + FORMAT + Colors.RESET,
        logging.INFO: Colors.GRAY + FORMAT + Colors.RESET,
        logging.WARNING: Colors.YELLOW + FORMAT + Colors.RESET,
        logging.ERROR: Colors.RED + FORMAT + Colors.RESET,
        logging.CRITICAL: Colors.BOLD_RED + FORMAT + Colors.RESET
    }
    
    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

class Logger:
    """Class to print/write logs to the terminals"""
    
    _instance = None
    _original_level = None
    _is_disabled = False
    
    def __new__(cls, is_task_logger=False):
        if not cls._instance:
            cls._instance = super(Logger, cls).__new__(cls)
            # Initialization moved to __init__
        return cls._instance
    
    def __init__(self, is_task_logger=False):
        if not hasattr(self, '_initialized'):  # Prevent re-initialization
            # For backward compatibility, accept boolean parameter
            if isinstance(is_task_logger, bool):
                self.is_task_logger = is_task_logger
                name = __name__
            else:
                # If string was passed, use it as name and assume task logger
                name = is_task_logger
                self.is_task_logger = True
            
            # Colors for different task categories
            base_task_colors = Colors.GRAY
            scan_management_colors = Colors.WHITE
            detection_analysis_colors = Colors.PURPLE
            web_discovery_colors = Colors.GREEN
            reconnaissance_colors = Colors.BLUE
            osint_colors = Colors.LIGHT_CYAN
            vulnerability_colors = Colors.LIGHT_ORANGE
            notification_colors = Colors.WHITE
            system_colors = Colors.GRAY

            # Map of task colors
            self.task_colors = {
                # Base tasks
                'default': base_task_colors,
                'run_command_line': Colors.YELLOW,
                
                # Scan management
                'initiate_scan': scan_management_colors,
                'initiate_subscan': scan_management_colors,
                'post_process': scan_management_colors,
                'remove_duplicate_endpoints': scan_management_colors,

                # Detection and analysis
                'waf_detection': detection_analysis_colors,
                'port_scan': detection_analysis_colors,
                'nmap': detection_analysis_colors,
                'scan_http_ports': detection_analysis_colors,
                
                # Web discovery
                'http_crawl': web_discovery_colors,
                'fetch_url': web_discovery_colors,
                'run_cmseek': web_discovery_colors,
                'screenshot': web_discovery_colors,

                # Reconnaissance
                'subdomain_discovery': reconnaissance_colors,
                'geo_localize': reconnaissance_colors,
                
                # OSINT
                'osint': Colors.CYAN,
                'osint_discovery': osint_colors,
                'dorking': osint_colors,
                'theHarvester': osint_colors,
                'h8mail': osint_colors,
                'find_subdomains': osint_colors,
                'query_whois': osint_colors,
                'query_reverse_whois': osint_colors,
                'query_ip_history': osint_colors,
                
                # Vulnerability analysis
                'vulnerability_scan': Colors.ORANGE,
                'nuclei_scan': vulnerability_colors,
                'nuclei_individual_severity_module': vulnerability_colors,
                'dir_file_fuzz': vulnerability_colors,
                'dalfox_scan': vulnerability_colors,
                'crlfuzz_scan': vulnerability_colors,
                's3scanner': vulnerability_colors,
                'llm_vulnerability_description': vulnerability_colors,
                
                # Notifications
                'send_scan_notif': notification_colors,
                'send_task_notif': notification_colors,
                'send_file_to_discord': notification_colors,
                'send_hackerone_report': notification_colors,
                
                # System tasks
                'report': system_colors,
                'scan_activity': system_colors
            }
            
            self.logger = logging.getLogger(name)
            self.logger.setLevel(logging.INFO)
            
            # Add handler with our custom formatter
            handler = logging.StreamHandler()
            handler.setFormatter(CustomFormatter())
            self.logger.addHandler(handler)
            
            # If celery task logger is needed
            self.task_logger = get_task_logger(name)
            self.task_logger.setLevel(logging.INFO)
            
            task_handler = logging.StreamHandler()
            task_handler.setFormatter(CustomFormatter())
            self.task_logger.addHandler(task_handler)
            
            # Initialization of colors for log levels
            self.level_colors = {
                'DEBUG': Colors.BLUE,
                'INFO': Colors.GRAY,
                'WARNING': Colors.YELLOW,
                'ERROR': Colors.RED,
                'CRITICAL': Colors.BOLD_RED
            }
            
            self._initialized = True
    
    def info(self, message):
        """Log an info message."""
        self._log(message, 'INFO')
        
    def debug(self, message):
        """Log a debug message."""
        self._log(message, 'DEBUG')
        
    def warning(self, message):
        """Log a warning message."""
        self._log(message, 'WARNING')
        
    def error(self, message):
        """Log an error message."""
        self._log(message, 'ERROR')
        
    def critical(self, message):
        """Log a critical message."""
        self._log(message, 'CRITICAL')
        
    def exception(self, message):
        """Log an exception message."""
        self._log(message, 'ERROR')
    
    def _log(self, message, level):
        if self._is_disabled:
            return
            
        task_name = current_task.name if hasattr(current_task, 'name') and self.is_task_logger else ''
        
        # Split multi-line messages
        lines = str(message).split('\n')
        
        # Process each line individually
        colored_lines = []
        for line in lines:
            if FORCE_COLOR:
                color = self.task_colors.get(task_name.split('.')[-1], self.task_colors['default'])
                level_color = self.level_colors.get(level, Colors.GRAY) if level != 'INFO' else color
                bold = Colors.BOLD if level != 'INFO' else ''
                colored_line = f"{color}{task_name:<20}{Colors.RESET} | {level_color}{bold}{level:<8}{Colors.RESET} | {level_color}{line}{Colors.RESET}"
                colored_lines.append(colored_line)
            else:
                colored_lines.append(f"{task_name:<20} | {level:<8} | {line}")

        # Join lines and print
        formatted_message = '\n'.join(colored_lines)
        print(formatted_message, flush=True)

    @classmethod
    def disable_logging(cls):
        """Disable all logging by setting level to CRITICAL."""
        if not cls._is_disabled:
            cls._original_level = logging.getLogger().getEffectiveLevel()
            logging.disable(logging.CRITICAL)
            cls._is_disabled = True

    @classmethod
    def enable_logging(cls):
        """Re-enable logging to its original level."""
        if cls._is_disabled:
            logging.disable(logging.NOTSET)
            logging.getLogger().setLevel(cls._original_level)
            cls._original_level = None
            cls._is_disabled = False

# Global logger instance (task logger by default)
default_logger = Logger(True)
