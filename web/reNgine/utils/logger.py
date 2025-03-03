import logging
import os
from celery.utils.log import get_task_logger
from celery import current_task

# ANSI color codes
GREY = "\x1b[38;20m"
BLUE = "\x1b[34;20m"
YELLOW = "\x1b[33;20m"
RED = "\x1b[31;20m"
BOLD_RED = "\x1b[31;1m"
RESET = "\x1b[0m"
BOLD = "\x1b[1m"
GREEN = "\x1b[32;20m"
CYAN = "\x1b[36;20m"
MAGENTA = "\x1b[35;20m"
WHITE = "\x1b[37;20m"

# Force colors even in Docker
FORCE_COLOR = os.environ.get('FORCE_COLOR', 'true').lower() != 'false'

class CustomFormatter(logging.Formatter):
    """Custom formatter that adds colors to logs"""
    
    FORMAT = "%(levelname)s | %(message)s"
    
    FORMATS = {
        logging.DEBUG: BLUE + FORMAT + RESET,
        logging.INFO: GREY + FORMAT + RESET,
        logging.WARNING: YELLOW + FORMAT + RESET,
        logging.ERROR: RED + FORMAT + RESET,
        logging.CRITICAL: BOLD_RED + FORMAT + RESET
    }
    
    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

class Logger:
    """Class to print/write logs to the terminals"""
    
    _instance = None
    
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
            
            # Map of task colors
            self.task_colors = {
                # Base tasks
                'default': WHITE,
                'run_command_line': YELLOW,
                
                # Detection and analysis
                'waf_detection': YELLOW,
                'vulnerability_scan': RED,
                'port_scan': BLUE,
                'nmap': CYAN,
                'scan_http_ports': MAGENTA,
                
                # Reconnaissance
                'subdomain_discovery': BLUE,
                'osint_discovery': CYAN,
                'theHarvester': CYAN,
                'find_subdomains': BLUE,
                'query_whois': GREEN,
                'query_reverse_whois': GREEN,
                'query_ip_history': GREEN,
                
                # Fuzzing and exploration
                'dir_file_fuzz': YELLOW,
                'http_crawl': MAGENTA,
                'dalfox_scan': RED,
                'crlfuzz_scan': RED,
                's3scanner': RED,
                
                # Screenshots and visual
                'screenshot': GREY,
                'fetch_url': GREY,
                
                # Vulnerability analysis
                'nuclei_scan': BOLD_RED,
                'llm_vulnerability_description': RED,
                
                # Notifications
                'send_scan_notif': GREEN,
                'send_task_notif': GREEN,
                'send_file_to_discord': GREEN,
                'send_hackerone_report': GREEN,
                
                # Scan management
                'initiate_scan': MAGENTA,
                'initiate_subscan': MAGENTA,
                'post_process': CYAN,
                'remove_duplicate_endpoints': BLUE,
                
                # Infrastructure
                'geo_localize': CYAN,
                'run_cmseek': YELLOW,
                
                # System tasks
                'report': GREEN,
                'scan_activity': WHITE
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
        task_name = current_task.name if hasattr(current_task, 'name') and self.is_task_logger else ''
        
        # Split multi-line messages
        lines = str(message).split('\n')
        
        # Process each line individually
        colored_lines = []
        for line in lines:
            if FORCE_COLOR:
                color = self.task_colors.get(task_name.split('.')[-1], self.task_colors['default'])
                level_color = self.level_colors.get(level, GREY)
                bold = BOLD if level != 'INFO' else ''
                colored_line = f"{color}{task_name:<35}{RESET} | {level_color}{bold}{level:<8}{RESET} | {color}{line}{RESET}"
                colored_lines.append(colored_line)
            else:
                colored_lines.append(f"{task_name:<35} | {level:<8} | {line}")

        # Join lines and print
        formatted_message = '\n'.join(colored_lines)
        print(formatted_message, flush=True)

# Global logger instance (task logger by default)
default_logger = Logger(True)
