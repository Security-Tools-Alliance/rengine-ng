#!/usr/bin/python
import logging
import re
from pathlib import Path
from .settings import RENGINE_WORDLISTS
import os

###############################################################################
# TOOLS DEFINITIONS
###############################################################################
logger = logging.getLogger('django')

###############################################################################
# TOOLS DEFINITIONS
###############################################################################

EMAIL_REGEX = re.compile(r'[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+')

###############################################################################
# YAML CONFIG DEFINITIONS
###############################################################################

ALL = 'all'
AMASS_WORDLIST = 'amass_wordlist'
AUTO_CALIBRATION = 'auto_calibration'
CUSTOM_HEADER = 'custom_header'
FETCH_LLM_REPORT = 'fetch_llm_report'
RUN_NUCLEI = 'run_nuclei'
RUN_CRLFUZZ = 'run_crlfuzz'
RUN_DALFOX = 'run_dalfox'
RUN_S3SCANNER = 'run_s3scanner'
DIR_FILE_FUZZ = 'dir_file_fuzz'
FOLLOW_REDIRECT = 'follow_redirect'
EXTENSIONS = 'extensions'
EXCLUDED_SUBDOMAINS = 'exclude_subdomains'
EXCLUDE_EXTENSIONS = 'exclude_extensions'
EXCLUDE_TEXT = 'exclude_text'
FETCH_URL = 'fetch_url'
GF_PATTERNS = 'gf_patterns'
HTTP_CRAWL = 'http_crawl'
IGNORE_FILE_EXTENSION = 'ignore_file_extensions'
INTENSITY = 'intensity'
MATCH_HTTP_STATUS = 'match_http_status'
MAX_TIME = 'max_time'
NAABU_EXCLUDE_PORTS = 'exclude_ports'
NAABU_EXCLUDE_SUBDOMAINS = 'exclude_subdomains'
ENABLE_NMAP = 'enable_nmap'
NMAP_COMMAND = 'nmap_cmd'
NMAP_SCRIPT = 'nmap_script'
NMAP_SCRIPT_ARGS = 'nmap_script_args'
NAABU_PASSIVE = 'passive'
NAABU_RATE = 'rate'
NUCLEI_TAGS = 'tags'
NUCLEI_SEVERITY = 'severities'
NUCLEI_CONCURRENCY = 'concurrency'
NUCLEI_TEMPLATES = 'templates'
NUCLEI_CUSTOM_TEMPLATES = 'custom_templates'
OSINT = 'osint'
OSINT_DOCUMENTS_LIMIT = 'documents_limit'
OSINT_DISCOVER = 'discover'
OSINT_DORK = 'dorks'
OSINT_CUSTOM_DORK = 'custom_dorks'
PORT = 'port'
PORTS = 'ports'
RECURSIVE = 'recursive'
RECURSIVE_LEVEL = 'recursive_level'
PORT_SCAN = 'port_scan'
RATE_LIMIT = 'rate_limit'
RETRIES = 'retries'
SCREENSHOT = 'screenshot'
SUBDOMAIN_DISCOVERY = 'subdomain_discovery'
STOP_ON_ERROR = 'stop_on_error'
THREADS = 'threads'
TIMEOUT = 'timeout'
USE_AMASS_CONFIG = 'use_amass_config'
USE_NAABU_CONFIG = 'use_naabu_config'
USE_NUCLEI_CONFIG = 'use_nuclei_config'
USE_SUBFINDER_CONFIG = 'use_subfinder_config'
USES_TOOLS = 'uses_tools'
VULNERABILITY_SCAN = 'vulnerability_scan'
WAF_DETECTION = 'waf_detection'
WORDLIST = 'wordlist_name'
REMOVE_DUPLICATE_ENDPOINTS = 'remove_duplicate_endpoints'
DUPLICATE_REMOVAL_FIELDS = 'duplicate_fields'
DALFOX = 'dalfox'
S3SCANNER = 's3scanner'
NUCLEI = 'nuclei'
NMAP = 'nmap'
CRLFUZZ = 'crlfuzz'
WAF_EVASION = 'waf_evasion'
BLIND_XSS_SERVER = 'blind_xss_server'
USER_AGENT = 'user_agent'
DELAY = 'delay'
PROVIDERS = 'providers'

###############################################################################
# Scan DEFAULTS
###############################################################################

LIVE_SCAN = 1
SCHEDULED_SCAN = 0

DEFAULT_SCAN_INTENSITY = 'normal'

###############################################################################
# Tools DEFAULTS
###############################################################################

# amass
AMASS_DEFAULT_WORDLIST_NAME = 'deepmagic.com-prefixes-top50000'
AMASS_DEFAULT_WORDLIST_PATH = str(Path(RENGINE_WORDLISTS))

# dorks
DORKS_DEFAULT_NAMES = [
    'stackoverflow',
    '3rdparty',
    'social_media',
    'project_management',
    'code_sharing',
    'config_files',
    'jenkins',
    'cloud_buckets',
    'php_error',
    'exposed_documents',
    'struts_rce',
    'db_files',
    'traefik',
    'git_exposed'
]

# ffuf
FFUF_DEFAULT_WORDLIST_NAME = 'fuzz-Bo0oM'
FFUF_DEFAULT_WORDLIST_PATH = str(Path(RENGINE_WORDLISTS))
FFUF_DEFAULT_MATCH_HTTP_STATUS = [200, 204]
FFUF_DEFAULT_RECURSIVE_LEVEL = 0
FFUF_DEFAULT_FOLLOW_REDIRECT = False

# naabu
NAABU_DEFAULT_PORTS = ['top-100']

# nuclei
NUCLEI_DEFAULT_TEMPLATES_PATH = str(Path.home() / 'nuclei-templates')
NUCLEI_SEVERITY_MAP = {
    'info': 0,
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4,
    'unknown': -1,
}
NUCLEI_REVERSE_SEVERITY_MAP = {v: k for k, v in NUCLEI_SEVERITY_MAP.items()}
NUCLEI_DEFAULT_SEVERITIES = list(NUCLEI_SEVERITY_MAP.keys())

# s3scanner
S3SCANNER_DEFAULT_PROVIDERS = ['gcp', 'aws', 'digitalocean', 'dreamhost', 'linode']

# dalfox
DALFOX_SEVERITY_MAP = {
    'Low': 1,
    'Medium': 2,
    'High': 3,
    'unknown': -1,
}

# osint
OSINT_DEFAULT_LOOKUPS = ['emails', 'metainfo', 'employees']
OSINT_DEFAULT_DORKS = [
    'stackoverflow',
    '3rdparty',
    'social_media',
    'project_management',
    'code_sharing',
    'config_files',
    'jenkins',
    'wordpress_files',
    'cloud_buckets',
    'php_error',
    'exposed_documents',
    'struts_rce',
    'db_files',
    'traefik',
    'git_exposed',
]
OSINT_DEFAULT_CONFIG = {
    'discover': OSINT_DEFAULT_LOOKUPS,
    'dork': OSINT_DEFAULT_DORKS
}

# subdomain scan
SUBDOMAIN_SCAN_DEFAULT_TOOLS = ['subfinder', 'ctfr', 'sublist3r', 'tlsx']

# endpoints scan
ENDPOINT_SCAN_DEFAULT_TOOLS = ['gospider']
ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS = ['content_length', 'page_title']

# http crawl
HTTP_THREADS = 30
HTTP_FOLLOW_REDIRECT = False
HTTP_PRE_CRAWL_UNCOMMON_PORTS = False
HTTP_PRE_CRAWL_ALL_PORTS = False
HTTP_PRE_CRAWL_BATCH_SIZE = 350


###############################################################################
# Logger DEFINITIONS
###############################################################################

CONFIG_FILE_NOT_FOUND = 'Config file not found'

###############################################################################
# Preferences DEFINITIONS
###############################################################################

SMALL = '100px'
MEDIM = '200px'
LARGE = '400px'
XLARGE = '500px'

# Discord message colors
DISCORD_INFO_COLOR = '0xfbbc00' # yellow
DISCORD_WARNING_COLOR = '0xf75b00' # orange
DISCORD_ERROR_COLOR = '0xf70000'
DISCORD_SUCCESS_COLOR = '0x00ff78'
DISCORD_SEVERITY_COLORS = {
    'info': DISCORD_INFO_COLOR,
    'warning': DISCORD_WARNING_COLOR,
    'error': DISCORD_ERROR_COLOR,
    'aborted': DISCORD_ERROR_COLOR,
    'success': DISCORD_SUCCESS_COLOR
}

STATUS_TO_SEVERITIES = {
    'RUNNING': 'info',
    'SUCCESS': 'success',
    'FAILED': 'error',
    'ABORTED': 'error'
}

###############################################################################
# Interesting Subdomain DEFINITIONS
###############################################################################
MATCHED_SUBDOMAIN = 'Subdomain'
MATCHED_PAGE_TITLE = 'Page Title'

###############################################################################
# Celery Task Status CODES
###############################################################################
INITIATED_TASK = -1
FAILED_TASK = 0
RUNNING_TASK = 1
SUCCESS_TASK = 2
ABORTED_TASK = 3
RUNNING_BACKGROUND = 4

CELERY_TASK_STATUS_MAP = {
    INITIATED_TASK: 'INITITATED',
    FAILED_TASK: 'FAILED',
    RUNNING_TASK: 'RUNNING',
    SUCCESS_TASK: 'SUCCESS',
    ABORTED_TASK: 'ABORTED',
    RUNNING_BACKGROUND: 'RUNNING_BACKGROUND'
}

CELERY_TASK_STATUSES = (
    (INITIATED_TASK, "Pending"),
    (FAILED_TASK, "Queued"), 
    (RUNNING_TASK, "Running"),
    (SUCCESS_TASK, "Completed"),
    (ABORTED_TASK, "Failed"),
    (RUNNING_BACKGROUND, "Running Background")
)
DYNAMIC_ID = -1

###############################################################################
# Uncommon Ports
# Source: https://github.com/six2dez/reconftw/blob/main/reconftw.cfg
###############################################################################
COMMON_WEB_PORTS = [
    80, 443,
    8000, 8001, 8080, 8081, 8082, 8443,
    3000, 3001, 5000, 9000
]
UNCOMMON_WEB_PORTS = [
    81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
    300,
    591,
    593,
    832,
    981,
    1010,
    1099,
    1311,
    2082, 2083, 2086, 2087, 2095, 2096,
    2480,
    3002, 3003, 3004, 3005,
    3128,
    3333,
    4000, 4001, 4002, 4003, 4004, 4005,
    4200,
    4243,
    4443, 4444, 4445, 4446, 4447, 4448, 4449,
    4567,
    4711,
    4712,
    4993,
    5001, 5002, 5003, 5004, 5005,
    5104,
    5108,
    5280,
    5281,
    5601,
    5800,
    6543,
    7000, 7001, 7002,
    7396,
    7474,
    8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009,
    8014,
    8042,
    8060,
    8069,
    8083, 8084, 8085, 8086, 8087, 8088, 8089,
    8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099,
    8100,
    8118,
    8123,
    8172,
    8180, 8181, 8182, 8183, 8184, 8185, 8186, 8187, 8188, 8189,
    8222,
    8243,
    8280,
    8281,
    8333,
    8337,
    8444, 8445, 8446, 8447, 8448, 8449,
    8500,
    8800,
    8834,
    8880,
    8888,
    8889,
    8983,
    9001, 9002, 9003, 9004, 9005,
    9043,
    9060,
    9080,
    9090, 9091, 9092, 9093, 9094, 9095,
    9200,
    9443, 9444, 9445, 9446, 9447, 9448, 9449,
    9502,
    9800,
    9981,
    10000, 10001, 10002, 10003, 10004,
    10250,
    10443,
    11371,
    12443,
    15672,
    16080,
    17778,
    18091,
    18092,
    20000,
    20720,
    32000,
    55440,
    55672
]

###############################################################################
# WHOIS DEFINITIONS
# IGNORE_WHOIS_RELATED_KEYWORD: To ignore and disable finding generic related domains
###############################################################################

IGNORE_WHOIS_RELATED_KEYWORD = [
    'Registration Private',
    'Domains By Proxy Llc',
    'Redacted For Privacy',
    'Digital Privacy Corporation',
    'Private Registrant',
    'Domain Administrator',
    'Administrator',
]


# Default FETCH URL params
DEFAULT_IGNORE_FILE_EXTENSIONS = [
    'png',
    'jpg',
    'jpeg',
    'gif',
    'mp4',
    'mpeg',
    'mp3',
]

DEFAULT_GF_PATTERNS = [
    'debug_logic',
    'idor',
    'interestingEXT',
    'interestingparams',
    'interestingsubs',
    'lfi',
    'rce',
    'redirect',
    'sqli',
    'ssrf',
    'ssti',
    'xss'
]


# Default Dir File Fuzz Params
DEFAULT_DIR_FILE_FUZZ_EXTENSIONS =  [
    '.html',
    '.php',
    '.git',
    '.yaml',
    '.conf',
    '.cnf',
    '.config',
    '.gz',
    '.env',
    '.log',
    '.db',
    '.mysql',
    '.bak',
    '.asp',
    '.aspx',
    '.txt',
    '.conf',
    '.sql',
    '.json',
    '.yml',
    '.pdf',
]

# Roles and Permissions
PERM_MODIFY_SYSTEM_CONFIGURATIONS = 'modify_system_configurations'
PERM_MODIFY_SCAN_CONFIGURATIONS = 'modify_scan_configurations'
PERM_MODIFY_TARGETS = 'modify_targets'
PERM_MODIFY_SCAN_RESULTS = 'modify_scan_results'
PERM_MODIFY_WORDLISTS = 'modify_wordlists'
PERM_MODIFY_INTERESTING_LOOKUP = 'modify_interesting_lookup'
PERM_MODIFY_SCAN_REPORT = 'modify_scan_report'
PERM_INITATE_SCANS_SUBSCANS = 'initiate_scans_subscans'

# 404 page url
FOUR_OH_FOUR_URL = '/404/'

# OSINT GooFuzz Path
GOFUZZ_EXEC_PATH = 'GooFuzz'

###############################################################################
# LLM DEFINITIONS
###############################################################################

# Default Ollama instance URL if not set in environment
DEFAULT_OLLAMA_INSTANCE = 'http://ollama:11434'

# Get Ollama instance URL from environment or use default
OLLAMA_INSTANCE = os.getenv('OLLAMA_INSTANCE', DEFAULT_OLLAMA_INSTANCE)

###############################################################################
# SCAN ENGINES DEFINITIONS
###############################################################################

ENGINE_DISPLAY_NAMES = [
    ('subdomain_discovery', 'Subdomain Discovery'),
    ('port_scan', 'Port Scan'),
    ('fetch_url', 'Fetch URLs'),
    ('dir_file_fuzz', 'Directory and File Fuzzing'),
    ('vulnerability_scan', 'Vulnerability Scan'),
    ('osint', 'Open-Source Intelligence'),
    ('screenshot', 'Screenshot'),
    ('waf_detection', 'WAF Detection')
]

# Engine names for internal use
ENGINE_NAMES = [engine[0] for engine in ENGINE_DISPLAY_NAMES]
