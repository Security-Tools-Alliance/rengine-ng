"""
Mock data utilities for dry run testing
"""

import random
import os

from reNgine.utils.logger import Logger

logger = Logger(True)

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
    # Check if we're actually in dry run mode
    if os.getenv('COMMAND_EXECUTOR_DRY_RUN', '0') != '1':
        logger.warning("🧪 generate_mock_urls called outside of dry run mode")
    
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

def generate_mock_vulnerabilities(urls, count=5):
    """Generate mock vulnerability data for dry run testing
    
    Args:
        urls (list): List of URLs to associate vulnerabilities with
        count (int): Number of vulnerabilities to generate per URL
        
    Returns:
        list: List of mock vulnerability dictionaries
    """
    # To be implemented for vulnerability testing
    pass

def generate_mock_subdomain_data(domain, count=10):
    """Generate mock subdomain data for dry run testing
    
    Args:
        domain (str): Base domain
        count (int): Number of subdomains to generate
        
    Returns:
        list: List of mock subdomain dictionaries
    """
    # To be implemented for subdomain discovery testing
    pass 

def prepare_urls_mock(ctx, input_path):
    # Import here to avoid circular imports
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
