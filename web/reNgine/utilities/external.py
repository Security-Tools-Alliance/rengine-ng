"""
External services integration utilities.

This module provides integration with external services and APIs for reconnaissance
and data gathering operations.

Key features:
- Reverse WHOIS lookups via ViewDNS
- Historical IP address lookups
- API key management for external services
- Google dorking with GooFuzz
- Associated domains discovery

Supported services:
- ViewDNS.info (reverse WHOIS, IP history)
- OpenAI API
- Netlas API
- Google dorking via GooFuzz
"""

from reNgine.utilities.core.file import join_path, delete_file, file_exists
from typing import List, Dict, Any, Optional, Union

import requests
from bs4 import BeautifulSoup
from celery.utils.log import get_task_logger

from dashboard.models import NetlasAPIKey, OpenAiAPIKey


logger = get_task_logger(__name__)


# -----------------#
# External Services #
# -----------------#


def reverse_whois(lookup_keyword: str) -> List[Dict[str, str]]:
    """
    Use ViewDNS to fetch reverse WHOIS information.

    Args:
        lookup_keyword (str): Lookup keyword like email or registrar name

    Returns:
        list: List of domains with creation dates

    Example:
        >>> domains = reverse_whois("admin@example.com")
        >>> # Returns: [{"name": "example.com", "created_on": "2020-01-01"}, ...]
    """
    domains = []
    
    try:
        url = f"https://viewdns.info:443/reversewhois/?q={lookup_keyword}"
        headers = {
            "Sec-Ch-Ua": '" Not A;Brand";v="99", "Chromium";v="104"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Linux"',
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Referer": "https://viewdns.info/",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        }
        
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, "lxml")
        table = soup.find("table", {"border": "1"})
        
        if not table:
            logger.warning(f"No reverse WHOIS data found for keyword: {lookup_keyword}")
            return domains
        
        for row in table.find_all("tr"):
            cells = row.find_all("td")
            if len(cells) >= 2:
                dom = cells[0].get_text(strip=True)
                created_on = cells[1].get_text(strip=True)
                
                if dom == "Domain Name":
                    continue
                    
                domains.append({
                    "name": dom,
                    "created_on": created_on
                })
                
    except requests.RequestException as e:
        logger.error(f"Request failed for reverse WHOIS lookup '{lookup_keyword}': {e}")
    except Exception as e:
        logger.error(f"Error in reverse WHOIS lookup for '{lookup_keyword}': {e}")
    
    return domains


def get_domain_historical_ip_address(domain: str) -> List[Dict[str, str]]:
    """
    Use ViewDNS to fetch historical IP addresses for a domain.

    Args:
        domain (str): Domain name to lookup

    Returns:
        list: List of historical IP addresses with metadata

    Example:
        >>> ips = get_domain_historical_ip_address("example.com")
        >>> # Returns: [{"ip": "1.2.3.4", "location": "US", "owner": "Example Corp", "last_seen": "2023-01-01"}, ...]
    """
    ips = []
    
    try:
        url = f"https://viewdns.info/iphistory/?domain={domain}"
        headers = {
            "Sec-Ch-Ua": '" Not A;Brand";v="99", "Chromium";v="104"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Linux"',
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Referer": "https://viewdns.info/",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        }
        
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, "lxml")
        table = soup.find("table", {"border": "1"})
        
        if not table:
            logger.warning(f"No historical IP data found for domain: {domain}")
            return ips
        
        for row in table.find_all("tr"):
            cells = row.find_all("td")
            if len(cells) >= 4:
                ip = cells[0].get_text(strip=True)
                location = cells[1].get_text(strip=True)
                owner = cells[2].get_text(strip=True)
                last_seen = cells[3].get_text(strip=True)
                
                if ip == "IP Address":
                    continue
                    
                ips.append({
                    "ip": ip,
                    "location": location,
                    "owner": owner,
                    "last_seen": last_seen,
                })
                
    except requests.RequestException as e:
        logger.error(f"Request failed for historical IP lookup '{domain}': {e}")
    except Exception as e:
        logger.error(f"Error in historical IP lookup for '{domain}': {e}")
    
    return ips


def get_open_ai_key() -> Optional[OpenAiAPIKey]:
    """
    Get the first available OpenAI API key.

    Returns:
        OpenAiAPIKey or None: First available API key or None if none found
    """
    try:
        openai_keys = OpenAiAPIKey.objects.all()
        return openai_keys[0] if openai_keys else None
    except Exception as e:
        logger.error(f"Error retrieving OpenAI API key: {e}")
        return None


def get_netlas_key() -> Optional[NetlasAPIKey]:
    """
    Get the first available Netlas API key.

    Returns:
        NetlasAPIKey or None: First available API key or None if none found
    """
    try:
        netlas_keys = NetlasAPIKey.objects.all()
        return netlas_keys[0] if netlas_keys else None
    except Exception as e:
        logger.error(f"Error retrieving Netlas API key: {e}")
        return None


def get_associated_domains(keywords: List[str]) -> List[str]:
    """
    Get associated domains based on keywords.
    
    TODO: Implement associated domains discovery logic.

    Args:
        keywords (list): List of keywords to search for

    Returns:
        list: List of associated domains (currently empty)
    """
    # TODO: Implement associated domains discovery
    logger.info(f"Associated domains discovery requested for keywords: {keywords}")
    return []


def get_and_save_dork_results(
    lookup_target: str,
    results_dir: str,
    dork_type: str,
    lookup_keywords: Optional[str] = None,
    lookup_extensions: Optional[str] = None,
    delay: int = 3,
    page_count: int = 2,
    scan_history=None,
) -> Dict[str, Any]:
    """
    Use GooFuzz to perform Google dorking and store results.

    Args:
        lookup_target (str): Target to look into (e.g., stackoverflow or target domain)
        results_dir (str): Results directory path
        dork_type (str): Dork type title
        lookup_keywords (str, optional): Comma-separated keywords or paths to look for
        lookup_extensions (str, optional): Comma-separated extensions to look for
        delay (int): Delay between requests in seconds
        page_count (int): Number of Google pages to extract
        scan_history (startScan.ScanHistory, optional): Scan History Object

    Returns:
        dict: Results with URLs found and any errors

    Example:
        >>> result = get_and_save_dork_results(
        ...     "example.com",
        ...     "/tmp/results",
        ...     "filetype:pdf",
        ...     lookup_keywords="confidential,secret",
        ...     page_count=3
        ... )
        >>> # Returns: {"results": ["url1", "url2"], "error": None}
    """
    results = []
    
    try:
        from reNgine.definitions import GOFUZZ_EXEC_PATH
        from reNgine.utilities.command import run_command
        from startScan.models import Dork

        # Build GooFuzz command
        gofuzz_command = f"{GOFUZZ_EXEC_PATH} -t {lookup_target} -d {delay} -p {page_count}"

        if lookup_extensions:
            gofuzz_command += f" -e {lookup_extensions}"
        elif lookup_keywords:
            gofuzz_command += f" -w {lookup_keywords}"

        # Set up output files
        output_file = join_path(results_dir, "gofuzz.txt")
        gofuzz_command += f" -o {output_file}"
        history_file = join_path(results_dir, "commands.txt")

        # Execute GooFuzz command
        return_code, output = run_command(
            gofuzz_command,
            shell=False,
            history_file=history_file,
            scan_id=scan_history.id if scan_history else None,
        )

        # Check if GooFuzz failed
        if return_code != 0:
            error_msg = f"GooFuzz command failed with exit code {return_code} for {lookup_target}"
            logger.warning(error_msg)
            return {"results": results, "error": error_msg}

        # Check if output file exists
        if not file_exists(output_file):
            error_msg = f"GooFuzz output file not found: {output_file}"
            logger.warning(error_msg)
            return {"results": results, "error": error_msg}

        # Process results
        with open(output_file, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url:
                    results.append(url)
                    
                    # Save dork to database
                    dork, created = Dork.objects.get_or_create(type=dork_type, url=url)
                    if scan_history:
                        scan_history.dorks.add(dork)

        # Clean up output file
        try:
            delete_file(output_file)
        except OSError as e:
            logger.warning(f"Could not remove output file {output_file}: {e}")

    except (OSError, PermissionError) as e:
        error_msg = f"Critical file system error in get_and_save_dork_results for {lookup_target}: {e}"
        logger.error(error_msg)
        return {"results": results, "error": f"File system error: {str(e)}"}
    except ImportError as e:
        error_msg = f"Critical import error in get_and_save_dork_results for {lookup_target}: {e}"
        logger.error(error_msg)
        return {"results": results, "error": f"Import error: {str(e)}"}
    except Exception as e:
        error_msg = f"Non-critical error in get_and_save_dork_results for {lookup_target}: {e}"
        logger.warning(error_msg)
        return {"results": results, "error": str(e)}

    return {"results": results, "error": None}


def validate_external_service_response(response: requests.Response, service_name: str) -> bool:
    """
    Validate external service response.

    Args:
        response (requests.Response): HTTP response object
        service_name (str): Name of the external service

    Returns:
        bool: True if response is valid, False otherwise
    """
    try:
        response.raise_for_status()
        return True
    except requests.HTTPError as e:
        logger.error(f"HTTP error from {service_name}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error validating {service_name} response: {e}")
        return False


def get_external_service_headers() -> Dict[str, str]:
    """
    Get standard headers for external service requests.

    Returns:
        dict: Standard headers for external service requests
    """
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
    }
