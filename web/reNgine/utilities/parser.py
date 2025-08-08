import json
import re
import xml.etree.ElementTree as ET
import xmltodict
from celery.utils.log import get_task_logger

from reNgine.definitions import NMAP, NUCLEI_SEVERITY_MAP
from reNgine.utilities.url import sanitize_url

logger = get_task_logger(__name__)


#-----------------#
# Parser functions #
#-----------------#

def parse_nmap_results(xml_file, output_file=None, parse_type='vulnerabilities'):
    """Parse results from nmap output file.

    Args:
        xml_file (str): nmap XML report file path.
        output_file (str, optional): JSON output file path.
        parse_type (str): Type of parsing to perform:
            - 'vulnerabilities': Parse vulnerabilities from nmap scripts
            - 'services': Parse service banners from -sV
            - 'ports': Parse only open ports

    Returns:
        list: List of parsed results depending on parse_type:
            - vulnerabilities: List of vulnerability dictionaries
            - services: List of service dictionaries
            - ports: List of port dictionaries
    """
    with open(xml_file, encoding='utf8') as f:
        content = f.read()
        try:
            nmap_results = xmltodict.parse(content)
        except Exception as e:
            logger.warning(e)
            logger.error(f'Cannot parse {xml_file} to valid JSON. Skipping.')
            return []

    if output_file:
        with open(output_file, 'w') as f:
            json.dump(nmap_results, f, indent=4)

    hosts = nmap_results.get('nmaprun', {}).get('host', {})
    if isinstance(hosts, dict):
        hosts = [hosts]

    results = []

    for host in hosts:
        # Get hostname/IP
        hostnames_dict = host.get('hostnames', {})

        host_addresses = host.get('address', [])
        if isinstance(host_addresses, dict):
            host_addresses = [host_addresses]
        addresses = [
            {'addr': addr.get('@addr'), 'type': addr.get('@addrtype')}
            for addr in host_addresses
            if addr.get('@addrtype') in ['ipv4', 'ipv6']
        ]
        if hostnames_dict:
            if not (hostname_data := hostnames_dict.get('hostname', [])):
                hostnames = [addresses[0]['addr'] if addresses else 'unknown']
            else:
                # Convert to list if it's a unique dictionary
                if isinstance(hostname_data, dict):
                    hostname_data = [hostname_data]
                hostnames = [entry.get('@name') for entry in hostname_data if entry.get('@name')] or [addresses[0]['addr'] if addresses else 'unknown']
        else:
            hostnames = [addresses[0]['addr'] if addresses else 'unknown']

        # Process each hostname
        for hostname in hostnames:
            ports = host.get('ports', {}).get('port', [])
            if isinstance(ports, dict):
                ports = [ports]

            for port in ports:
                port_number = port['@portid']
                if not port_number or not port_number.isdigit():
                    continue

                port_protocol = port['@protocol']
                port_state = port.get('state', {}).get('@state')

                # Skip closed ports
                if port_state != 'open':
                    continue

                url = sanitize_url(f'{hostname}:{port_number}')

                if parse_type == 'ports':
                    # Return only open ports info with addresses
                    results.append({
                        'host': hostname,
                        'port': port_number,
                        'protocol': port_protocol,
                        'state': port_state,
                        'addresses': addresses
                    })
                    continue

                if parse_type == 'services':
                    # Parse service information from -sV
                    service = port.get('service', {})
                    results.append({
                        'host': hostname,
                        'port': port_number,
                        'protocol': port_protocol,
                        'service_name': service.get('@name'),
                        'service_product': service.get('@product'),
                        'service_version': service.get('@version'),
                        'service_extrainfo': service.get('@extrainfo'),
                        'service_ostype': service.get('@ostype'),
                        'service_method': service.get('@method'),
                        'service_conf': service.get('@conf')
                    })
                    continue

                if parse_type == 'vulnerabilities':
                    # Original vulnerability parsing logic
                    url_vulns = []
                    scripts = port.get('script', [])
                    if isinstance(scripts, dict):
                        scripts = [scripts]

                    for script in scripts:
                        script_id = script['@id']
                        script_output = script['@output']

                        if script_id == 'vulscan':
                            vulns = parse_nmap_vulscan_output(script_output)
                            url_vulns.extend(vulns)
                        elif script_id == 'vulners':
                            vulns = parse_nmap_vulners_output(script_output)
                            url_vulns.extend(vulns)
                        else:
                            logger.warning(f'Script output parsing for script "{script_id}" is not supported yet.')

                    for vuln in url_vulns:
                        vuln['source'] = NMAP
                        vuln['http_url'] = url
                        if 'http_path' in vuln:
                            vuln['http_url'] += vuln['http_path']
                        results.append(vuln)

    return results
def parse_nmap_vulscan_output(script_output):
    """Parse nmap vulscan script output.

    Args:
        script_output (str): Vulscan script output.

    Returns:
        list: List of Vulnerability dicts.
    """
    import pprint

    data = {}
    vulns = []
    provider_name = ''

    # Sort all vulns found by provider so that we can match each provider with
    # a function that pulls from its API to get more info about the
    # vulnerability.
    for line in script_output.splitlines():
        if not line:
            continue
        if not line.startswith('['): # provider line
            if "No findings" in line:
                logger.info(f"No findings: {line}")
            elif ' - ' in line:
                provider_name, provider_url = tuple(line.split(' - '))
                data[provider_name] = {'url': provider_url.rstrip(':'), 'entries': []}
            else:
                # Log a warning
                logger.warning(f"Unexpected line format: {line}")
            continue
        reg = r'\[(.*)\] (.*)'
        matches = re.match(reg, line)
        id, title = matches.groups()
        entry = {'id': id, 'title': title}
        data[provider_name]['entries'].append(entry)

    logger.warning('Vulscan parsed output:')
    logger.warning(pprint.pformat(data))

    for provider_name in data:
        if provider_name == 'Exploit-DB':
            logger.error(f'Provider {provider_name} is not supported YET.')
        elif provider_name == 'IBM X-Force':
            logger.error(f'Provider {provider_name} is not supported YET.')
        elif provider_name == 'MITRE CVE':
            logger.error(f'Provider {provider_name} is not supported YET.')
            for entry in data[provider_name]['entries']:
                cve_id = entry['id']
                vuln = cve_to_vuln(cve_id)
                vulns.append(vuln)
        elif provider_name == 'OSVDB':
            logger.error(f'Provider {provider_name} is not supported YET.')
        elif provider_name == 'OpenVAS (Nessus)':
            logger.error(f'Provider {provider_name} is not supported YET.')
        elif provider_name == 'SecurityFocus':
            logger.error(f'Provider {provider_name} is not supported YET.')
        elif provider_name == 'VulDB':
            logger.error(f'Provider {provider_name} is not supported YET.')
        else:
            logger.error(f'Provider {provider_name} is not supported.')
    return vulns


def parse_nmap_vulners_output(script_output, url=''):
    """Parse nmap vulners script output.

    TODO: Rework this as it's currently matching all CVEs no matter the
    confidence.

    Args:
        script_output (str): Script output.

    Returns:
        list: List of found vulnerabilities.
    """
    vulns = []
    # Check for CVE in script output
    CVE_REGEX = re.compile(r'.*(CVE-\d\d\d\d-\d+).*')
    matches = CVE_REGEX.findall(script_output)
    matches = list(dict.fromkeys(matches))
    for cve_id in matches: # get CVE info
        if vuln := cve_to_vuln(cve_id, vuln_type='nmap-vulners-nse'):
            vulns.append(vuln)
    return vulns


def cve_to_vuln(cve_id, vuln_type=''):
    """Search for a CVE using CVESearch and return Vulnerability data.

    Args:
        cve_id (str): CVE ID in the form CVE-*

    Returns:
        dict: Vulnerability dict.
    """
    from pycvesearch import CVESearch

    cve_info = CVESearch('https://cve.circl.lu').id(cve_id)
    if not cve_info:
        logger.error(f'Could not fetch CVE info for cve {cve_id}. Skipping.')
        return None
    vuln_cve_id = cve_info['id']
    vuln_name = vuln_cve_id
    vuln_description = cve_info.get('summary', 'none').replace(vuln_cve_id, '').strip()
    try:
        vuln_cvss = float(cve_info.get('cvss', -1))
    except (ValueError, TypeError):
        vuln_cvss = -1
    vuln_cwe_id = cve_info.get('cwe', '')
    exploit_ids = cve_info.get('refmap', {}).get('exploit-db', [])
    osvdb_ids = cve_info.get('refmap', {}).get('osvdb', [])
    references = cve_info.get('references', [])
    capec_objects = cve_info.get('capec', [])

    if ovals := cve_info.get('oval', []):
        vuln_name = ovals[0]['title']
        vuln_type = ovals[0]['family']

    # Set vulnerability severity based on CVSS score
    vuln_severity = 'info'
    if vuln_cvss < 4:
        vuln_severity = 'low'
    elif vuln_cvss < 7:
        vuln_severity = 'medium'
    elif vuln_cvss < 9:
        vuln_severity = 'high'
    else:
        vuln_severity = 'critical'

    # Build console warning message
    msg = f'{vuln_name} | {vuln_severity.upper()} | {vuln_cve_id} | {vuln_cwe_id} | {vuln_cvss}'
    for id in osvdb_ids:
        msg += f'\n\tOSVDB: {id}'
    for exploit_id in exploit_ids:
        msg += f'\n\tEXPLOITDB: {exploit_id}'
    logger.warning(msg)
    return {
        'name': vuln_name,
        'type': vuln_type,
        'severity': NUCLEI_SEVERITY_MAP[vuln_severity],
        'description': vuln_description,
        'cvss_score': vuln_cvss,
        'references': references,
        'cve_ids': [vuln_cve_id],
        'cwe_ids': [vuln_cwe_id],
    }


def process_nmap_service_results(xml_file):
    """Update port information with nmap service detection results"""
    from reNgine.utilities.port import create_or_update_port_with_service
    from startScan.models import IpAddress
    
    services = parse_nmap_results(xml_file, parse_type='services')
    
    for service in services:
        try:
            # Get IP from host address node
            ip = service.get('ip', '')
            host = service.get('host', '')
            
            # If IP is empty, try to get it from the host
            if not ip and host:
                # Parse XML to get IP for this host
                tree = ET.parse(xml_file)
                root = tree.getroot()
                for host_elem in root.findall('.//host'):
                    hostnames = host_elem.find('hostnames')
                    if hostnames is not None:
                        for hostname in hostnames.findall('hostname'):
                            if hostname.get('name') == host:
                                ip = host_elem.find('address').get('addr')
                                break
            
            # Skip if still empty or if it's a hostname
            if not ip or any(c.isalpha() for c in ip):
                logger.warning(f"Skipping invalid IP address: {ip} for host {host}")
                continue
                
            ip_address, _ = IpAddress.objects.get_or_create(
                address=ip
            )
            create_or_update_port_with_service(
                port_number=int(service['port']),
                service_info=service,
                ip_address=ip_address
            )
        except Exception as e:
            logger.error(f"Failed to process port {service['port']}: {str(e)}")


def process_httpx_response(line):
    """TODO: implement this"""
    pass 