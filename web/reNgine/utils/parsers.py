import html
import json
import xmltodict
import re
import pprint
from pycvesearch import CVESearch
from reNgine.definitions import (
    CRLFUZZ,
    DALFOX,
    DALFOX_SEVERITY_MAP,
    NMAP,
    NUCLEI,
    NUCLEI_SEVERITY_MAP,
    NUCLEI_DEFAULT_TEMPLATES_PATH,
)
from reNgine.utils.logger import Logger

logger = Logger(__name__)

def parse_s3scanner_result(line):
    '''
        Parses and returns s3Scanner Data
    '''
    bucket = line['bucket']
    return {
        'name': bucket['name'],
        'region': bucket['region'],
        'provider': bucket['provider'],
        'owner_display_name': bucket['owner_display_name'],
        'owner_id': bucket['owner_id'],
        'perm_auth_users_read': bucket['perm_auth_users_read'],
        'perm_auth_users_write': bucket['perm_auth_users_write'],
        'perm_auth_users_read_acl': bucket['perm_auth_users_read_acl'],
        'perm_auth_users_write_acl': bucket['perm_auth_users_write_acl'],
        'perm_auth_users_full_control': bucket['perm_auth_users_full_control'],
        'perm_all_users_read': bucket['perm_all_users_read'],
        'perm_all_users_write': bucket['perm_all_users_write'],
        'perm_all_users_read_acl': bucket['perm_all_users_read_acl'],
        'perm_all_users_write_acl': bucket['perm_all_users_write_acl'],
        'perm_all_users_full_control': bucket['perm_all_users_full_control'],
        'num_objects': bucket['num_objects'],
        'size': bucket['bucket_size']
    }

def parse_nuclei_result(line):
    """Parse results from nuclei JSON output.

    Args:
        line (dict): Nuclei JSON line output.

    Returns:
        dict: Vulnerability data.
    """
    return {
        'name': line.get('info', {}).get('name', ''),
        'type': line.get('type', ''),
        'severity': NUCLEI_SEVERITY_MAP.get(
            line.get('info', {}).get('severity', 'unknown'), 0
        ),
        'template': line.get('template-path', '').replace(
            f'{NUCLEI_DEFAULT_TEMPLATES_PATH}/', ''
        ),
        'template_url': line.get('template-url', ''),
        'template_id': line.get('template-id', ''),
        'description': line.get('info', {}).get('description', ''),
        'matcher_name': line.get('matcher-name', ''),
        'curl_command': line.get('curl-command'),
        'request': html.escape(line.get('request', '')),
        'response': html.escape(line.get('response', '')),
        'extracted_results': line.get('extracted-results', []),
        'cvss_metrics': line.get('info', {})
        .get('classification', {})
        .get('cvss-metrics', ''),
        'cvss_score': line.get('info', {})
        .get('classification', {})
        .get('cvss-score'),
        'cve_ids': line.get('info', {})
        .get('classification', {})
        .get('cve_id', [])
        or [],
        'cwe_ids': line.get('info', {})
        .get('classification', {})
        .get('cwe_id', [])
        or [],
        'references': line.get('info', {}).get('reference', []) or [],
        'tags': line.get('info', {}).get('tags', []),
        'source': NUCLEI,
    }

def parse_dalfox_result(line):
    """Parse results from dalfox JSON output.

    Args:
        line (dict): Dalfox JSON line output.

    Returns:
        dict: Vulnerability data.
    """
    description = ''
    description += f" Evidence: {line.get('evidence')} <br>" if line.get('evidence') else ''
    description += f" Message: {line.get('message')} <br>" if line.get('message') else ''
    description += f" Payload: {line.get('message_str')} <br>" if line.get('message_str') else ''
    description += f" Vulnerable Parameter: {line.get('param')} <br>" if line.get('param') else ''

    return {
        'name': 'XSS (Cross Site Scripting)',
        'type': 'XSS',
        'severity': DALFOX_SEVERITY_MAP[line.get('severity', 'unknown')],
        'description': description,
        'source': DALFOX,
        'cwe_ids': [line.get('cwe')]
    }

def parse_crlfuzz_result(url):
    """Parse CRLF results

    Args:
        url (str): CRLF Vulnerable URL

    Returns:
        dict: Vulnerability data.
    """
    return {
        'name': 'CRLF (HTTP Response Splitting)',
        'type': 'CRLF',
        'severity': 2,
        'description': 'A CRLF (HTTP Response Splitting) vulnerability has been discovered.',
        'source': CRLFUZZ,
    }

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
    from reNgine.utils.http import sanitize_url

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

def parse_custom_header(custom_header):
    """
    Parse the custom_header input to ensure it is a dictionary with valid header values.

    Args:
        custom_header (dict or str): Dictionary or string containing the custom headers.

    Returns:
        dict: Parsed dictionary of custom headers.
    """
    def is_valid_header_value(value):
        return bool(re.match(r'^[\w\-\s.,;:@()/+*=\'\[\]{}]+$', value))

    if isinstance(custom_header, str):
        header_dict = {}
        headers = custom_header.split(',')
        for header in headers:
            parts = header.split(':', 1)
            if len(parts) == 2:
                key, value = parts
                key = key.strip()
                value = value.strip()
                if is_valid_header_value(value):
                    header_dict[key] = value
                else:
                    raise ValueError(f"Invalid header value: '{value}'")
            else:
                raise ValueError(f"Invalid header format: '{header}'")
        return header_dict
    elif isinstance(custom_header, dict):
        for key, value in custom_header.items():
            if not is_valid_header_value(value):
                raise ValueError(f"Invalid header value: '{value}'")
        return custom_header
    else:
        raise ValueError("custom_header must be a dictionary or a string")
