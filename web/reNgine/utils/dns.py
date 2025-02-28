import requests
from bs4 import BeautifulSoup
import subprocess
import tldextract

from reNgine.utils.logger import Logger
from reNgine.utils.command_builder import CommandBuilder
from reNgine.common_serializers import (
    DomainDNSRecordSerializer,
    DomainWhoisStatusSerializer,
    HistoricalIPSerializer,
    NameServersSerializer,
    RelatedDomainSerializer,
)
from dotted_dict import DottedDict

logger = Logger(True)

def reverse_whois(lookup_keyword):
    domains = []
    '''
        This function will use viewdns to fetch reverse whois info
        Input: lookup keyword like email or registrar name
        Returns a list of domains as string.
    '''
    url = f"https://viewdns.info:443/reversewhois/?q={lookup_keyword}"
    headers = {
        "Sec-Ch-Ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"104\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": "\"Linux\"",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Referer": "https://viewdns.info/",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8"
    }
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.content, 'lxml')
    table = soup.find("table", {"border" : "1"})
    if table:
        for row in table.find_all("tr"):
            cells = row.find_all("td")
            if len(cells) < 2:
                continue
            dom = cells[0].get_text(strip=True)
            created_on = cells[1].get_text(strip=True)
            if dom == "Domain Name":
                continue
            domains.append({'name': dom, 'created_on': created_on})
    return domains


def get_domain_historical_ip_address(domain):
    """
    This function will use viewdns to fetch historical IP address for a domain.
    
    Args:
        domain (str): Domain name to lookup
        
    Returns:
        list: List of dictionaries containing historical IP information
    """
    ips = []
    url = f"https://viewdns.info/iphistory/?domain={domain}"
    headers = {
        "Sec-Ch-Ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"104\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": "\"Linux\"",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Referer": "https://viewdns.info/",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8"
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise exception for bad responses
        
        soup = BeautifulSoup(response.content, 'lxml')
        table = soup.find("table", {"border": "1"})
        
        if not table:
            logger.warning(f"No historical IP data found for domain: {domain}")
            return ips
            
        for row in table.find_all("tr"):
            cells = row.find_all('td')
            
            # Skip if not enough cells or header row
            if len(cells) < 4:
                continue
                
            ip = cells[0].get_text(strip=True)
            
            # Skip header row
            if ip == 'IP Address':
                continue
                
            location = cells[1].get_text(strip=True)
            owner = cells[2].get_text(strip=True)
            last_seen = cells[3].get_text(strip=True)  # Correction: was using cells[2] twice
            
            ips.append({
                'ip': ip,
                'location': location,
                'owner': owner,
                'last_seen': last_seen,
            })
            
    except requests.RequestException as e:
        logger.error(f"Error retrieving historical IP data for {domain}: {str(e)}")
    except Exception as e:
        logger.error(f"Error parsing historical IP data for {domain}: {str(e)}")
        
    return ips

def get_domain_info_from_db(domain_obj):
    """Extract domain information from database object and convert to DottedDict.
    
    Args:
        domain_obj: Domain database object with domain_info relation
        
    Returns:
        DottedDict: Domain information in a standardized format
    """
    if not domain_obj or not domain_obj.domain_info:
        return None
        
    domain_info_db = domain_obj.domain_info
    
    # Create base dotted dict with all fields
    domain_info = DottedDict(
        dnssec=domain_info_db.dnssec,
        created=domain_info_db.created,
        updated=domain_info_db.updated,
        expires=domain_info_db.expires,
        geolocation_iso=domain_info_db.geolocation_iso,
        whois_server=domain_info_db.whois_server,
        status=[
            status['name']
            for status in DomainWhoisStatusSerializer(
                domain_info_db.status, many=True
            ).data
        ],
        ns_records=[
            ns['name']
            for ns in NameServersSerializer(
                domain_info_db.name_servers, many=True
            ).data
        ],
    )
    
    # Add registrar information
    if domain_info_db.registrar:
        domain_info.registrar_name = domain_info_db.registrar.name
        domain_info.registrar_phone = domain_info_db.registrar.phone
        domain_info.registrar_email = domain_info_db.registrar.email
        domain_info.registrar_url = domain_info_db.registrar.url
    
    # Add registrant information
    if domain_info_db.registrant:
        domain_info.registrant_name = domain_info_db.registrant.name
        domain_info.registrant_id = domain_info_db.registrant.id_str
        domain_info.registrant_organization = domain_info_db.registrant.organization
        domain_info.registrant_city = domain_info_db.registrant.city
        domain_info.registrant_state = domain_info_db.registrant.state
        domain_info.registrant_zip_code = domain_info_db.registrant.zip_code
        domain_info.registrant_country = domain_info_db.registrant.country
        domain_info.registrant_phone = domain_info_db.registrant.phone
        domain_info.registrant_fax = domain_info_db.registrant.fax
        domain_info.registrant_email = domain_info_db.registrant.email
        domain_info.registrant_address = domain_info_db.registrant.address
    
    # Add admin information
    if domain_info_db.admin:
        domain_info.admin_name = domain_info_db.admin.name
        domain_info.admin_id = domain_info_db.admin.id_str
        domain_info.admin_organization = domain_info_db.admin.organization
        domain_info.admin_city = domain_info_db.admin.city
        domain_info.admin_state = domain_info_db.admin.state
        domain_info.admin_zip_code = domain_info_db.admin.zip_code
        domain_info.admin_country = domain_info_db.admin.country
        domain_info.admin_phone = domain_info_db.admin.phone
        domain_info.admin_fax = domain_info_db.admin.fax
        domain_info.admin_email = domain_info_db.admin.email
        domain_info.admin_address = domain_info_db.admin.address
    
    # Add tech information
    if domain_info_db.tech:
        domain_info.tech_name = domain_info_db.tech.name
        domain_info.tech_id = domain_info_db.tech.id_str
        domain_info.tech_organization = domain_info_db.tech.organization
        domain_info.tech_city = domain_info_db.tech.city
        domain_info.tech_state = domain_info_db.tech.state
        domain_info.tech_zip_code = domain_info_db.tech.zip_code
        domain_info.tech_country = domain_info_db.tech.country
        domain_info.tech_phone = domain_info_db.tech.phone
        domain_info.tech_fax = domain_info_db.tech.fax
        domain_info.tech_email = domain_info_db.tech.email
        domain_info.tech_address = domain_info_db.tech.address
    
    # Add related domains
    domain_info.related_tlds = [
        domain['name']
        for domain in RelatedDomainSerializer(
            domain_info_db.related_tlds, many=True
        ).data
    ]
    
    domain_info.related_domains = [
        domain['name']
        for domain in RelatedDomainSerializer(
            domain_info_db.related_domains, many=True
        ).data
    ]
    
    # Add historical IPs
    domain_info.historical_ips = list(
        HistoricalIPSerializer(
            domain_info_db.historical_ips, many=True
        ).data
    )
    
    # Extract DNS records if available
    if domain_info_db.dns_records:
        a_records = []
        txt_records = []
        mx_records = []
        dns_records = [{'name': dns['name'], 'type': dns['type']} 
                     for dns in DomainDNSRecordSerializer(domain_info_db.dns_records, many=True).data]
        
        for dns in dns_records:
            if dns['type'] == 'a':
                a_records.append(dns['name'])
            elif dns['type'] == 'txt':
                txt_records.append(dns['name'])
            elif dns['type'] == 'mx':
                mx_records.append(dns['name'])
                
        domain_info.a_records = a_records
        domain_info.txt_records = txt_records
        domain_info.mx_records = mx_records
    
    return domain_info

def find_related_tlds(domain):
    """Find related TLDs for a domain using TLSx tool.
    
    Args:
        domain (str): Domain to find related TLDs for
        
    Returns:
        list: List of related TLD domains
    """
    related_tlds = []
    output_path = '/tmp/ip_domain_tlsx.txt'
    
    # Build command with CommandBuilder for better security
    cmd_builder = CommandBuilder('tlsx')
    cmd_builder.add_option('-san')
    cmd_builder.add_option('-cn')
    cmd_builder.add_option('-silent')
    cmd_builder.add_option('-ro')
    cmd_builder.add_option('-host', domain)
    cmd_builder.add_option('-o', output_path)
    
    # Need to use shell=True due to redirection 
    cmd = cmd_builder.build_string()
    
    try:
        subprocess.run(cmd, shell=True, check=True)
        
        with open(output_path) as f:
            tlsx_output = f.readlines()
        
        tldextract_target = tldextract.extract(domain)
        for doms in tlsx_output:
            doms = doms.strip()
            tldextract_res = tldextract.extract(doms)
            if (domain != doms and 
                tldextract_res.domain == tldextract_target.domain and 
                tldextract_res.subdomain == ''):
                related_tlds.append(doms)
        
        related_tlds = list(set(related_tlds))
    except Exception as e:
        logger.error(f"Error finding related TLDs for {domain}: {str(e)}")
    
    return related_tlds

def format_whois_response(domain_info, ip_domain):
    """Format domain information into standard response format.
    
    Args:
        domain_info (DottedDict): Domain information
        ip_domain (str): Original domain or IP queried
        
    Returns:
        dict: Formatted response with domain information
    """
    return {
        'status': True,
        'ip_domain': ip_domain,
        'dnssec': domain_info.get('dnssec'),
        'created': domain_info.get('created'),
        'updated': domain_info.get('updated'),
        'expires': domain_info.get('expires'),
        'geolocation_iso': domain_info.get('registrant_country'),
        'domain_statuses': domain_info.get('status'),
        'whois_server': domain_info.get('whois_server'),
        'dns': {
            'a': domain_info.get('a_records'),
            'mx': domain_info.get('mx_records'),
            'txt': domain_info.get('txt_records'),
        },
        'registrar': {
            'name': domain_info.get('registrar_name'),
            'phone': domain_info.get('registrar_phone'),
            'email': domain_info.get('registrar_email'),
            'url': domain_info.get('registrar_url'),
        },
        'registrant': {
            'name': domain_info.get('registrant_name'),
            'id': domain_info.get('registrant_id'),
            'organization': domain_info.get('registrant_organization'),
            'address': domain_info.get('registrant_address'),
            'city': domain_info.get('registrant_city'),
            'state': domain_info.get('registrant_state'),
            'zipcode': domain_info.get('registrant_zip_code'),
            'country': domain_info.get('registrant_country'),
            'phone': domain_info.get('registrant_phone'),
            'fax': domain_info.get('registrant_fax'),
            'email': domain_info.get('registrant_email'),
        },
        'admin': {
            'name': domain_info.get('admin_name'),
            'id': domain_info.get('admin_id'),
            'organization': domain_info.get('admin_organization'),
            'address':domain_info.get('admin_address'),
            'city': domain_info.get('admin_city'),
            'state': domain_info.get('admin_state'),
            'zipcode': domain_info.get('admin_zip_code'),
            'country': domain_info.get('admin_country'),
            'phone': domain_info.get('admin_phone'),
            'fax': domain_info.get('admin_fax'),
            'email': domain_info.get('admin_email'),
        },
        'technical_contact': {
            'name': domain_info.get('tech_name'),
            'id': domain_info.get('tech_id'),
            'organization': domain_info.get('tech_organization'),
            'address': domain_info.get('tech_address'),
            'city': domain_info.get('tech_city'),
            'state': domain_info.get('tech_state'),
            'zipcode': domain_info.get('tech_zip_code'),
            'country': domain_info.get('tech_country'),
            'phone': domain_info.get('tech_phone'),
            'fax': domain_info.get('tech_fax'),
            'email': domain_info.get('tech_email'),
        },
        'nameservers': domain_info.get('ns_records'),
        'related_domains': domain_info.get('related_domains'),
        'related_tlds': domain_info.get('related_tlds'),
        'historical_ips': domain_info.get('historical_ips'),
    }

def execute_whois(domain):
    """Run whois command and parse output.
    
    Args:
        domain (str): Domain to query whois for
        
    Returns:
        dict: Parsed whois output
    """
    # Build command with CommandBuilder for better security
    cmd_builder = CommandBuilder('whois')
    cmd_builder.add_option(domain)
    
    try:
        output = subprocess.check_output(cmd_builder.build_list(), universal_newlines=True)
        
        # Initialize whois_data with defaults
        whois_data = {
            'domain': domain,
            'registrar': {},
            'registrant': {},
            'admin': {},
            'tech': {},
            'nameservers': [],
            'domain_status': []
        }
        
        # Basic parsing of whois output
        for line in output.splitlines():
            line = line.strip()
            if not line or ': ' not in line:
                continue
                
            # Split the line into key-value pair
            key, value = line.split(': ', 1)
            key = key.strip().lower()
            value = value.strip()
            
            # Map keys to whois_data structure
            # This is a simplified version and might need adaptation
            # based on different whois server formats
            if 'registrar:' in key:
                whois_data['registrar']['name'] = value
            elif 'registrar url:' in key:
                whois_data['registrar']['url'] = value
            elif 'creation date:' in key:
                whois_data['created'] = value
            elif 'updated date:' in key:
                whois_data['updated'] = value
            elif 'expiration date:' in key:
                whois_data['expires'] = value
            elif 'name server:' in key:
                whois_data['nameservers'].append(value)
            elif 'status:' in key:
                whois_data['domain_status'].append(value)
        
        return whois_data
    except Exception as e:
        logger.error(f"Error executing whois for {domain}: {str(e)}")
        return None
