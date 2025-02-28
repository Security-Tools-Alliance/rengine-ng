from dotted_dict import DottedDict
from django.utils import timezone

from reNgine.celery import app
from reNgine.utils.logger import Logger
from reNgine.utils.dns import (
    get_domain_info_from_db,
    get_domain_historical_ip_address,
    reverse_whois,
    find_related_tlds,
    format_whois_response,
    execute_whois
)
from targetApp.models import (
    Domain,
    DomainInfo,
    Registrar,
)

logger = Logger(True)

@app.task(name='query_whois', bind=False, queue='io_queue')
def query_whois(ip_domain, force_reload_whois=False):
    """Query WHOIS information for an IP or a domain name.

    Args:
        ip_domain (str): IP address or domain name.
        force_reload_whois (bool): Whether to force reload whois or not, default False
    Returns:
        dict: WHOIS information.
    """
    domain = Domain.objects.filter(name=ip_domain).first()

    # Case 1: We have domain info in DB and don't need to force reload
    if not force_reload_whois and domain and domain.domain_info:
        # Update insert date if not set
        if not domain.insert_date:
            domain.insert_date = timezone.now()
            domain.save()

        # Get domain info from database and format response
        domain_info = get_domain_info_from_db(domain)
        return format_whois_response(domain_info, ip_domain)

    # Case 2: Need to query whois and other data sources
    logger.info(f'🔍 Domain info for "{ip_domain}" not found in DB, querying whois')
    domain_info = DottedDict()

    # Step 1: Find historical IPs
    try:
        historical_ips = get_domain_historical_ip_address(ip_domain)
        domain_info.historical_ips = historical_ips
    except Exception as e:
        logger.error(f'HistoricalIP for {ip_domain} not found!\nError: {str(e)}')
        historical_ips = []

    # Step 2: Find associated domains using reverse whois
    try:
        related_domains = reverse_whois(ip_domain.split('.')[0])
        domain_info.related_domains = [domain['name'] for domain in related_domains]
    except Exception as e:
        logger.error(f'Associated domain not found for {ip_domain}\nError: {str(e)}')
        domain_info.related_domains = []

    # Step 3: Find related TLDs
    try:
        related_tlds = find_related_tlds(ip_domain)
        domain_info.related_tlds = related_tlds
    except Exception as e:
        logger.error(f'Related TLDs not found for {ip_domain}\nError: {str(e)}')
        domain_info.related_tlds = []

    # Step 4: Execute WHOIS
    try:
        if whois_data := execute_whois(ip_domain):
            # Update domain_info with whois data
            domain_info.update(whois_data)
    except Exception as e:
        logger.error(f'Error executing whois for {ip_domain}\nError: {str(e)}')

    # Step 5: Save information to database if we have a domain object
    if domain:
        try:
            # Create or update domain info in database
            # This part is simplified - full implementation would need
            # to recreate all the database objects from the domain_info
            whois_server = domain_info.get('whois_server')
            created = domain_info.get('created')
            updated = domain_info.get('updated')
            expires = domain_info.get('expires')

            if registrar_name := domain_info.get('registrar_name'):
                registrar, _ = Registrar.objects.get_or_create(
                    name=registrar_name,
                    defaults={
                        'url': domain_info.get('registrar_url'),
                        'email': domain_info.get('registrar_email'),
                        'phone': domain_info.get('registrar_phone'),
                    }
                )
            else:
                registrar = None

            # Create domain info
            domain_info_obj, created = DomainInfo.objects.get_or_create(
                domain=domain,
                defaults={
                    'whois_server': whois_server,
                    'created': created,
                    'updated': updated,
                    'expires': expires,
                    'registrar': registrar,
                }
            )

            if not created:
                domain_info_obj.whois_server = whois_server
                domain_info_obj.created = created
                domain_info_obj.updated = updated
                domain_info_obj.expires = expires
                domain_info_obj.registrar = registrar
                domain_info_obj.save()

            domain.domain_info = domain_info_obj
            domain.save()

        except Exception as e:
            return {
                'status': False,
                'ip_domain': ip_domain,
                'result': "unable to fetch records from WHOIS database.",
                'message': str(e)
            }

    # Step 6: Format and return response
    return format_whois_response(domain_info, ip_domain)

@app.task(name='query_reverse_whois', bind=False, queue='io_queue')
def query_reverse_whois(lookup_keyword):
    """Queries Reverse WHOIS information for an organization or email address.

    Args:
        lookup_keyword (str): Registrar Name or email
    Returns:
        dict: Reverse WHOIS information.
    """
    return reverse_whois(lookup_keyword)

@app.task(name='query_ip_history', bind=False, queue='io_queue')
def query_ip_history(domain):
    """Queries the IP history for a domain

    Args:
        domain (str): domain_name
    Returns:
        list: list of historical ip addresses
    """
    return get_domain_historical_ip_address(domain) 