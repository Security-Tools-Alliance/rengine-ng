import json
import subprocess
import tldextract

from celery.utils.log import get_task_logger
from django.utils import timezone
from dotted_dict import DottedDict

from reNgine.celery import app
from reNgine.utilities.external import (
    get_domain_historical_ip_address,
    reverse_whois,
    get_associated_domains,
    get_netlas_key
)
from reNgine.definitions import EMAIL_REGEX
from reNgine.tasks.command import run_command
from targetApp.models import (
    DNSRecord,
    Domain,
    DomainInfo,
    DomainRegistration,
    HistoricalIP,
    NameServer,
    Registrar,
    RelatedDomain,
    WhoisStatus,
)
from reNgine.common_serializers import (
    DomainDNSRecordSerializer,
    DomainWhoisStatusSerializer,
    HistoricalIPSerializer,
    NameServersSerializer,
    RelatedDomainSerializer
)
logger = get_task_logger(__name__)


@app.task(name='query_whois', bind=False, queue='io_queue')
def query_whois(ip_domain, force_reload_whois=False):
    """Query WHOIS information for an IP or a domain name.

    Args:
        ip_domain (str): IP address or domain name.
        force_reload_whois (bool): Whether to force reload WHOIS information.
    Returns:
        dict: WHOIS information.
    """
    if not force_reload_whois and Domain.objects.filter(name=ip_domain).exists() and Domain.objects.get(name=ip_domain).domain_info:
        domain = Domain.objects.get(name=ip_domain)
        if not domain.insert_date:
            domain.insert_date = timezone.now()
            domain.save()
        domain_info_db = domain.domain_info
        domain_info = DottedDict(
            dnssec=domain_info_db.dnssec,
            created=domain_info_db.created,
            updated=domain_info_db.updated,
            expires=domain_info_db.expires,
            geolocation_iso=domain_info_db.geolocation_iso,
            status=[
                status['name']
                for status in DomainWhoisStatusSerializer(
                    domain_info_db.status, many=True
                ).data
            ],
            whois_server=domain_info_db.whois_server,
            ns_records=[
                ns['name']
                for ns in NameServersSerializer(
                    domain_info_db.name_servers, many=True
                ).data
            ],
            registrar_name=domain_info_db.registrar.name,
            registrar_phone=domain_info_db.registrar.phone,
            registrar_email=domain_info_db.registrar.email,
            registrar_url=domain_info_db.registrar.url,
            registrant_name=domain_info_db.registrant.name,
            registrant_id=domain_info_db.registrant.id_str,
            registrant_organization=domain_info_db.registrant.organization,
            registrant_city=domain_info_db.registrant.city,
            registrant_state=domain_info_db.registrant.state,
            registrant_zip_code=domain_info_db.registrant.zip_code,
            registrant_country=domain_info_db.registrant.country,
            registrant_phone=domain_info_db.registrant.phone,
            registrant_fax=domain_info_db.registrant.fax,
            registrant_email=domain_info_db.registrant.email,
            registrant_address=domain_info_db.registrant.address,
            admin_name=domain_info_db.admin.name,
            admin_id=domain_info_db.admin.id_str,
            admin_organization=domain_info_db.admin.organization,
            admin_city=domain_info_db.admin.city,
            admin_state=domain_info_db.admin.state,
            admin_zip_code=domain_info_db.admin.zip_code,
            admin_country=domain_info_db.admin.country,
            admin_phone=domain_info_db.admin.phone,
            admin_fax=domain_info_db.admin.fax,
            admin_email=domain_info_db.admin.email,
            admin_address=domain_info_db.admin.address,
            tech_name=domain_info_db.tech.name,
            tech_id=domain_info_db.tech.id_str,
            tech_organization=domain_info_db.tech.organization,
            tech_city=domain_info_db.tech.city,
            tech_state=domain_info_db.tech.state,
            tech_zip_code=domain_info_db.tech.zip_code,
            tech_country=domain_info_db.tech.country,
            tech_phone=domain_info_db.tech.phone,
            tech_fax=domain_info_db.tech.fax,
            tech_email=domain_info_db.tech.email,
            tech_address=domain_info_db.tech.address,
            related_tlds=[
                domain['name']
                for domain in RelatedDomainSerializer(
                    domain_info_db.related_tlds, many=True
                ).data
            ],
            related_domains=[
                domain['name']
                for domain in RelatedDomainSerializer(
                    domain_info_db.related_domains, many=True
                ).data
            ],
            historical_ips=list(
                HistoricalIPSerializer(
                    domain_info_db.historical_ips, many=True
                ).data
            ),
        )
        if domain_info_db.dns_records:
            a_records = []
            txt_records = []
            mx_records = []
            dns_records = [{'name': dns['name'], 'type': dns['type']} for dns in DomainDNSRecordSerializer(domain_info_db.dns_records, many=True).data]
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
    else:
        logger.info(f'Domain info for "{ip_domain}" not found in DB, querying whois')
        domain_info = DottedDict()
        # find domain historical ip
        try:
            historical_ips = get_domain_historical_ip_address(ip_domain)
            domain_info.historical_ips = historical_ips
        except Exception as e:
            logger.error(f'HistoricalIP for {ip_domain} not found!\nError: {str(e)}')
            historical_ips = []
        # find associated domains using ip_domain
        try:
            related_domains = reverse_whois(ip_domain.split('.')[0])
        except Exception as e:
            logger.error(f'Associated domain not found for {ip_domain}\nError: {str(e)}')
            similar_domains = []
        # find related tlds using TLSx
        try:
            related_tlds = []
            output_path = '/tmp/ip_domain_tlsx.txt'
            tlsx_command = f'tlsx -san -cn -silent -ro -host {ip_domain} -o {output_path}'
            run_command(
                tlsx_command,
                shell=True,
            )
            tlsx_output = []
            with open(output_path) as f:
                tlsx_output = f.readlines()

            tldextract_target = tldextract.extract(ip_domain)
            for doms in tlsx_output:
                doms = doms.strip()
                tldextract_res = tldextract.extract(doms)
                if ip_domain != doms and tldextract_res.domain == tldextract_target.domain and tldextract_res.subdomain == '':
                    related_tlds.append(doms)

            related_tlds = list(set(related_tlds))
            domain_info.related_tlds = related_tlds
        except Exception as e:
            logger.error(f'Associated domain not found for {ip_domain}\nError: {str(e)}')
            similar_domains = []

        related_domains_list = []
        if Domain.objects.filter(name=ip_domain).exists():
            domain = Domain.objects.get(name=ip_domain)
            db_domain_info = domain.domain_info or DomainInfo()
            db_domain_info.save()
            for _domain in related_domains:
                domain_related = RelatedDomain.objects.get_or_create(
                    name=_domain['name'],
                )[0]
                db_domain_info.related_domains.add(domain_related)
                related_domains_list.append(_domain['name'])

            for _domain in related_tlds:
                domain_related = RelatedDomain.objects.get_or_create(
                    name=_domain,
                )[0]
                db_domain_info.related_tlds.add(domain_related)

            for _ip in historical_ips:
                historical_ip = HistoricalIP.objects.get_or_create(
                    ip=_ip['ip'],
                    owner=_ip['owner'],
                    location=_ip['location'],
                    last_seen=_ip['last_seen'],
                )[0]
                db_domain_info.historical_ips.add(historical_ip)
            domain.domain_info = db_domain_info
            domain.save()

        command = f'netlas host {ip_domain} -f json'
        # check if netlas key is provided
        netlas_key = get_netlas_key()
        command += f' -a {netlas_key}' if netlas_key else ''

        result = subprocess.check_output(command.split()).decode('utf-8')
        if 'Failed to parse response data' in result:
            # do fallback
            return {
                'status': False,
                'ip_domain': ip_domain,
                'result': "Netlas limit exceeded.",
                'message': 'Netlas limit exceeded.'
            }
        try:
            netlas_result = json.loads(result)
            line_str = json.dumps(netlas_result, indent=2)
            logger.debug(line_str)
            whois = netlas_result.get('whois') or {}

            domain_info.created = whois.get('created_date')
            domain_info.expires = whois.get('expiration_date')
            domain_info.updated = whois.get('updated_date')
            domain_info.whois_server = whois.get('whois_server')


            if 'registrant' in whois:
                registrant = whois.get('registrant')
                domain_info.registrant_name = registrant.get('name')
                domain_info.registrant_country = registrant.get('country')
                domain_info.registrant_id = registrant.get('id')
                domain_info.registrant_state = registrant.get('province')
                domain_info.registrant_city = registrant.get('city')
                domain_info.registrant_phone = registrant.get('phone')
                domain_info.registrant_address = registrant.get('street')
                domain_info.registrant_organization = registrant.get('organization')
                domain_info.registrant_fax = registrant.get('fax')
                domain_info.registrant_zip_code = registrant.get('postal_code')
                email_search = EMAIL_REGEX.search(str(registrant.get('email')))
                field_content = email_search.group(0) if email_search else None
                domain_info.registrant_email = field_content

            if 'administrative' in whois:
                administrative = whois.get('administrative')
                domain_info.admin_name = administrative.get('name')
                domain_info.admin_country = administrative.get('country')
                domain_info.admin_id = administrative.get('id')
                domain_info.admin_state = administrative.get('province')
                domain_info.admin_city = administrative.get('city')
                domain_info.admin_phone = administrative.get('phone')
                domain_info.admin_address = administrative.get('street')
                domain_info.admin_organization = administrative.get('organization')
                domain_info.admin_fax = administrative.get('fax')
                domain_info.admin_zip_code = administrative.get('postal_code')
                email_search = EMAIL_REGEX.search(str(administrative.get('email')))
                field_content = email_search.group(0) if email_search else None
                domain_info.admin_email = field_content

            if 'technical' in whois:
                technical = whois.get('technical')
                domain_info.tech_name = technical.get('name')
                domain_info.tech_country = technical.get('country')
                domain_info.tech_state = technical.get('province')
                domain_info.tech_id = technical.get('id')
                domain_info.tech_city = technical.get('city')
                domain_info.tech_phone = technical.get('phone')
                domain_info.tech_address = technical.get('street')
                domain_info.tech_organization = technical.get('organization')
                domain_info.tech_fax = technical.get('fax')
                domain_info.tech_zip_code = technical.get('postal_code')
                email_search = EMAIL_REGEX.search(str(technical.get('email')))
                field_content = email_search.group(0) if email_search else None
                domain_info.tech_email = field_content

            if 'dns' in netlas_result:
                dns = netlas_result.get('dns')
                domain_info.mx_records = dns.get('mx')
                domain_info.txt_records = dns.get('txt')
                domain_info.a_records = dns.get('a')

            domain_info.ns_records = whois.get('name_servers')
            domain_info.dnssec = bool(whois.get('dnssec'))
            domain_info.status = whois.get('status')

            if 'registrar' in whois:
                registrar = whois.get('registrar')
                domain_info.registrar_name = registrar.get('name')
                domain_info.registrar_email = registrar.get('email')
                domain_info.registrar_phone = registrar.get('phone')
                domain_info.registrar_url = registrar.get('url')

            netlas_related_domains = netlas_result.get('related_domains') or {}
            for _domain in netlas_related_domains:
                domain_related = RelatedDomain.objects.get_or_create(
                    name=_domain
                )[0]
                db_domain_info.related_domains.add(domain_related)
                related_domains_list.append(_domain)

            # find associated domains if registrant email is found
            related_domains = reverse_whois(domain_info.get('registrant_email')) if domain_info.get('registrant_email') else []
            related_domains_list.extend(_domain['name'] for _domain in related_domains)
            # remove duplicate domains from related domains list
            related_domains_list = list(set(related_domains_list))
            domain_info.related_domains = related_domains_list

            # save to db if domain exists
            if Domain.objects.filter(name=ip_domain).exists():
                domain = Domain.objects.get(name=ip_domain)
                db_domain_info = domain.domain_info or DomainInfo()
                db_domain_info.save()
                for _domain in related_domains:
                    domain_rel = RelatedDomain.objects.get_or_create(
                        name=_domain['name'],
                    )[0]
                    db_domain_info.related_domains.add(domain_rel)

                db_domain_info.dnssec = domain_info.get('dnssec')
                #dates
                db_domain_info.created = domain_info.get('created')
                db_domain_info.updated = domain_info.get('updated')
                db_domain_info.expires = domain_info.get('expires')
                #registrar
                db_domain_info.registrar = Registrar.objects.get_or_create(
                    name=domain_info.get('registrar_name'),
                    email=domain_info.get('registrar_email'),
                    phone=domain_info.get('registrar_phone'),
                    url=domain_info.get('registrar_url'),
                )[0]
                db_domain_info.registrant = DomainRegistration.objects.get_or_create(
                    name=domain_info.get('registrant_name'),
                    organization=domain_info.get('registrant_organization'),
                    address=domain_info.get('registrant_address'),
                    city=domain_info.get('registrant_city'),
                    state=domain_info.get('registrant_state'),
                    zip_code=domain_info.get('registrant_zip_code'),
                    country=domain_info.get('registrant_country'),
                    email=domain_info.get('registrant_email'),
                    phone=domain_info.get('registrant_phone'),
                    fax=domain_info.get('registrant_fax'),
                    id_str=domain_info.get('registrant_id'),
                )[0]
                db_domain_info.admin = DomainRegistration.objects.get_or_create(
                    name=domain_info.get('admin_name'),
                    organization=domain_info.get('admin_organization'),
                    address=domain_info.get('admin_address'),
                    city=domain_info.get('admin_city'),
                    state=domain_info.get('admin_state'),
                    zip_code=domain_info.get('admin_zip_code'),
                    country=domain_info.get('admin_country'),
                    email=domain_info.get('admin_email'),
                    phone=domain_info.get('admin_phone'),
                    fax=domain_info.get('admin_fax'),
                    id_str=domain_info.get('admin_id'),
                )[0]
                db_domain_info.tech = DomainRegistration.objects.get_or_create(
                    name=domain_info.get('tech_name'),
                    organization=domain_info.get('tech_organization'),
                    address=domain_info.get('tech_address'),
                    city=domain_info.get('tech_city'),
                    state=domain_info.get('tech_state'),
                    zip_code=domain_info.get('tech_zip_code'),
                    country=domain_info.get('tech_country'),
                    email=domain_info.get('tech_email'),
                    phone=domain_info.get('tech_phone'),
                    fax=domain_info.get('tech_fax'),
                    id_str=domain_info.get('tech_id'),
                )[0]
                for status in domain_info.get('status') or []:
                    _status = WhoisStatus.objects.get_or_create(
                        name=status
                    )[0]
                    _status.save()
                    db_domain_info.status.add(_status)

                for ns in domain_info.get('ns_records') or []:
                    _ns = NameServer.objects.get_or_create(
                        name=ns
                    )[0]
                    _ns.save()
                    db_domain_info.name_servers.add(_ns)

                for a in domain_info.get('a_records') or []:
                    _a = DNSRecord.objects.get_or_create(
                        name=a,
                        type='a'
                    )[0]
                    _a.save()
                    db_domain_info.dns_records.add(_a)
                for mx in domain_info.get('mx_records') or []:
                    _mx = DNSRecord.objects.get_or_create(
                        name=mx,
                        type='mx'
                    )[0]
                    _mx.save()
                    db_domain_info.dns_records.add(_mx)
                for txt in domain_info.get('txt_records') or []:
                    _txt = DNSRecord.objects.get_or_create(
                        name=txt,
                        type='txt'
                    )[0]
                    _txt.save()
                    db_domain_info.dns_records.add(_txt)

                db_domain_info.geolocation_iso = domain_info.get('registrant_country')
                db_domain_info.whois_server = domain_info.get('whois_server')
                db_domain_info.save()
                domain.domain_info = db_domain_info
                domain.save()

        except Exception as e:
            logger.error(f'Error fetching records from WHOIS database: {str(e)}')
            return {
                'status': False,
                'ip_domain': ip_domain,
                'result': "unable to fetch records from WHOIS database.",
                'message': str(e)
            }

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
        # 'similar_domains': domain_info.get('similar_domains'),
        'related_domains': domain_info.get('related_domains'),
        'related_tlds': domain_info.get('related_tlds'),
        'historical_ips': domain_info.get('historical_ips'),
    }


@app.task(name='query_reverse_whois', bind=False, queue='io_queue')
def query_reverse_whois(lookup_keyword):
    """Queries Reverse WHOIS information for an organization or email address.

    Args:
        lookup_keyword (str): Registrar Name or email
    Returns:
        dict: Reverse WHOIS information.
    """

    return get_associated_domains(lookup_keyword)


@app.task(name='query_ip_history', bind=False, queue='io_queue')
def query_ip_history(domain):
    """Queries the IP history for a domain

    Args:
        domain (str): domain_name
    Returns:
        list: list of historical ip addresses
    """

    return get_domain_historical_ip_address(domain) 