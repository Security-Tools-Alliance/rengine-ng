"""
DNS tasks for WHOIS queries, reverse DNS lookups, and IP range discovery.

This module provides functionality for DNS-related operations including
WHOIS queries, reverse DNS lookups, and IP range discovery.
"""

import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import IPv4Network
from typing import Any, Dict, List, Optional, Union

from asgiref.sync import async_to_sync
from celery.utils.log import get_task_logger
from channels.layers import get_channel_layer
from django.utils import timezone
from dotted_dict import DottedDict
import tldextract

from reNgine.celery import app
from reNgine.common_serializers import (
    DomainDNSRecordSerializer,
    DomainWhoisStatusSerializer,
    HistoricalIPSerializer,
    NameServersSerializer,
    RelatedDomainSerializer,
)
from reNgine.definitions import EMAIL_REGEX
from reNgine.settings import DEFAULT_THREADS
from reNgine.utilities.distributed import (
    get_distributed_utilities,
    ProcessorType,
    create_balanced_config,
    DistributedDNSProcessor,
    DistributedNetworkResult,
    DistributedCommandExecutor,
    DistributedCommandBuilder
)
from reNgine.utilities.core import (
    is_iterable,
    chunk_list,
    remove_duplicates,
    is_valid_ip,
    is_valid_domain
)
from reNgine.utilities.core import (
    resolve_hostname,
    reverse_dns_lookup,
    get_common_ports
)
from reNgine.utilities.external import (
    get_associated_domains,
    get_domain_historical_ip_address,
    get_netlas_key,
    reverse_whois,
)
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


logger = get_task_logger(__name__)


class DNSProcessor:
    """DNS processor using distributed utilities"""
    
    def __init__(self, config=None):
        self.distributed_utils = get_distributed_utilities(config)
        self.dns_processor = self.distributed_utils.get_dns_processor()
        self.command_processor = self.distributed_utils.get_command_processor()
    
    def resolve_domains_batch(
        self,
        domains: List[str],
        batch_id: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Resolve multiple domains using distributed DNS processor"""
        try:
            result = self.dns_processor.resolve_domains_batch(
                domains, batch_id, **kwargs
            )
            
            return {
                "success": result.is_successful,
                "batch_id": batch_id,
                "total_domains": len(domains),
                "resolved_domains": result.data.get("resolved_domains", []),
                "failed_domains": result.data.get("failed_domains", []),
                "errors": result.errors,
                "processing_time": result.processing_time
            }
            
        except Exception as e:
            logger.error(f"DNS resolution batch processing failed for batch {batch_id}: {e}")
            return {
                "success": False,
                "batch_id": batch_id,
                "error": str(e),
                "total_domains": len(domains)
            }
    
    def reverse_dns_lookup_batch(
        self,
        ips: List[str],
        batch_id: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Perform reverse DNS lookup for multiple IPs using distributed DNS processor"""
        try:
            # Use the method that returns a dictionary directly
            result = self.dns_processor.reverse_dns_lookup_batch(
                ips, batch_id, **kwargs
            )
            
            # The result is already in the correct format, just add batch_id
            result["batch_id"] = batch_id
            return result
            
        except Exception as e:
            logger.error(f"Reverse DNS lookup batch processing failed for batch {batch_id}: {e}")
            return {
                "success": False,
                "batch_id": batch_id,
                "error": str(e),
                "total_ips": len(ips)
            }
    
    def build_tlsx_command(
        self,
        host: str,
        output_file: str,
        flags: List[str] = None
    ) -> str:
        """Build tlsx command using distributed command builder"""
        if flags is None:
            flags = ["-san", "-cn", "-silent", "-ro"]
        
        command_builder = DistributedCommandBuilder("tlsx")
        
        # Add flags
        for flag in flags:
            command_builder.add_flag(flag)
        
        # Add host
        command_builder.add_option("-host", host)
        
        # Add output file
        command_builder.add_option("-o", output_file)
        
        return command_builder.build()
    
    def execute_tlsx_command(
        self,
        host: str,
        output_file: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Execute tlsx command using distributed command processor"""
        try:
            command = self.build_tlsx_command(host, output_file)
            
            result = self.command_processor.execute_commands_batch(
                [command], "tlsx_command", timeout=300, **kwargs
            )
            
            if result.is_successful:
                return {
                    "success": True,
                    "command": command,
                    "output_file": output_file,
                    "execution_time": result.processing_time
                }
            else:
                return {
                    "success": False,
                    "command": command,
                    "error": result.errors[0] if result.errors else "Unknown error",
                    "execution_time": result.processing_time
                }
                
        except Exception as e:
            logger.error(f"TLSx command execution failed: {e}")
            return {
                "success": False,
                "command": command,
                "error": str(e),
                "execution_time": 0
            }


# Celery tasks

@app.task(name="query_whois", bind=False, queue="io_queue")
def query_whois(ip_domain, force_reload_whois=False):
    """Query WHOIS information for an IP or a domain name.

    Args:
        ip_domain (str): IP address or domain name.
        force_reload_whois (bool): Whether to force reload WHOIS information.
    Returns:
        dict: WHOIS information.
    """
    if (
        not force_reload_whois
        and Domain.objects.filter(name=ip_domain).exists()
        and Domain.objects.get(name=ip_domain).domain_info
    ):
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
            status=[status["name"] for status in DomainWhoisStatusSerializer(domain_info_db.status, many=True).data],
            whois_server=domain_info_db.whois_server,
            ns_records=[ns["name"] for ns in NameServersSerializer(domain_info_db.name_servers, many=True).data],
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
                domain["name"] for domain in RelatedDomainSerializer(domain_info_db.related_tlds, many=True).data
            ],
            related_domains=[
                domain["name"] for domain in RelatedDomainSerializer(domain_info_db.related_domains, many=True).data
            ],
            historical_ips=list(HistoricalIPSerializer(domain_info_db.historical_ips, many=True).data),
        )
        if domain_info_db.dns_records:
            a_records = []
            txt_records = []
            mx_records = []
            dns_records = [
                {"name": dns["name"], "type": dns["type"]}
                for dns in DomainDNSRecordSerializer(domain_info_db.dns_records, many=True).data
            ]
            for dns in dns_records:
                if dns["type"] == "a":
                    a_records.append(dns["name"])
                elif dns["type"] == "txt":
                    txt_records.append(dns["name"])
                elif dns["type"] == "mx":
                    mx_records.append(dns["name"])
            domain_info.a_records = a_records
            domain_info.txt_records = txt_records
            domain_info.mx_records = mx_records
    else:
        logger.info(f'Domain info for "{ip_domain}" not found in DB, querying whois')
        domain_info = DottedDict()
        
        # Use distributed DNS processor for network operations
        dns_processor = DNSProcessor()
        
        # find domain historical ip
        try:
            historical_ips = get_domain_historical_ip_address(ip_domain)
            domain_info.historical_ips = historical_ips
        except Exception as e:
            logger.error(f"HistoricalIP for {ip_domain} not found!\nError: {str(e)}")
            historical_ips = []
        
        # find associated domains using ip_domain
        try:
            related_domains = reverse_whois(ip_domain.split(".")[0])
        except Exception as e:
            logger.error(f"Associated domain not found for {ip_domain}\nError: {str(e)}")
        
        # find related tlds using TLSx
        try:
            related_tlds = []
            output_path = "/tmp/ip_domain_tlsx.txt"
            
            # Use distributed command processor for tlsx
            tlsx_result = dns_processor.execute_tlsx_command(ip_domain, output_path)
            
            if tlsx_result["success"]:
                tlsx_output = []
                with open(output_path) as f:
                    tlsx_output = f.readlines()

                tldextract_target = tldextract.extract(ip_domain)
                for doms in tlsx_output:
                    doms = doms.strip()
                    tldextract_res = tldextract.extract(doms)
                    if (
                        ip_domain != doms
                        and tldextract_res.domain == tldextract_target.domain
                        and tldextract_res.subdomain == ""
                    ):
                        related_tlds.append(doms)

                related_tlds = list(set(related_tlds))
                domain_info.related_tlds = related_tlds
        except Exception as e:
            logger.error(f"Associated domain not found for {ip_domain}\nError: {str(e)}")

        related_domains_list = []
        if Domain.objects.filter(name=ip_domain).exists():
            domain = Domain.objects.get(name=ip_domain)
            db_domain_info = domain.domain_info or DomainInfo()
            db_domain_info.save()
            for _domain in related_domains:
                domain_related = RelatedDomain.objects.get_or_create(
                    name=_domain["name"],
                )[0]
                db_domain_info.related_domains.add(domain_related)
                related_domains_list.append(_domain["name"])

            for _domain in related_tlds:
                domain_related = RelatedDomain.objects.get_or_create(
                    name=_domain,
                )[0]
                db_domain_info.related_tlds.add(domain_related)

            for _ip in historical_ips:
                historical_ip = HistoricalIP.objects.get_or_create(
                    ip=_ip["ip"],
                    owner=_ip["owner"],
                    location=_ip["location"],
                    last_seen=_ip["last_seen"],
                )[0]
                db_domain_info.historical_ips.add(historical_ip)
            domain.domain_info = db_domain_info
            domain.save()

        command = f"netlas host {ip_domain} -f json"
        # check if netlas key is provided
        netlas_key = get_netlas_key()
        command += f" -a {netlas_key}" if netlas_key else ""

        result = subprocess.check_output(command.split()).decode("utf-8")
        if "Failed to parse response data" in result:
            # do fallback
            return {
                "status": False,
                "ip_domain": ip_domain,
                "result": "Netlas limit exceeded.",
                "message": "Netlas limit exceeded.",
            }
        try:
            netlas_result = json.loads(result)
            line_str = json.dumps(netlas_result, indent=2)
            logger.debug(line_str)
            whois = netlas_result.get("whois") or {}

            domain_info.created = whois.get("created_date")
            domain_info.expires = whois.get("expiration_date")
            domain_info.updated = whois.get("updated_date")
            domain_info.whois_server = whois.get("whois_server")

            if "registrant" in whois:
                registrant = whois.get("registrant")
                domain_info.registrant_name = registrant.get("name")
                domain_info.registrant_country = registrant.get("country")
                domain_info.registrant_id = registrant.get("id")
                domain_info.registrant_state = registrant.get("province")
                domain_info.registrant_city = registrant.get("city")
                domain_info.registrant_phone = registrant.get("phone")
                domain_info.registrant_address = registrant.get("street")
                domain_info.registrant_organization = registrant.get("organization")
                domain_info.registrant_fax = registrant.get("fax")
                domain_info.registrant_zip_code = registrant.get("postal_code")
                email_search = EMAIL_REGEX.search(str(registrant.get("email")))
                field_content = email_search.group(0) if email_search else None
                domain_info.registrant_email = field_content

            if "administrative" in whois:
                administrative = whois.get("administrative")
                domain_info.admin_name = administrative.get("name")
                domain_info.admin_country = administrative.get("country")
                domain_info.admin_id = administrative.get("id")
                domain_info.admin_state = administrative.get("province")
                domain_info.admin_city = administrative.get("city")
                domain_info.admin_phone = administrative.get("phone")
                domain_info.admin_address = administrative.get("street")
                domain_info.admin_organization = administrative.get("organization")
                domain_info.admin_fax = administrative.get("fax")
                domain_info.admin_zip_code = administrative.get("postal_code")
                email_search = EMAIL_REGEX.search(str(administrative.get("email")))
                field_content = email_search.group(0) if email_search else None
                domain_info.admin_email = field_content

            if "technical" in whois:
                technical = whois.get("technical")
                domain_info.tech_name = technical.get("name")
                domain_info.tech_country = technical.get("country")
                domain_info.tech_state = technical.get("province")
                domain_info.tech_id = technical.get("id")
                domain_info.tech_city = technical.get("city")
                domain_info.tech_phone = technical.get("phone")
                domain_info.tech_address = technical.get("street")
                domain_info.tech_organization = technical.get("organization")
                domain_info.tech_fax = technical.get("fax")
                domain_info.tech_zip_code = technical.get("postal_code")
                email_search = EMAIL_REGEX.search(str(technical.get("email")))
                field_content = email_search.group(0) if email_search else None
                domain_info.tech_email = field_content

            if "dns" in netlas_result:
                dns = netlas_result.get("dns")
                domain_info.mx_records = dns.get("mx")
                domain_info.txt_records = dns.get("txt")
                domain_info.a_records = dns.get("a")

            domain_info.ns_records = whois.get("name_servers")
            domain_info.dnssec = bool(whois.get("dnssec"))
            domain_info.status = whois.get("status")

            if "registrar" in whois:
                registrar = whois.get("registrar")
                domain_info.registrar_name = registrar.get("name")
                domain_info.registrar_email = registrar.get("email")
                domain_info.registrar_phone = registrar.get("phone")
                domain_info.registrar_url = registrar.get("url")

            netlas_related_domains = netlas_result.get("related_domains") or {}
            for _domain in netlas_related_domains:
                domain_related = RelatedDomain.objects.get_or_create(name=_domain)[0]
                db_domain_info.related_domains.add(domain_related)
                related_domains_list.append(_domain)

            # find associated domains if registrant email is found
            related_domains = (
                reverse_whois(domain_info.get("registrant_email")) if domain_info.get("registrant_email") else []
            )
            related_domains_list.extend(_domain["name"] for _domain in related_domains)
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
                        name=_domain["name"],
                    )[0]
                    db_domain_info.related_domains.add(domain_rel)

                db_domain_info.dnssec = domain_info.get("dnssec")
                # dates
                db_domain_info.created = domain_info.get("created")
                db_domain_info.updated = domain_info.get("updated")
                db_domain_info.expires = domain_info.get("expires")
                # registrar
                db_domain_info.registrar = Registrar.objects.get_or_create(
                    name=domain_info.get("registrar_name"),
                    email=domain_info.get("registrar_email"),
                    phone=domain_info.get("registrar_phone"),
                    url=domain_info.get("registrar_url"),
                )[0]
                db_domain_info.registrant = DomainRegistration.objects.get_or_create(
                    name=domain_info.get("registrant_name"),
                    organization=domain_info.get("registrant_organization"),
                    address=domain_info.get("registrant_address"),
                    city=domain_info.get("registrant_city"),
                    state=domain_info.get("registrant_state"),
                    zip_code=domain_info.get("registrant_zip_code"),
                    country=domain_info.get("registrant_country"),
                    email=domain_info.get("registrant_email"),
                    phone=domain_info.get("registrant_phone"),
                    fax=domain_info.get("registrant_fax"),
                    id_str=domain_info.get("registrant_id"),
                )[0]
                db_domain_info.admin = DomainRegistration.objects.get_or_create(
                    name=domain_info.get("admin_name"),
                    organization=domain_info.get("admin_organization"),
                    address=domain_info.get("admin_address"),
                    city=domain_info.get("admin_city"),
                    state=domain_info.get("admin_state"),
                    zip_code=domain_info.get("admin_zip_code"),
                    country=domain_info.get("admin_country"),
                    email=domain_info.get("admin_email"),
                    phone=domain_info.get("admin_phone"),
                    fax=domain_info.get("admin_fax"),
                    id_str=domain_info.get("admin_id"),
                )[0]
                db_domain_info.tech = DomainRegistration.objects.get_or_create(
                    name=domain_info.get("tech_name"),
                    organization=domain_info.get("tech_organization"),
                    address=domain_info.get("tech_address"),
                    city=domain_info.get("tech_city"),
                    state=domain_info.get("tech_state"),
                    zip_code=domain_info.get("tech_zip_code"),
                    country=domain_info.get("tech_country"),
                    email=domain_info.get("tech_email"),
                    phone=domain_info.get("tech_phone"),
                    fax=domain_info.get("tech_fax"),
                    id_str=domain_info.get("tech_id"),
                )[0]
                for status in domain_info.get("status") or []:
                    _status = WhoisStatus.objects.get_or_create(name=status)[0]
                    _status.save()
                    db_domain_info.status.add(_status)

                for ns in domain_info.get("ns_records") or []:
                    _ns = NameServer.objects.get_or_create(name=ns)[0]
                    _ns.save()
                    db_domain_info.name_servers.add(_ns)

                for a in domain_info.get("a_records") or []:
                    _a = DNSRecord.objects.get_or_create(name=a, type="a")[0]
                    _a.save()
                    db_domain_info.dns_records.add(_a)
                for mx in domain_info.get("mx_records") or []:
                    _mx = DNSRecord.objects.get_or_create(name=mx, type="mx")[0]
                    _mx.save()
                    db_domain_info.dns_records.add(_mx)
                for txt in domain_info.get("txt_records") or []:
                    _txt = DNSRecord.objects.get_or_create(name=txt, type="txt")[0]
                    _txt.save()
                    db_domain_info.dns_records.add(_txt)

                db_domain_info.geolocation_iso = domain_info.get("registrant_country")
                db_domain_info.whois_server = domain_info.get("whois_server")
                db_domain_info.save()
                domain.domain_info = db_domain_info
                domain.save()

        except Exception as e:
            logger.error(f"Error fetching records from WHOIS database: {str(e)}")
            return {
                "status": False,
                "ip_domain": ip_domain,
                "result": "unable to fetch records from WHOIS database.",
                "message": str(e),
            }

    return {
        "status": True,
        "ip_domain": ip_domain,
        "dnssec": domain_info.get("dnssec"),
        "created": domain_info.get("created"),
        "updated": domain_info.get("updated"),
        "expires": domain_info.get("expires"),
        "geolocation_iso": domain_info.get("registrant_country"),
        "domain_statuses": domain_info.get("status"),
        "whois_server": domain_info.get("whois_server"),
        "dns": {
            "a": domain_info.get("a_records"),
            "mx": domain_info.get("mx_records"),
            "txt": domain_info.get("txt_records"),
        },
        "registrar": {
            "name": domain_info.get("registrar_name"),
            "phone": domain_info.get("registrar_phone"),
            "email": domain_info.get("registrar_email"),
            "url": domain_info.get("registrar_url"),
        },
        "registrant": {
            "name": domain_info.get("registrant_name"),
            "id": domain_info.get("registrant_id"),
            "organization": domain_info.get("registrant_organization"),
            "address": domain_info.get("registrant_address"),
            "city": domain_info.get("registrant_city"),
            "state": domain_info.get("registrant_state"),
            "zipcode": domain_info.get("registrant_zip_code"),
            "country": domain_info.get("registrant_country"),
            "phone": domain_info.get("registrant_phone"),
            "fax": domain_info.get("registrant_fax"),
            "email": domain_info.get("registrant_email"),
        },
        "admin": {
            "name": domain_info.get("admin_name"),
            "id": domain_info.get("admin_id"),
            "organization": domain_info.get("admin_organization"),
            "address": domain_info.get("admin_address"),
            "city": domain_info.get("admin_city"),
            "state": domain_info.get("admin_state"),
            "zipcode": domain_info.get("admin_zip_code"),
            "country": domain_info.get("admin_country"),
            "phone": domain_info.get("admin_phone"),
            "fax": domain_info.get("admin_fax"),
            "email": domain_info.get("admin_email"),
        },
        "technical_contact": {
            "name": domain_info.get("tech_name"),
            "id": domain_info.get("tech_id"),
            "organization": domain_info.get("tech_organization"),
            "address": domain_info.get("tech_address"),
            "city": domain_info.get("tech_city"),
            "state": domain_info.get("tech_state"),
            "zipcode": domain_info.get("tech_zip_code"),
            "country": domain_info.get("tech_country"),
            "phone": domain_info.get("tech_phone"),
            "fax": domain_info.get("tech_fax"),
            "email": domain_info.get("tech_email"),
        },
        "nameservers": domain_info.get("ns_records"),
        "related_domains": domain_info.get("related_domains"),
        "related_tlds": domain_info.get("related_tlds"),
        "historical_ips": domain_info.get("historical_ips"),
    }


@app.task(name="query_reverse_whois", bind=False, queue="io_queue")
def query_reverse_whois(lookup_keyword):
    """Queries Reverse WHOIS information for an organization or email address.

    Args:
        lookup_keyword (str): Registrar Name or email
    Returns:
        dict: Reverse WHOIS information.
    """

    return get_associated_domains(lookup_keyword)


@app.task(name="query_ip_history", bind=False, queue="io_queue")
def query_ip_history(domain):
    """Queries the IP history for a domain

    Args:
        domain (str): domain_name
    Returns:
        list: list of historical ip addresses
    """

    return get_domain_historical_ip_address(domain)


@app.task(name="ip_range_discovery", bind=False, queue="io_queue")
def ip_range_discovery(ip_address, scan_id, custom_dns=None, use_system_fallback=False, chunk_size=50):
    """
    Parallel host discovery on IP range using Celery

    Args:
        ip_address (str): IP range (e.g., 192.168.1.0/24)
        scan_id (str): Unique scan ID for WebSocket
        custom_dns (str): Custom DNS servers (comma-separated)
        use_system_fallback (bool): Use system DNS as fallback
        chunk_size (int): Chunk size for parallelization

    Returns:
        dict: Discovery results
    """
    try:
        logger.info(f"Starting IP range discovery for {ip_address} with scan_id {scan_id}")

        # Initialize WebSocket
        channel_layer = get_channel_layer()
        room_group_name = f"ip-scan-{scan_id}"

        def send_progress(percentage, message, details="", log_message=None, log_type="info"):
            if channel_layer:
                try:
                    async_to_sync(channel_layer.group_send)(
                        room_group_name,
                        {
                            "type": "scan_progress",
                            "message": {
                                "percentage": percentage,
                                "message": message,
                                "details": details,
                                "scan_id": scan_id,
                                "log_message": log_message,
                                "log_type": log_type,
                            },
                        },
                    )
                except Exception as e:
                    logger.debug(f"WebSocket send failed: {e}")

        # DNS configuration
        from reNgine.utilities.dns import get_current_dns_servers

        current_dns_servers = get_current_dns_servers()
        dns_servers = []

        if custom_dns:
            dns_servers = [dns.strip() for dns in custom_dns.split(",") if dns.strip()]
            send_progress(
                10,
                "Custom DNS configured",
                f"Using: {', '.join(dns_servers)}",
                f"Custom DNS servers: {', '.join(dns_servers)}",
                "success",
            )

            if use_system_fallback:
                dns_servers.extend(current_dns_servers)
                send_progress(
                    15,
                    "System DNS added as fallback",
                    f"Total: {len(dns_servers)} servers",
                    f"System DNS added: {', '.join(current_dns_servers)}",
                    "warning",
                )
        else:
            dns_servers = current_dns_servers
            send_progress(
                10,
                "Using system DNS",
                f"Servers: {', '.join(dns_servers)}",
                f"System DNS servers: {', '.join(dns_servers)}",
                "info",
            )

        # Parse IP range
        from ipaddress import AddressValueError

        try:
            # Try to parse as network (CIDR)
            ip_list = list(IPv4Network(ip_address, False))
        except AddressValueError:
            # Single IP address, convert to /32 network
            ip_list = list(IPv4Network(f"{ip_address}/32", False))

        total_ips = len(ip_list)

        send_progress(
            20, f"Processing {total_ips} IP addresses", f"Chunking into groups of {chunk_size} for parallel processing"
        )

        # Use distributed DNS processor for resolution
        dns_processor = DNSProcessor()
        
        # Process IPs in chunks using distributed processing
        send_progress(
            20, f"Processing {len(ip_list)} IPs", f"Using distributed DNS processing with {chunk_size} chunk size"
        )

        # Process in chunks directly with detailed progress
        resolved_ips = []
        discovered_domains = set()

        chunks = [ip_list[i : i + chunk_size] for i in range(0, len(ip_list), chunk_size)]
        total_chunks = len(chunks)

        # Send initial progress for chunk processing
        send_progress(25, "Starting DNS resolution", f"Will process {total_chunks} chunks of {chunk_size} IPs each")
        
        # Process chunks in parallel using ThreadPoolExecutor
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        send_progress(30, "Starting parallel DNS processing", f"Processing {total_chunks} chunks in parallel", "Starting parallel DNS processing", "info")
        
        with ThreadPoolExecutor(max_workers=min(total_chunks, 10)) as executor:
            # Submit all chunk processing tasks
            future_to_chunk = {
                executor.submit(
                    dns_processor.reverse_dns_lookup_batch, 
                    [str(ip) for ip in chunk], 
                    f"ip_chunk_{i}",
                    dns_servers=dns_servers,
                    use_system_fallback=use_system_fallback
                ): (i, chunk) 
                for i, chunk in enumerate(chunks)
            }
            
            completed_chunks = 0
            
            # Collect results as they complete
            for future in as_completed(future_to_chunk):
                chunk_index, chunk = future_to_chunk[future]
                completed_chunks += 1
                
                try:
                    chunk_results = future.result()
                    
                    # Add results and update progress
                    if chunk_results["success"]:
                        logger.info(f"Chunk {chunk_index} successful: {len(chunk_results.get('resolved_ips', []))} results")
                        for result in chunk_results.get("resolved_ips", []):
                            if result and result.get("domain") != result.get("ip"):
                                discovered_domains.add(result["domain"])
                                logger.debug(f"Found domain: {result['domain']} for IP: {result['ip']}")
                            resolved_ips.append(result)
                    else:
                        logger.warning(f"Chunk {chunk_index} failed, using fallback")
                        # Fallback to individual resolution
                        from reNgine.utilities.dns import resolve_ip_chunk
                        chunk_results = resolve_ip_chunk(
                            ip_chunk=[str(ip) for ip in chunk], dns_servers=dns_servers, use_system_fallback=use_system_fallback
                        )
                        for result in chunk_results:
                            if result and result.get("domain") != result.get("ip"):
                                discovered_domains.add(result["domain"])
                            resolved_ips.append(result)
                    
                    # Send progress update
                    progress_percent = min(int(30 + (completed_chunks * 50 / total_chunks)), 80)
                    send_progress(
                        progress_percent,
                        f"Completed DNS chunk {chunk_index + 1}/{total_chunks}",
                        f"Processed {completed_chunks}/{total_chunks} chunks ({len(discovered_domains)} domains found)",
                        f"Completed DNS chunk {chunk_index + 1}/{total_chunks}",
                        "info"
                    )
                    
                except Exception as e:
                    logger.error(f"Error processing DNS chunk {chunk_index + 1}: {e}")
                    # Fallback: mark all hosts in chunk as failed
                    for ip in chunk:
                        resolved_ips.append({
                            "ip": str(ip),
                            "domain": str(ip),
                            "domains": [],
                            "ips": [],
                            "resolved_by": None,
                            "is_alive": False
                        })
                    
                    # Send error progress update
                    progress_percent = min(int(30 + (completed_chunks * 50 / total_chunks)), 80)
                    send_progress(
                        progress_percent,
                        f"Error in DNS chunk {chunk_index + 1}/{total_chunks}",
                        f"Chunk failed, using fallback",
                        f"Error in DNS chunk {chunk_index + 1}/{total_chunks}",
                        "warning"
                    )

        send_progress(80, "DNS discovery completed", "Ready for ping checks")

        # Sort results
        resolved_ips.sort(key=lambda x: (x["domain"] == x["ip"], x["ip"]))

        send_progress(90, "Consolidating results", "Sorting and formatting results")

        # Final statistics
        hostname_count = sum(ip["domain"] != ip["ip"] for ip in resolved_ips)

        send_progress(95, "Finalizing results", f"Found {len(resolved_ips)} hosts ({hostname_count} with hostnames)")

        response = {
            "status": True,
            "orig": ip_address,
            "ip_address": resolved_ips,
            "discovered_domains": list(discovered_domains),
            "current_dns_servers": current_dns_servers,
            "used_dns_servers": dns_servers,
            "scan_id": scan_id,
            "total_hosts": len(resolved_ips),
            "hostname_count": hostname_count,
            "ping_required": True,  # Indicate that ping task is needed
        }

        send_progress(100, "Scan completed!", "Ready for target selection")

        logger.info(f"IP range discovery completed for {ip_address}: {len(resolved_ips)} hosts found")
        return response

    except Exception as e:
        logger.exception(f"Error in IP range discovery: {e}")
        if channel_layer:
            try:
                async_to_sync(channel_layer.group_send)(
                    room_group_name,
                    {
                        "type": "scan_progress",
                        "message": {
                            "percentage": 100,
                            "message": "Error occurred",
                            "details": f"Failed: {str(e)}",
                            "scan_id": scan_id,
                            "log_message": f"Error: {str(e)}",
                            "log_type": "error",
                        },
                    },
                )
            except Exception:
                pass

        return {"status": False, "ip_address": ip_address, "message": f"Exception: {e}", "scan_id": scan_id}


@app.task(name="ping_hosts_task", bind=False, queue="io_queue")
def ping_hosts_task(ip_list, scan_id=None):
    """
    Celery task to ping multiple hosts in parallel

    Args:
        ip_list (list): List of IP addresses to ping
        scan_id (str): Scan ID for WebSocket updates

    Returns:
        dict: Ping results with is_alive status
    """
    from asgiref.sync import async_to_sync
    from channels.layers import get_channel_layer

    from reNgine.utilities.dns import check_host_alive

    logger.info(f"Starting ping check for {len(ip_list)} hosts")

    # WebSocket for progress updates
    channel_layer = get_channel_layer()
    room_group_name = f"ip-scan-{scan_id}" if scan_id else None

    def send_progress(percentage=None, message="", details="", log_message=None, log_type="info"):
        if channel_layer and room_group_name:
            try:
                message_data = {"log_message": log_message or message, "log_type": log_type, "scan_id": scan_id}

                # Add percentage if provided
                if percentage is not None:
                    message_data["percentage"] = percentage
                    message_data["message"] = message
                    message_data["details"] = details

                async_to_sync(channel_layer.group_send)(
                    room_group_name, {"type": "scan_progress", "message": message_data}
                )
            except Exception as e:
                logger.debug(f"Ping WebSocket error: {e}")
                pass

    results = {}
    alive_count = 0

    # Process pings in parallel using ThreadPoolExecutor
    send_progress(0, "Starting ping checks", f"Checking {len(ip_list)} hosts", "Starting ping checks", "info")

    with ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:
        # Submit all ping tasks
        future_to_ip = {executor.submit(check_host_alive, ip): ip for ip in ip_list}

        # Collect results as they complete
        for i, future in enumerate(as_completed(future_to_ip)):
            ip = future_to_ip[future]
            try:
                is_alive = future.result(timeout=10)
                results[ip] = is_alive
                if is_alive:
                    alive_count += 1

                # Send progress update every 5 pings for better granularity
                if (i + 1) % 5 == 0 or (i + 1) == len(ip_list):
                    progress_percent = int((i + 1) * 100 / len(ip_list))
                    send_progress(
                        percentage=progress_percent,
                        message="Ping check in progress...",
                        details=f"Pinged {i + 1}/{len(ip_list)} hosts ({alive_count} alive)",
                        log_message=f"Pinged {i + 1}/{len(ip_list)} hosts ({alive_count} alive) - {progress_percent}%",
                        log_type="info",
                    )

            except Exception as e:
                logger.debug(f"Ping failed for {ip}: {e}")
                results[ip] = False

    # Send completion message with results
    completion_message = f"Ping completed: {alive_count}/{len(ip_list)} hosts alive"
    
    # Send final results via WebSocket with ping_results included
    if channel_layer and room_group_name:
        try:
            async_to_sync(channel_layer.group_send)(
                room_group_name,
                {
                    "type": "scan_progress",
                    "message": {
                        "percentage": 100,
                        "message": "Ping check completed!",
                        "details": f"{alive_count}/{len(ip_list)} hosts alive",
                        "log_message": completion_message,
                        "log_type": "success",
                        "scan_id": scan_id,
                        "ping_results": results,
                        "alive_count": alive_count,
                        "total_count": len(ip_list),
                        "ping_completed": True,
                    },
                },
            )
        except Exception as e:
            logger.debug(f"WebSocket final results error: {e}")

    return {"status": True, "ping_results": results, "alive_count": alive_count, "total_count": len(ip_list)}


@app.task(name="ping_hosts_distributed", bind=False, queue="io_queue")
def ping_hosts_distributed(ip_list, scan_id=None, chunk_size=50):
    """
    Distributed Celery task to ping multiple hosts using distributed processing
    
    Args:
        ip_list (list): List of IP addresses to ping
        scan_id (str): Scan ID for WebSocket updates
        chunk_size (int): Size of chunks for distributed processing
        
    Returns:
        dict: Ping results with is_alive status
    """
    from asgiref.sync import async_to_sync
    from channels.layers import get_channel_layer
    from reNgine.utilities.distributed.network import DistributedDNSProcessor
    
    logger.info(f"Starting distributed ping check for {len(ip_list)} hosts")
    
    # WebSocket for progress updates
    channel_layer = get_channel_layer()
    room_group_name = f"ip-scan-{scan_id}" if scan_id else None
    
    def send_progress(percentage=None, message="", details="", log_message=None, log_type="info"):
        if channel_layer and room_group_name:
            try:
                message_data = {"log_message": log_message or message, "log_type": log_type, "scan_id": scan_id}
                
                # Add percentage if provided
                if percentage is not None:
                    message_data["percentage"] = percentage
                    message_data["message"] = message
                    message_data["details"] = details
                
                async_to_sync(channel_layer.group_send)(
                    room_group_name, {"type": "scan_progress", "message": message_data}
                )
            except Exception as e:
                logger.debug(f"Ping WebSocket error: {e}")
                pass
    
    # Initialize distributed DNS processor
    dns_processor = DistributedDNSProcessor()
    
    # Process in chunks for better performance
    chunks = [ip_list[i:i + chunk_size] for i in range(0, len(ip_list), chunk_size)]
    total_chunks = len(chunks)
    
    send_progress(0, "Starting distributed ping checks", f"Processing {total_chunks} chunks of {chunk_size} hosts each", "Starting distributed ping checks", "info")
    
    all_results = {}
    total_alive_count = 0
    
    # Process chunks in parallel using ThreadPoolExecutor
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    send_progress(20, "Starting parallel ping processing", f"Processing {total_chunks} chunks in parallel", "Starting parallel ping processing", "info")
    
    with ThreadPoolExecutor(max_workers=min(total_chunks, 10)) as executor:
        # Submit all chunk processing tasks
        future_to_chunk = {
            executor.submit(dns_processor.ping_hosts_batch, chunk, f"ping_chunk_{i}"): (i, chunk) 
            for i, chunk in enumerate(chunks)
        }
        
        completed_chunks = 0
        
        # Collect results as they complete
        for future in as_completed(future_to_chunk):
            chunk_index, chunk = future_to_chunk[future]
            completed_chunks += 1
            
            try:
                chunk_results = future.result()
                
                # Merge results
                if chunk_results.get("success"):
                    all_results.update(chunk_results.get("ping_results", {}))
                    total_alive_count += chunk_results.get("alive_count", 0)
                else:
                    # Fallback: mark all hosts in chunk as dead
                    for ip in chunk:
                        all_results[ip] = False
                
                # Send progress update
                progress_percent = min(int(20 + (completed_chunks * 70 / total_chunks)), 90)
                send_progress(
                    progress_percent,
                    f"Completed chunk {chunk_index + 1}/{total_chunks}",
                    f"Processed {completed_chunks}/{total_chunks} chunks ({total_alive_count} alive hosts found)",
                    f"Completed chunk {chunk_index + 1}/{total_chunks}",
                    "info"
                )
                
            except Exception as e:
                logger.error(f"Error processing chunk {chunk_index + 1}: {e}")
                # Mark all hosts in failed chunk as dead
                for ip in chunk:
                    all_results[ip] = False
                
                # Send error progress update
                progress_percent = min(int(20 + (completed_chunks * 70 / total_chunks)), 90)
                send_progress(
                    progress_percent,
                    f"Error in chunk {chunk_index + 1}/{total_chunks}",
                    f"Chunk failed, marking hosts as dead",
                    f"Error in chunk {chunk_index + 1}/{total_chunks}",
                    "warning"
                )
    
    # Send completion message with results
    completion_message = f"Distributed ping completed: {total_alive_count}/{len(ip_list)} hosts alive"
    
    # Send final results via WebSocket with ping_results included
    if channel_layer and room_group_name:
        try:
            async_to_sync(channel_layer.group_send)(
                room_group_name,
                {
                    "type": "scan_progress",
                    "message": {
                        "percentage": 100,
                        "message": "Distributed ping check completed!",
                        "details": f"{total_alive_count}/{len(ip_list)} hosts alive",
                        "log_message": completion_message,
                        "log_type": "success",
                        "scan_id": scan_id,
                        "ping_results": all_results,
                        "alive_count": total_alive_count,
                        "total_count": len(ip_list),
                        "ping_completed": True,
                    },
                },
            )
        except Exception as e:
            logger.debug(f"WebSocket final results error: {e}")
    
    logger.info(f"Distributed ping check completed for {len(ip_list)} hosts: {total_alive_count} alive")
    return {"status": True, "ping_results": all_results, "alive_count": total_alive_count, "total_count": len(ip_list)}


# Utility functions for easy access

def resolve_domains_distributed(
    domains: List[str],
    **kwargs
) -> Dict[str, Any]:
    """
    Resolve domains using distributed processing.
    """
    processor = DNSProcessor()
    return processor.resolve_domains_batch(
        domains, "domain_resolution", **kwargs
    )


def reverse_dns_lookup_distributed(
    ips: List[str],
    **kwargs
) -> Dict[str, Any]:
    """
    Perform reverse DNS lookup using distributed processing.
    """
    processor = DNSProcessor()
    return processor.reverse_dns_lookup_batch(
        ips, "reverse_dns_lookup", **kwargs
    )


def get_dns_statistics(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get statistics from DNS resolution results.
    
    Args:
        results: DNS resolution results
        
    Returns:
        Statistics dictionary
    """
    if not results:
        return {
            "total_processed": 0,
            "successful_resolutions": 0,
            "failed_resolutions": 0,
            "success_rate": 0
        }
    
    total_processed = results.get("total_domains", 0) or results.get("total_ips", 0)
    successful = len(results.get("resolved_domains", [])) or len(results.get("resolved_ips", []))
    failed = len(results.get("failed_domains", [])) or len(results.get("failed_ips", []))
    
    success_rate = (successful / total_processed * 100) if total_processed > 0 else 0
    
    return {
        "total_processed": total_processed,
        "successful_resolutions": successful,
        "failed_resolutions": failed,
        "success_rate": success_rate
    }
