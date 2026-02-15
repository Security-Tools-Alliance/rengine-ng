import csv
from datetime import timedelta
import io
import ipaddress
import json
from pathlib import Path
from urllib.parse import urlparse

from django import http
from django.conf import settings
from django.contrib import messages
from django.core.serializers.json import DjangoJSONEncoder
from django.db.models import Case, Count, IntegerField, Value, When
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone
from django.utils.safestring import mark_safe
from rolepermissions.decorators import has_permission_decorator
import validators

from api.serializers import IpSerializer
from reNgine.core.data import get_ip_info, get_ips_from_cidr_range
from reNgine.core.path import resolve_results_dir_under_base, safe_rmtree
from reNgine.core.validators import is_valid_cidr
from reNgine.definitions import (
    FOUR_OH_FOUR_URL,
    PERM_MODIFY_TARGETS,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_QUEUED,
    SCAN_STATUS_RUNNING,
    SCAN_STATUS_RUNNING_BACKGROUND,
)
from reNgine.services.repositories import EndpointRepository
from reNgine.utilities.dns import get_reverse_dns
from reNgine.utilities.logger import get_module_logger
from reNgine.utilities.url import sanitize_url
from scanEngine.models import EngineType, SecatorWorker
from startScan.models import (
    CountryISO,
    CveId,
    CweId,
    Email,
    Employee,
    EndPoint,
    IpAddress,
    Port,
    ScanHistory,
    Subdomain,
    Vulnerability,
    VulnerabilityTags,
)
from startScan.secator.profiles import build_secator_profiles_context
from targetApp.forms import (
    AddOrganizationForm,
    AddTargetForm,
    UpdateOrganizationForm,
    UpdateTargetForm,
)
from targetApp.models import (
    Domain,
    Organization,
    Project,
)
from targetApp.utilities import StatsTracker


PREFIX_TARGET = "[TARGET]"
logger = get_module_logger(__name__)


def validate_dns_servers(dns_servers_string):
    """
    Validate a comma-separated string of DNS servers.

    Validates that each entry is either a valid IPv4 address, IPv6 address, or hostname.
    Supports optional port specification (e.g., 8.8.8.8:53).

    Args:
        dns_servers_string (str): Comma-separated DNS servers string

    Returns:
        tuple: (is_valid, error_message, cleaned_servers)
            - is_valid: Boolean indicating if validation passed
            - error_message: Error message if validation failed, None otherwise
            - cleaned_servers: Cleaned and validated DNS servers string

    Examples:
        >>> validate_dns_servers("8.8.8.8,1.1.1.1")
        (True, None, "8.8.8.8,1.1.1.1")

        >>> validate_dns_servers("8.8.8.8,invalid!@#,1.1.1.1")
        (False, "Invalid DNS server: invalid!@#", None)
    """
    if not dns_servers_string:
        return True, None, ""

    # Split by comma and clean up whitespace
    servers = [s.strip() for s in dns_servers_string.split(",") if s.strip()]

    if not servers:
        return True, None, ""

    validated_servers = []

    for server in servers:
        # Split address and port if port is specified
        if ":" in server and not server.count(":") > 1:  # IPv4 with port
            address, port = server.rsplit(":", 1)
            try:
                port_num = int(port)
                if port_num < 1 or port_num > 65535:
                    return False, f"Invalid port number in DNS server: {server}", None
            except ValueError:
                return False, f"Invalid port in DNS server: {server}", None
        elif server.count(":") > 1:  # Likely IPv6
            # Handle IPv6 - could be with or without port
            # For simplicity, we'll treat it as full address for now
            address = server
        else:
            address = server

        # Validate the address part
        is_valid = False

        # Try IPv4
        try:
            ipaddress.IPv4Address(address)
            is_valid = True
        except (ipaddress.AddressValueError, ValueError):
            pass

        # Try IPv6 if IPv4 failed
        if not is_valid:
            try:
                ipaddress.IPv6Address(address)
                is_valid = True
            except (ipaddress.AddressValueError, ValueError):
                pass

        # Try hostname validation if IP validation failed
        if not is_valid and (validators.domain(address) or validators.ipv4(address) or validators.ipv6(address)):
            is_valid = True

        if not is_valid:
            return False, f"Invalid DNS server address: {server}", None

        validated_servers.append(server)

    # Return cleaned servers string
    cleaned = ",".join(validated_servers)
    return True, None, cleaned


def index(request):
    """
    index renders the index page for the target application. It returns the HTML template for the target index view, allowing users to access the main interface for managing targets.

    Args:
        request (HttpRequest): The HTTP request object containing metadata about the request.

    Returns:
        HttpResponse: The rendered HTML response for the target index page.
    """
    # TODO bring default target page
    return render(request, "target/index.html")


@has_permission_decorator(PERM_MODIFY_TARGETS, redirect_url=FOUR_OH_FOUR_URL)
def add_target(request, slug):
    """Add a new target. Targets can be URLs, IPs, CIDR ranges, or Domains.

    Args:
        request: Django request.
    """
    project = Project.objects.get(slug=slug)
    form = AddTargetForm(request.POST or None)
    if request.method == "POST":
        logger.log_line(
            PREFIX_TARGET,
            "ADD_TARGET",
            "POST data received: %s" % (dict(request.POST),),
            level="info",
        )
        total_processed_count = 0
        multiple_targets = request.POST.get("add-multiple-targets")
        ip_target = request.POST.get("add-ip-target")
        try:
            # Multiple targets
            if multiple_targets:
                bulk_targets = [t.rstrip() for t in request.POST["addTargets"].split("\n") if t]
                sanitized_targets = [
                    target if isinstance(target, str) and validators.domain(target) else "Invalid target"
                    for target in bulk_targets
                ]
                logger.log_line(
                    PREFIX_TARGET,
                    "ADD_TARGET",
                    "Adding multiple targets: %s" % (sanitized_targets,),
                    level="info",
                )
                description = request.POST.get("targetDescription", "")
                h1_team_handle = request.POST.get("targetH1TeamHandle")
                organization_name = request.POST.get("targetOrganization")
                for target in bulk_targets:
                    target = target.rstrip("\n")
                    http_urls = []
                    domains = []
                    ports = []
                    ips = []

                    # Validate input and find what type of address it is.
                    # Valid inputs are URLs, Domains, or IP addresses.
                    # TODO: support IP CIDR ranges (auto expand range and
                    # save new found ips to DB)
                    is_domain = bool(validators.domain(target))
                    is_ip = bool(validators.ipv4(target)) or bool(validators.ipv6(target))
                    is_range = is_valid_cidr(target)
                    is_url = bool(validators.url(target))

                    # Set ip_domain / http_url based on type of input
                    sanitized_target = (
                        target if isinstance(target, str) and validators.domain(target) else "Invalid target"
                    )
                    logger.log_line(
                        PREFIX_TARGET,
                        "ADD_TARGET",
                        "%s | Domain? %s | IP? %s | CIDR range? %s | URL? %s"
                        % (sanitized_target, is_domain, is_ip, is_range, is_url),
                        level="info",
                    )

                    if is_domain:
                        domains.append(target)

                    elif is_url:
                        url = urlparse(target)
                        http_url = url.geturl()
                        http_urls.append(http_url)
                        split = url.netloc.split(":")
                        if len(split) == 1:
                            domain = split[0]
                            domains.append(domain)
                        if len(split) == 2:
                            domain, port_number = tuple(split)
                            domains.append(domain)
                            ports.append(port_number)

                    elif is_ip:
                        ips.append(target)
                        domains.append(target)

                    elif is_range:
                        _ips = get_ips_from_cidr_range(target)
                        for ip_address in _ips:
                            ips.append(ip_address)
                            domains.append(ip_address)
                    else:
                        msg = f"{target} is not a valid domain, IP, or URL. Skipped."
                        logger.log_line(
                            PREFIX_TARGET,
                            "ADD_TARGET",
                            msg,
                            level="warning",
                        )
                        messages.add_message(request, messages.WARNING, msg)
                        continue

                    # Sanitize the lists for logging
                    sanitized_ips = [ip if validators.ipv4(ip) or validators.ipv6(ip) else "Invalid IP" for ip in ips]
                    sanitized_domains = [
                        domain if isinstance(domain, str) and validators.domain(domain) else "Invalid Domain"
                        for domain in domains
                    ]
                    sanitized_http_urls = [url if validators.url(url) else "Invalid URL" for url in http_urls]
                    sanitized_ports = [port if isinstance(port, int) else "Invalid Port" for port in ports]
                    logger.log_line(
                        PREFIX_TARGET,
                        "ADD_TARGET",
                        "IPs: %s | Domains: %s | URLs: %s | Ports: %s"
                        % (sanitized_ips, sanitized_domains, sanitized_http_urls, sanitized_ports),
                        level="info",
                    )

                    for domain_name in domains:
                        if not Domain.objects.filter(name=domain_name).exists():
                            domain, created = Domain.objects.get_or_create(
                                name=domain_name,
                                description=description,
                                h1_team_handle=h1_team_handle,
                                project=project,
                                ip_address_cidr=domain_name if is_ip else None,
                            )
                            domain.insert_date = timezone.now()
                            domain.save()
                            total_processed_count += 1
                            if created:
                                logger.log_line(
                                    PREFIX_TARGET,
                                    "ADD_TARGET",
                                    "Added new target %s" % (domain.name,),
                                    level="info",
                                )

                            if organization_name:
                                organization = None
                                organization_query = Organization.objects.filter(name=organization_name)
                                if organization_query.exists():
                                    organization = organization_query[0]
                                else:
                                    organization = Organization.objects.create(
                                        name=organization_name, project=project, insert_date=timezone.now()
                                    )
                                organization.domains.add(domain)

                    for http_url in http_urls:
                        http_url = sanitize_url(http_url)
                        endpoint, created = EndPoint.objects.get_or_create(target_domain=domain, http_url=http_url)
                        if created:
                            logger.log_line(
                                PREFIX_TARGET,
                                "ADD_TARGET",
                                "Added new endpoint %s" % (endpoint.http_url,),
                                level="info",
                            )

                    for ip_address in ips:
                        ip_data = get_ip_info(ip_address)
                        ip, created = IpAddress.objects.get_or_create(address=ip_address)

                        # Perform reverse DNS lookup for accurate reverse pointer
                        ip.reverse_pointer = get_reverse_dns(ip_address)
                        ip.is_private = ip_data.is_private
                        ip.version = ip_data.version
                        ip.save()
                        if created:
                            logger.log_line(
                                PREFIX_TARGET,
                                "ADD_TARGET",
                                "Added new IP %s" % (ip,),
                                level="warning",
                            )

                    for port_number in ports:
                        port, created = Port.objects.get_or_create(
                            number=port_number, defaults={"is_uncommon": port_number not in [80, 443, 8080, 8443]}
                        )
                        if created:
                            logger.log_line(
                                PREFIX_TARGET,
                                "ADD_TARGET",
                                "Added new port %s" % (port.number,),
                                level="warning",
                            )

            # Import from txt / csv
            elif "import-txt-target" in request.POST or "import-csv-target" in request.POST:
                txt_file = request.FILES.get("txtFile")
                csv_file = request.FILES.get("csvFile")
                if not (txt_file or csv_file):
                    messages.add_message(request, messages.ERROR, "Files uploaded are not .txt or .csv files.")
                    return http.HttpResponseRedirect(reverse("add_target", kwargs={"slug": slug}))

                if (txt_file and txt_file.size == 0) or (csv_file and csv_file.size == 0):
                    messages.add_message(
                        request, messages.ERROR, "The uploaded file is empty. Please upload a valid file."
                    )
                    return http.HttpResponseRedirect(reverse("add_target", kwargs={"slug": slug}))

                if txt_file:
                    is_txt = txt_file.content_type == "text/plain" or txt_file.name.split(".")[-1] == "txt"
                    if not is_txt:
                        messages.add_message(request, messages.ERROR, "File is not a valid TXT file")
                        return http.HttpResponseRedirect(reverse("add_target", kwargs={"slug": slug}))
                    txt_content = txt_file.read().decode("UTF-8")
                    io_string = io.StringIO(txt_content)
                    for target in io_string:
                        target_domain = target.rstrip("\n").rstrip("\r")
                        domain = None
                        domain_query = Domain.objects.filter(name=target_domain)
                        if not domain_query.exists():
                            if not validators.domain(target_domain):
                                messages.add_message(
                                    request,
                                    messages.ERROR,
                                    f"Domain {target_domain} is not a valid domain name. Skipping.",
                                )
                                continue
                            Domain.objects.create(name=target_domain, project=project, insert_date=timezone.now())
                            total_processed_count += 1

                elif csv_file:
                    is_csv = csv_file.content_type = "text/csv" or csv_file.name.split(".")[-1] == "csv"
                    if not is_csv:
                        messages.add_message(request, messages.ERROR, "File is not a valid CSV file.")
                        return http.HttpResponseRedirect(reverse("add_target", kwargs={"slug": slug}))
                    csv_content = csv_file.read().decode("UTF-8")
                    io_string = io.StringIO(csv_content)
                    for column in csv.reader(io_string, delimiter=","):
                        domain = column[0]
                        description = None if len(column) <= 1 else column[1]
                        organization = None if len(column) <= 2 else column[2]
                        domain_query = Domain.objects.filter(name=domain)
                        if not domain_query.exists():
                            if not validators.domain(domain):
                                messages.add_message(
                                    request, messages.ERROR, f"Domain {domain} is not a valid domain name. Skipping."
                                )
                                continue
                            domain_obj = Domain.objects.create(
                                name=domain, project=project, description=description, insert_date=timezone.now()
                            )
                            total_processed_count += 1

                            # Optionally add domain to organization
                            if organization:
                                organization_query = Organization.objects.filter(name=organization)
                                if organization_query.exists():
                                    organization = organization_query[0]
                                else:
                                    organization = Organization.objects.create(
                                        name=organization, project=project, insert_date=timezone.now()
                                    )
                                organization.domains.add(domain_obj)
            elif ip_target:
                # add targets from "resolve and add ip address" tab with improved methodology
                from ipaddress import AddressValueError
                import json

                from reNgine.utilities.url import get_domain_from_subdomain
                from startScan.models import Subdomain

                # Get selected items from the form
                discovered_domains = request.POST.getlist("discovered_domains")
                resolved_hosts_data = request.POST.getlist("resolved_hosts")

                target_name = request.POST.get("targetName", "").strip()
                description = request.POST.get("targetDescription", "")
                h1_team_handle = request.POST.get("targetH1TeamHandle")
                original_ip_range = request.POST.get("ip_address", "")
                used_dns_servers = request.POST.get("used_dns_servers", "").strip()

                # Validate DNS servers input for security
                if used_dns_servers:
                    is_valid, error_msg, cleaned_dns = validate_dns_servers(used_dns_servers)
                    if not is_valid:
                        messages.add_message(request, messages.ERROR, f"Invalid DNS servers configuration: {error_msg}")
                        logger.log_line(
                            PREFIX_TARGET,
                            "IP_SCAN",
                            "Invalid DNS servers submitted: %s - %s" % (used_dns_servers, error_msg),
                            level="warning",
                        )
                        context = {"current_project": project}
                        return render(request, "target/add.html", context)
                    used_dns_servers = cleaned_dns

                logger.log_line(
                    PREFIX_TARGET,
                    "IP_SCAN",
                    "Processing IP scan results for %s" % (original_ip_range,),
                    level="info",
                )
                logger.log_line(
                    PREFIX_TARGET,
                    "IP_SCAN",
                    "Target name: %s" % (target_name,),
                    level="info",
                )
                logger.log_line(
                    PREFIX_TARGET,
                    "IP_SCAN",
                    "Selected domains: %s" % (discovered_domains,),
                    level="info",
                )
                logger.log_line(
                    PREFIX_TARGET,
                    "IP_SCAN",
                    "Selected hosts count: %s" % (len(resolved_hosts_data),),
                    level="info",
                )
                logger.log_line(
                    PREFIX_TARGET,
                    "IP_SCAN",
                    "DNS servers used: %s" % (used_dns_servers,),
                    level="info",
                )

                # Parse selected hosts to categorize them and deduplicate
                selected_domains = set()
                selected_hostnames = []
                selected_ips = []
                seen_hostnames = set()
                seen_ips = set()

                # Initialize stats tracker for detailed feedback
                stats = StatsTracker()

                # If target name is provided, create a single target and group everything under it
                if target_name:
                    logger.log_line(
                        PREFIX_TARGET,
                        "IP_SCAN",
                        "Creating single target '%s' to group all selected items" % (target_name,),
                        level="info",
                    )

                    # Create the main target with the provided name
                    main_target, created = Domain.objects.get_or_create(
                        name=target_name,
                        project=project,
                        defaults={
                            "description": description or f"Grouped target from {original_ip_range}",
                            "h1_team_handle": h1_team_handle,
                            "insert_date": timezone.now(),
                            "custom_dns_servers": used_dns_servers if used_dns_servers else None,
                        },
                    )

                    # Update DNS servers if target already exists and DNS was provided
                    if not created and used_dns_servers:
                        # Use select_for_update to prevent race conditions
                        from django.db import transaction

                        with transaction.atomic():
                            main_target_locked = type(main_target).objects.select_for_update().get(pk=main_target.pk)
                            main_target_locked.custom_dns_servers = used_dns_servers
                            main_target_locked.save()
                        logger.log_line(
                            PREFIX_TARGET,
                            "IP_SCAN",
                            "Updated DNS servers for existing target %s" % (main_target.name,),
                            level="info",
                        )

                    stats.domain(created)
                    if created:
                        logger.log_line(
                            PREFIX_TARGET,
                            "IP_SCAN",
                            "Created new grouped target %s with DNS servers: %s" % (main_target.name, used_dns_servers),
                            level="info",
                        )
                    else:
                        logger.log_line(
                            PREFIX_TARGET,
                            "IP_SCAN",
                            "Using existing target %s" % (main_target.name,),
                            level="info",
                        )

                    # Process all selected items as subdomains of the main target
                    logger.log_line(
                        PREFIX_TARGET,
                        "IP_SCAN",
                        "Processing %s selected hosts for target %s" % (len(resolved_hosts_data), main_target.name),
                        level="info",
                    )
                    for i, host_data_json in enumerate(resolved_hosts_data):
                        try:
                            logger.log_line(
                                PREFIX_TARGET,
                                "IP_SCAN",
                                "Processing host %s/%s: %s" % (i + 1, len(resolved_hosts_data), host_data_json),
                                level="debug",
                            )
                            host_info = json.loads(host_data_json.replace("&quot;", '"'))
                            ip = host_info.get("ip")
                            hostname = host_info.get("domain")
                            is_alive = host_info.get("is_alive", False)

                            logger.log_line(
                                PREFIX_TARGET,
                                "IP_SCAN",
                                "Parsed host info - IP: %s, Hostname: %s, Alive: %s" % (ip, hostname, is_alive),
                                level="debug",
                            )

                            # Deduplication: Skip if we've already processed this hostname
                            if hostname in seen_hostnames:
                                logger.log_line(
                                    PREFIX_TARGET,
                                    "IP_SCAN",
                                    "Skipping duplicate hostname: %s" % (hostname,),
                                    level="debug",
                                )
                                continue
                            seen_hostnames.add(hostname)

                            # Create subdomain entry
                            subdomain, created = Subdomain.objects.get_or_create(
                                name=hostname,
                                target_domain=main_target,
                                defaults={
                                    "discovered_date": timezone.now(),
                                },
                            )

                            stats.subdomain(created)
                            if created:
                                logger.log_line(
                                    PREFIX_TARGET,
                                    "IP_SCAN",
                                    "Added subdomain %s to grouped target %s" % (hostname, main_target.name),
                                    level="info",
                                )
                            else:
                                logger.log_line(
                                    PREFIX_TARGET,
                                    "IP_SCAN",
                                    "Subdomain %s already exists for target %s" % (hostname, main_target.name),
                                    level="info",
                                )

                            # Create/update IP address record
                            if validators.ipv4(ip) or validators.ipv6(ip):
                                ip_data = get_ip_info(ip)

                                # Perform reverse DNS lookup for accurate reverse pointer
                                reverse_pointer = get_reverse_dns(ip)

                                ip_obj, ip_created = IpAddress.objects.get_or_create(
                                    address=ip,
                                    defaults={
                                        "reverse_pointer": reverse_pointer,
                                        "is_private": ip_data.is_private,
                                        "version": ip_data.version,
                                    },
                                )
                                subdomain.ip_addresses.add(ip_obj)

                                stats.ip(ip_created)
                                if ip_created:
                                    logger.log_line(
                                        PREFIX_TARGET,
                                        "IP_SCAN",
                                        "Added new IP %s" % (ip_obj.address,),
                                        level="info",
                                    )

                            subdomain.save()

                        except (json.JSONDecodeError, KeyError) as e:
                            logger.log_line(
                                PREFIX_TARGET,
                                "IP_SCAN",
                                "Error processing host data '%s': %s" % (host_data_json, e),
                                level="warning",
                            )
                            continue

                    # Also add discovered domains as subdomains
                    for domain in discovered_domains:
                        if validators.domain(domain):
                            subdomain, created = Subdomain.objects.get_or_create(
                                name=domain,
                                target_domain=main_target,
                                defaults={
                                    "discovered_date": timezone.now(),
                                },
                            )
                            stats.subdomain(created)
                            if created:
                                logger.log_line(
                                    PREFIX_TARGET,
                                    "IP_SCAN",
                                    "Added discovered domain %s as subdomain to grouped target %s"
                                    % (domain, main_target.name),
                                    level="info",
                                )
                            else:
                                logger.log_line(
                                    PREFIX_TARGET,
                                    "IP_SCAN",
                                    "Discovered domain %s already exists as subdomain for target %s"
                                    % (domain, main_target.name),
                                    level="info",
                                )

                    # Update total_processed_count
                    total_processed_count = stats.get_total_processed()
                    logger.log_line(
                        PREFIX_TARGET,
                        "IP_SCAN",
                        "Grouped target processing complete: %s" % (stats.as_dict(),),
                        level="info",
                    )

                else:
                    # Original logic for individual targets (when no target name is provided)
                    for host_data_json in resolved_hosts_data:
                        try:
                            host_info = json.loads(host_data_json.replace("&quot;", '"'))
                            ip = host_info.get("ip")
                            hostname = host_info.get("domain")
                            is_alive = host_info.get("is_alive", False)
                            resolved_by = host_info.get("resolved_by")

                            if hostname != ip:  # It's a hostname
                                # Deduplicate hostnames
                                if hostname not in seen_hostnames:
                                    seen_hostnames.add(hostname)
                                    selected_hostnames.append(host_info)

                                    # Extract domain from hostname for domain creation using tldextract
                                    # This handles complex TLDs like .co.uk, .com.au correctly
                                    domain_name = get_domain_from_subdomain(hostname)
                                    if domain_name:
                                        selected_domains.add(domain_name)
                            else:  # It's an IP only
                                # Deduplicate IPs
                                if ip not in seen_ips:
                                    seen_ips.add(ip)
                                    selected_ips.append(host_info)
                        except (json.JSONDecodeError, KeyError) as e:
                            logger.log_line(
                                PREFIX_TARGET,
                                "IP_SCAN",
                                "Error processing host data: %s" % (e,),
                                level="warning",
                            )
                            continue

                    # Add discovered domains from checkboxes to the set
                    for domain in discovered_domains:
                        if validators.domain(domain):
                            selected_domains.add(domain)

                    subdomain_count = 0

                    # 1. If user selected domains, add each domain as a target
                    domain_targets = {}
                    for domain_name in selected_domains:
                        if validators.domain(domain_name):
                            domain, created = Domain.objects.get_or_create(
                                name=domain_name,
                                project=project,
                                defaults={
                                    "description": f"{description} (Discovered from {original_ip_range})",
                                    "h1_team_handle": h1_team_handle,
                                    "insert_date": timezone.now(),
                                    "custom_dns_servers": used_dns_servers if used_dns_servers else None,
                                },
                            )

                            # Update DNS servers if target already exists and DNS was provided
                            if not created and used_dns_servers:
                                domain.custom_dns_servers = used_dns_servers
                                domain.save()
                                logger.log_line(
                                    PREFIX_TARGET,
                                    "IP_SCAN",
                                    "Updated DNS servers for existing domain target %s" % (domain.name,),
                                    level="info",
                                )

                            stats.domain(created)
                            if created:
                                logger.log_line(
                                    PREFIX_TARGET,
                                    "IP_SCAN",
                                    "Added new target %s with DNS servers: %s" % (domain.name, used_dns_servers),
                                    level="info",
                                )
                            else:
                                logger.log_line(
                                    PREFIX_TARGET,
                                    "IP_SCAN",
                                    "Domain target %s already exists" % (domain.name,),
                                    level="info",
                                )
                            domain_targets[domain_name] = domain

                    # 2. Process selected hostnames - add them as subdomains to their respective domain targets
                    for host_info in selected_hostnames:
                        ip = host_info.get("ip")
                        hostname = host_info.get("domain")
                        is_alive = host_info.get("is_alive", False)

                        # Find the domain target for this hostname using consistent extraction
                        domain_name = get_domain_from_subdomain(hostname)
                        if domain_name:
                            target_domain = domain_targets.get(domain_name)

                            if target_domain:
                                # Create subdomain entry
                                subdomain, created = Subdomain.objects.get_or_create(
                                    name=hostname,
                                    target_domain=target_domain,
                                    defaults={
                                        "discovered_date": timezone.now(),
                                    },
                                )

                                stats.subdomain(created)
                                if created:
                                    logger.log_line(
                                        PREFIX_TARGET,
                                        "IP_SCAN",
                                        "Added hostname subdomain %s for target %s" % (hostname, target_domain.name),
                                        level="info",
                                    )
                                else:
                                    logger.log_line(
                                        PREFIX_TARGET,
                                        "IP_SCAN",
                                        "Subdomain %s already exists for target %s" % (hostname, target_domain.name),
                                        level="info",
                                    )

                                # Create/update IP address record
                                if validators.ipv4(ip) or validators.ipv6(ip):
                                    ip_data = get_ip_info(ip)

                                    # Perform reverse DNS lookup for accurate reverse pointer
                                    reverse_pointer = get_reverse_dns(ip)

                                    ip_obj, ip_created = IpAddress.objects.get_or_create(
                                        address=ip,
                                        defaults={
                                            "reverse_pointer": reverse_pointer,
                                            "is_private": ip_data.is_private,
                                            "version": ip_data.version,
                                        },
                                    )
                                    subdomain.ip_addresses.add(ip_obj)

                                    stats.ip(ip_created)
                                    if ip_created:
                                        logger.log_line(
                                            PREFIX_TARGET,
                                            "IP_SCAN",
                                            "Added new IP %s" % (ip_obj.address,),
                                            level="info",
                                        )

                                subdomain.save()

                    # 3. Process selected IPs - create a target with the IP range and add IPs as subdomains
                    if selected_ips:
                        try:
                            # Create target with IP range naming convention and store original IP range
                            # Use a clear naming convention that distinguishes IP ranges from domain names
                            range_target_name = f"iprange-{original_ip_range.replace('/', '_').replace(':', '-')}"
                            ip_range_domain, created = Domain.objects.get_or_create(
                                name=range_target_name,
                                project=project,
                                defaults={
                                    "description": f"{description} (IP Range {original_ip_range})",
                                    "h1_team_handle": h1_team_handle,
                                    "insert_date": timezone.now(),
                                    "ip_address_cidr": original_ip_range,
                                    "custom_dns_servers": used_dns_servers if used_dns_servers else None,
                                },
                            )

                            # Update DNS servers if target already exists and DNS was provided
                            if not created and used_dns_servers:
                                ip_range_domain.custom_dns_servers = used_dns_servers
                                ip_range_domain.save()
                                logger.log_line(
                                    PREFIX_TARGET,
                                    "IP_SCAN",
                                    "Updated DNS servers for existing IP range target %s" % (ip_range_domain.name,),
                                    level="info",
                                )

                            stats.domain(created)
                            if created:
                                logger.log_line(
                                    PREFIX_TARGET,
                                    "IP_SCAN",
                                    "Added new IP range target %s with DNS servers: %s"
                                    % (ip_range_domain.name, used_dns_servers),
                                    level="info",
                                )
                            else:
                                logger.log_line(
                                    PREFIX_TARGET,
                                    "IP_SCAN",
                                    "IP range target %s already exists" % (ip_range_domain.name,),
                                    level="info",
                                )

                            # Add selected IPs as subdomains
                            for host_info in selected_ips:
                                ip = host_info.get("ip")
                                is_alive = host_info.get("is_alive", False)

                                # Create subdomain entry for the IP
                                subdomain, created = Subdomain.objects.get_or_create(
                                    name=ip,
                                    target_domain=ip_range_domain,
                                    defaults={
                                        "discovered_date": timezone.now(),
                                    },
                                )

                                # Create/update IP address record
                                if validators.ipv4(ip) or validators.ipv6(ip):
                                    ip_data = get_ip_info(ip)

                                    # Perform reverse DNS lookup for accurate reverse pointer
                                    reverse_pointer = get_reverse_dns(ip)

                                    ip_obj, ip_created = IpAddress.objects.get_or_create(
                                        address=ip,
                                        defaults={
                                            "reverse_pointer": reverse_pointer,
                                            "is_private": ip_data.is_private,
                                            "version": ip_data.version,
                                        },
                                    )
                                    subdomain.ip_addresses.add(ip_obj)

                                    if ip_created:
                                        logger.log_line(
                                            PREFIX_TARGET,
                                            "IP_SCAN",
                                            "Added new IP %s" % (ip_obj.address,),
                                            level="info",
                                        )

                                stats.subdomain(created)
                                if created:
                                    logger.log_line(
                                        PREFIX_TARGET,
                                        "IP_SCAN",
                                        "Added IP subdomain %s for target %s" % (ip, ip_range_domain.name),
                                        level="info",
                                    )
                                else:
                                    logger.log_line(
                                        PREFIX_TARGET,
                                        "IP_SCAN",
                                        "IP subdomain %s already exists for target %s" % (ip, ip_range_domain.name),
                                        level="info",
                                    )

                                subdomain.save()

                        except (AddressValueError, ValueError) as e:
                            logger.log_line(
                                PREFIX_TARGET,
                                "IP_SCAN",
                                "Error creating IP range target: %s" % (e,),
                                level="warning",
                            )

                    # Update total_processed_count to include both created and existing items
                    total_processed_count = stats.get_total_processed()

                    logger.log_line(
                        PREFIX_TARGET,
                        "IP_SCAN",
                        "Processing complete: %s" % (stats.as_dict(),),
                        level="info",
                    )

        except (Http404, ValueError) as e:
            logger.log_line(
                PREFIX_TARGET,
                "ADD_TARGET",
                "Exception while adding domain: %s" % (e,),
                level="error",
                exc_info=True,
            )
            messages.add_message(request, messages.ERROR, f"Exception while adding domain: {e}")
            return http.HttpResponseRedirect(reverse("add_target", kwargs={"slug": slug}))

        # No targets processed, handle error case
        if total_processed_count == 0:
            # Provide more detailed error message based on the operation type
            if ip_target:
                error_msg = "No targets were processed. This could be due to: 1) All selected hosts already exist, 2) Invalid host data format, or 3) Domain extraction errors. Check the logs for details."
            else:
                error_msg = (
                    "Oops! Could not import any targets, either targets already exists or is not a valid target."
                )

            logger.log_line(
                PREFIX_TARGET,
                "ADD_TARGET",
                "No targets processed (total_processed_count=0) for request: %s" % (dict(request.POST),),
                level="warning",
            )
            messages.add_message(request, messages.ERROR, error_msg)

            # Handle AJAX requests with JSON error response
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return JsonResponse({"status": "error", "message": error_msg, "added_count": 0}, status=400)

            return http.HttpResponseRedirect(reverse("add_target", kwargs={"slug": slug}))

        # Create detailed success message
        if ip_target and "stats" in locals():
            # Detailed feedback for IP target additions
            stats_dict = stats.as_dict()
            msg_parts = []
            if stats_dict["domains_created"] > 0:
                msg_parts.append(f"{stats_dict['domains_created']} new target(s)")
            if stats_dict["domains_existing"] > 0:
                msg_parts.append(f"{stats_dict['domains_existing']} existing target(s)")
            if stats_dict["subdomains_created"] > 0:
                msg_parts.append(f"{stats_dict['subdomains_created']} new subdomain(s)")
            if stats_dict["subdomains_existing"] > 0:
                msg_parts.append(f"{stats_dict['subdomains_existing']} existing subdomain(s)")

            if msg_parts:
                msg = f"Processing complete: {', '.join(msg_parts)} processed successfully"
            else:
                msg = "No targets were processed"
        else:
            # Standard message for other target types
            msg = f"{total_processed_count} targets processed successfully"

        messages.add_message(request, messages.SUCCESS, msg)

        # Handle AJAX requests with JSON response
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            response_data = {
                "status": "success",
                "message": msg,
                "processed_count": total_processed_count,
                "redirect_url": reverse("list_target", kwargs={"slug": slug}),
            }

            # Add detailed stats for IP targets
            if ip_target and "stats" in locals():
                response_data["stats"] = stats.as_dict()

            return JsonResponse(response_data)

        # Regular form submission redirect
        return http.HttpResponseRedirect(reverse("list_target", kwargs={"slug": slug}))

    # GET request
    context = {"add_target_li": "active", "target_data_active": "active", "form": form}
    return render(request, "target/add.html", context)


def list_target(request, slug):
    project = get_object_or_404(Project, slug=slug)
    context = {
        "list_target_li": "active",
        "target_data_active": "active",
        "detail_scan_url": reverse("detail_scan", args=[project.slug, 0]),
        "start_scan_url": reverse("start_scan", args=[project.slug, 0]),
        "schedule_scan_url": reverse("schedule_scan", args=[project.slug, 0]),
        "update_target_url": reverse("update_target", args=[project.slug, 0]),
        "delete_target_url": reverse("delete_target", args=[project.slug, 0]),
        "target_summary_url": reverse("target_summary", args=[project.slug, 0]),
    }
    return render(request, "target/list.html", context)


@has_permission_decorator(PERM_MODIFY_TARGETS, redirect_url=FOUR_OH_FOUR_URL)
def delete_target(request, slug, id):
    if request.method == "POST":
        try:
            target = get_object_or_404(Domain, id=id)
            base = Path(settings.RENGINE_RESULTS)
            if base.exists():
                result_dirs = set()
                for scan in ScanHistory.objects.filter(domain=target):
                    results_dir = getattr(scan, "results_dir", None) or ""
                    # resolve_results_dir_under_base returns None when results_dir is missing/invalid;
                    # we intentionally no-op in that case (no filesystem delete) for safety.
                    resolved = resolve_results_dir_under_base(settings.RENGINE_RESULTS, results_dir)
                    if resolved is not None:
                        result_dirs.add(resolved)
                for dir_path in result_dirs:
                    result = safe_rmtree(settings.RENGINE_RESULTS, dir_path)
                    if result != "removed":
                        logger.log_line(
                            PREFIX_TARGET,
                            "DELETE_TARGET",
                            "Results dir cleanup returned %s for path %s" % (result, dir_path),
                            level="warning",
                        )
                resolved_direct = resolve_results_dir_under_base(settings.RENGINE_RESULTS, target.name)
                if resolved_direct is not None and resolved_direct.is_dir():
                    result = safe_rmtree(settings.RENGINE_RESULTS, resolved_direct)
                    if result != "removed":
                        logger.log_line(
                            PREFIX_TARGET,
                            "DELETE_TARGET",
                            "Results dir cleanup returned %s for path %s" % (result, resolved_direct),
                            level="warning",
                        )
                prefix = f"{target.name}__"
                for entry in base.iterdir():
                    if entry.is_dir() and entry.name.startswith(prefix):
                        result = safe_rmtree(settings.RENGINE_RESULTS, entry)
                        if result != "removed":
                            logger.log_line(
                                PREFIX_TARGET,
                                "DELETE_TARGET",
                                "Results dir cleanup returned %s for path %s" % (result, entry),
                                level="warning",
                            )
            target.delete()
            response_data = {"status": "true"}
            messages.add_message(request, messages.INFO, "Domain successfully deleted!")
        except Http404:
            if isinstance(id, int):  # Ensure id is an integer
                logger.log_line(
                    PREFIX_TARGET,
                    "DELETE_TARGET",
                    "Domain not found: %d" % (id,),
                    level="error",
                )
            else:
                logger.log_line(
                    PREFIX_TARGET,
                    "DELETE_TARGET",
                    "Domain not found: Invalid ID provided",
                    level="error",
                )
            messages.add_message(request, messages.ERROR, "Domain not found.")
            response_data = {"status": "false"}
    else:
        valid_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
        if request.method in valid_methods:
            logger.log_line(
                PREFIX_TARGET,
                "DELETE_TARGET",
                "Invalid request method: %s" % (request.method,),
                level="error",
            )
        else:
            logger.log_line(
                PREFIX_TARGET,
                "DELETE_TARGET",
                "Invalid request method: Unknown method provided",
                level="error",
            )

        response_data = {"status": "false"}
        messages.add_message(request, messages.ERROR, "Oops! Domain could not be deleted!")
    return http.JsonResponse(response_data)


@has_permission_decorator(PERM_MODIFY_TARGETS, redirect_url=FOUR_OH_FOUR_URL)
def delete_targets(request, slug):
    if request.method == "POST":
        for key, value in request.POST.items():
            if key != "list_target_table_length" and key != "csrfmiddlewaretoken":
                Domain.objects.filter(id=value).delete()
        messages.add_message(request, messages.INFO, "Targets deleted!")
    return http.HttpResponseRedirect(reverse("list_target", kwargs={"slug": slug}))


@has_permission_decorator(PERM_MODIFY_TARGETS, redirect_url=FOUR_OH_FOUR_URL)
def update_target(request, slug, id):
    domain = get_object_or_404(Domain, id=id)
    form = UpdateTargetForm()
    if request.method == "POST":
        form = UpdateTargetForm(request.POST, instance=domain)
        if form.is_valid():
            form.save()
            messages.add_message(request, messages.INFO, f"Domain {domain.name} modified!")
            return http.HttpResponseRedirect(reverse("list_target", kwargs={"slug": slug}))
    else:
        form.set_value(domain.name, domain.description, domain.h1_team_handle)
    context = {"list_target_li": "active", "target_data_active": "active", "domain": domain, "form": form}
    return render(request, "target/update.html", context)


def target_summary(request, slug, id):
    """Summary of a target (domain). Contains aggregated information on all
    objects (Subdomain, EndPoint, Vulnerability, Emails, ...) found across all
    scans.

    Args:
        request: Django request.
        id: Domain id.
    """
    context = {}

    # Domain
    target = get_object_or_404(Domain, id=id)
    context["target"] = target

    # Scan History: running first, then queued, completed, failed; within group by most recent first
    scan = ScanHistory.objects.filter(domain__id=id)
    scan_status_order = Case(
        When(scan_status=SCAN_STATUS_RUNNING, then=Value(0)),
        When(scan_status=SCAN_STATUS_RUNNING_BACKGROUND, then=Value(0)),
        When(scan_status=SCAN_STATUS_QUEUED, then=Value(1)),
        When(scan_status=SCAN_STATUS_COMPLETED, then=Value(2)),
        When(scan_status=SCAN_STATUS_FAILED, then=Value(3)),
        default=Value(4),
        output_field=IntegerField(),
    )
    context["recent_scans"] = scan.annotate(sort_priority=scan_status_order).order_by(
        "sort_priority", "-start_scan_date"
    )[:4]
    context["scan_count"] = scan.count()
    last_week = timezone.now() - timedelta(days=7)
    context["this_week_scan_count"] = scan.filter(start_scan_date__gte=last_week).count()

    # Scan Engines
    context["scan_engines"] = EngineType.objects.order_by("engine_name").all()

    # Subdomains
    subdomains = Subdomain.objects.filter(target_domain__id=id).values("name").distinct()
    context["subdomain_count"] = subdomains.count()
    context["alive_count"] = subdomains.filter(http_status__gt=0).count()

    # Endpoints
    endpoints = EndPoint.objects.filter(target_domain__id=id).values("http_url").distinct()
    context["endpoint_count"] = endpoints.count()
    context["endpoint_alive_count"] = endpoints.filter(http_status__gt=0).count()

    # Vulnerabilities
    vulnerabilities = Vulnerability.objects.filter(target_domain__id=id)
    unknown_count = vulnerabilities.filter(severity=-1).count()
    info_count = vulnerabilities.filter(severity=0).count()
    low_count = vulnerabilities.filter(severity=1).count()
    medium_count = vulnerabilities.filter(severity=2).count()
    high_count = vulnerabilities.filter(severity=3).count()
    critical_count = vulnerabilities.filter(severity=4).count()
    ignore_info_count = sum([low_count, medium_count, high_count, critical_count])
    context["unknown_count"] = unknown_count
    context["info_count"] = info_count
    context["low_count"] = low_count
    context["medium_count"] = medium_count
    context["high_count"] = high_count
    context["critical_count"] = critical_count
    context["total_vul_ignore_info_count"] = ignore_info_count
    context["most_common_vulnerability"] = (
        vulnerabilities.exclude(severity=0)
        .values("name", "severity")
        .annotate(count=Count("name"))
        .order_by("-count")[:10]
    )
    context["vulnerability_count"] = vulnerabilities.count()
    context["vulnerability_list"] = vulnerabilities.order_by("-severity").all()[:30]

    # Vulnerability Tags
    context["most_common_tags"] = (
        VulnerabilityTags.objects.filter(vuln_tags__in=vulnerabilities)
        .annotate(nused=Count("vuln_tags"))
        .order_by("-nused")
        .values("name", "nused")[:7]
    )

    # Emails
    emails = Email.objects.filter(emails__in=scan).distinct()
    context["exposed_count"] = emails.exclude(password__isnull=True).count()
    context["email_count"] = emails.count()

    # Employees
    context["employees_count"] = Employee.objects.filter(employees__in=scan).count()

    # HTTP Statuses (legacy + Secator via default endpoints)
    context["http_status_breakdown"] = EndpointRepository().get_http_status_breakdown(target)

    # CVEs
    context["most_common_cve"] = (
        CveId.objects.filter(cve_ids__in=vulnerabilities)
        .annotate(nused=Count("cve_ids"))
        .order_by("-nused")
        .values("name", "nused")[:7]
    )

    # CWEs
    context["most_common_cwe"] = (
        CweId.objects.filter(cwe_ids__in=vulnerabilities)
        .annotate(nused=Count("cwe_ids"))
        .order_by("-nused")
        .values("name", "nused")[:7]
    )

    # Country ISOs
    subdomains = Subdomain.objects.filter(target_domain__id=id)
    ip_addresses = IpAddress.objects.filter(ip_addresses__in=subdomains).distinct("address")
    ip_serializer = IpSerializer(ip_addresses.all(), many=True, context={"target_id": id})
    context["ip_addresses"] = json.dumps(ip_serializer.data, cls=DjangoJSONEncoder)

    context["asset_countries"] = (
        CountryISO.objects.filter(ipaddress__in=ip_addresses).annotate(count=Count("iso")).order_by("-count")
    )

    context.update(build_secator_profiles_context())
    context["secator_workers"] = SecatorWorker.objects.filter(is_active=True).order_by("name")
    return render(request, "target/summary.html", context)


@has_permission_decorator(PERM_MODIFY_TARGETS, redirect_url=FOUR_OH_FOUR_URL)
def add_organization(request, slug):
    form = AddOrganizationForm(request.POST or None, project=slug)
    if request.method == "POST" and form.is_valid():
        data = form.cleaned_data
        project = Project.objects.get(slug=slug)
        organization = Organization.objects.create(
            name=data["name"], description=data["description"], project=project, insert_date=timezone.now()
        )
        for domain_id in request.POST.getlist("domains"):
            domain = Domain.objects.get(id=domain_id)
            organization.domains.add(domain)
        messages.add_message(request, messages.INFO, f"Organization {data['name']} added successfully")
        return http.HttpResponseRedirect(reverse("list_organization", kwargs={"slug": slug}))
    context = {"organization_active": "active", "form": form}
    return render(request, "organization/add.html", context)


def list_organization(request, slug):
    organizations = Organization.objects.filter(project__slug=slug).order_by("-insert_date")
    context = {"organization_active": "active", "organizations": organizations}
    return render(request, "organization/list.html", context)


@has_permission_decorator(PERM_MODIFY_TARGETS, redirect_url=FOUR_OH_FOUR_URL)
def delete_organization(request, slug, id):
    if request.method == "POST":
        try:
            organization = get_object_or_404(Organization, id=id)
            organization.delete()
            messages.add_message(request, messages.INFO, "Organization successfully deleted!")
            response_data = {"status": "true"}
        except Http404:
            messages.add_message(request, messages.ERROR, "Organization not found.")
            response_data = {"status": "false"}
    else:
        response_data = {"status": "false"}
        messages.add_message(request, messages.ERROR, "Oops! Organization could not be deleted!")
    return http.JsonResponse(response_data)


@has_permission_decorator(PERM_MODIFY_TARGETS, redirect_url=FOUR_OH_FOUR_URL)
def update_organization(request, slug, id):
    organization = get_object_or_404(Organization, id=id)
    form = UpdateOrganizationForm()
    domain_list = []
    if request.method == "POST":
        form = UpdateOrganizationForm(request.POST, instance=organization)
        if form.is_valid():
            data = form.cleaned_data
            for domain in organization.get_domains():
                organization.domains.remove(domain)

            organization_obj = Organization.objects.filter(id=id)
            organization_obj.update(
                name=data["name"],
                description=data["description"],
            )
            for domain_id in request.POST.getlist("domains"):
                domain = Domain.objects.get(id=domain_id)
                organization.domains.add(domain)
            msg = "Organization %s modified!" % (organization.name,)
            logger.log_line(
                PREFIX_TARGET,
                "ORGANIZATION",
                msg,
                level="info",
            )
            messages.add_message(request, messages.INFO, msg)
            return http.HttpResponseRedirect(reverse("list_organization", kwargs={"slug": slug}))
    else:
        domain_list = organization.get_domains().values_list("id", flat=True)
        domain_list = [str(id) for id in domain_list]
        form.set_value(organization.name, organization.description)
    context = {
        "list_organization_li": "active",
        "organization_data_active": "true",
        "organization": organization,
        "domain_list": mark_safe(domain_list),
        "form": form,
    }
    return render(request, "organization/update.html", context)
