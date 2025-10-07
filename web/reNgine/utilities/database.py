import hashlib
import threading
import time
from urllib.parse import urlparse

from celery.utils.log import get_task_logger
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.utils import timezone
from redis.exceptions import LockError, RedisError
import validators

from dashboard.models import User
from reNgine.settings import RENGINE_RESULTS, RENGINE_TASK_IGNORE_CACHE_KWARGS
from reNgine.utilities.data import is_iterable, replace_nulls
from reNgine.utilities.distributed_lock import DistributedLock, get_redis_connection
from reNgine.utilities.url import get_domain_from_subdomain, is_target_allowed_for_domain, is_valid_url, sanitize_url
from startScan.models import (
    CveId,
    CweId,
    DirectoryFile,
    Email,
    Employee,
    EndPoint,
    IpAddress,
    MetaFinderDocument,
    ScanActivity,
    ScanHistory,
    Subdomain,
    Vulnerability,
    VulnerabilityTags,
)
from targetApp.models import Domain


logger = get_task_logger(__name__)

# Thread-local storage for IP collection
_thread_local = threading.local()


# -------------------------------#
# Database Save Functions      #
# -------------------------------#


def save_endpoint(http_url, ctx=None, is_default=False, http_status=0, **endpoint_data):
    """Get or create EndPoint object.

    Args:
        http_url (str): Input HTTP URL.
        ctx (dict): Context containing scan and domain information.
        is_default (bool): If the url is a default url for SubDomains.
        http_status (int): HTTP status code.
        endpoint_data: Additional endpoint data (including subdomain).

    Returns:
        tuple: (EndPoint, created) or (None, False) if invalid
    """
    # Remove nulls and validate basic inputs
    endpoint_data = replace_nulls(endpoint_data)
    scheme = urlparse(http_url).scheme

    if not scheme:
        logger.warning(f"{http_url} is missing scheme (http or https). Creating default endpoint with http scheme.")
        http_url = f"http://{http_url.strip()}"
        is_default = True

    if not is_valid_url(http_url):
        logger.error(f"{http_url} is not a valid URL. Skipping.")
        return None, False

    # Get required objects
    scan = ScanHistory.objects.filter(pk=ctx.get("scan_history_id")).first()
    domain = Domain.objects.filter(pk=ctx.get("domain_id")).first()
    subdomain = endpoint_data.get("subdomain")

    if not all([scan, domain]):
        logger.error("Missing scan or domain information")
        return None, False
    if not is_target_allowed_for_domain(http_url, domain.name, ctx, target_type="url"):
        logger.error(f"{http_url} is not a URL of domain {domain.name}. Skipping.")
        return None, False

    http_url = sanitize_url(http_url)

    # If this is a default endpoint, check if one already exists for this subdomain + port combination
    if is_default and subdomain:
        # Extract port from current URL
        parsed_current = urlparse(http_url)
        if parsed_current.port:
            current_port = parsed_current.port
        elif parsed_current.scheme == "https":
            current_port = 443
        else:
            current_port = 80

        # Get all default endpoints for this subdomain
        existing_defaults = EndPoint.objects.filter(
            scan_history=scan, target_domain=domain, subdomain=subdomain, is_default=True
        )

        # Check if any existing default endpoint has the same port
        for existing_default in existing_defaults:
            # Extract port from existing URL
            parsed_existing = urlparse(existing_default.http_url)
            if parsed_existing.port:
                existing_port = parsed_existing.port
            elif parsed_existing.scheme == "https":
                existing_port = 443
            else:
                existing_port = 80

            if existing_port == current_port:
                logger.info(f"Default endpoint already exists for subdomain {subdomain} on port {current_port}")
                return existing_default, False

    if existing_endpoint := EndPoint.objects.filter(scan_history=scan, target_domain=domain, http_url=http_url).first():
        return existing_endpoint, False

    # Create new endpoint
    create_data = {
        "scan_history": scan,
        "target_domain": domain,
        "http_url": http_url,
        "is_default": is_default,
        "discovered_date": timezone.now(),
        "http_status": http_status,
    }

    create_data |= endpoint_data

    endpoint = EndPoint.objects.create(**create_data)
    created = True

    # Add subscan relation if needed
    if created and ctx.get("subscan_id"):
        endpoint.endpoint_subscan_ids.add(ctx.get("subscan_id"))
        endpoint.save()

    return endpoint, created


def validate_and_save_subdomain(subdomain_name, ctx=None):
    """
    Centralized function to validate and save subdomain with consistent error handling.

    This function provides a single point of entry for subdomain validation and saving,
    ensuring consistent error messages and validation logic across all modules.

    Design Decision: This function catches only expected exceptions (database errors,
    validation errors, Redis errors) and returns (None, False) instead of propagating
    them because it's used in mass processing loops (subdomain discovery, URL crawling,
    etc.). Propagating exceptions would stop the entire scan if a single subdomain fails,
    which is unacceptable for resilience. Unexpected exceptions (bugs) are allowed to
    propagate to facilitate debugging.

    Args:
        subdomain_name (str): Subdomain name to validate and save.
        ctx (dict): Context containing scan information and settings.

    Returns:
        tuple: (Subdomain object or None, created boolean)
            - (Subdomain, True): Successfully created new subdomain
            - (Subdomain, False): Subdomain already existed
            - (None, False): Expected error occurred (logged)

    Raises:
        Unexpected exceptions (programming errors, critical system failures) are
        propagated to help identify bugs during development and testing.
    """
    try:
        subdomain, created = save_subdomain(subdomain_name, ctx=ctx)
    except (IntegrityError, ValidationError) as e:
        # Expected database/validation errors - log and continue
        logger.warning(f"Database/validation error for subdomain '{subdomain_name}': {e.__class__.__name__}: {e}")
        return None, False
    except (LockError, RedisError) as e:
        # Expected Redis errors - log and continue
        logger.warning(f"Redis error for subdomain '{subdomain_name}': {e.__class__.__name__}: {e}")
        return None, False
    # Unexpected exceptions (bugs, critical failures) propagate for debugging

    if not isinstance(subdomain, Subdomain):
        logger.error(f"Invalid subdomain encountered: {subdomain}")
        return None, False

    return subdomain, created


def save_subdomain(subdomain_name, ctx=None):
    """Get or create Subdomain object with race condition protection.

    Args:
        subdomain_name (str): Subdomain name.
        ctx (dict): Context containing scan information and settings.

    Returns:
        tuple: (startScan.models.Subdomain, created) where `created` is a
            boolean indicating if the object has been created in DB.
    """
    scan_id = ctx.get("scan_history_id")
    out_of_scope_subdomains = ctx.get("out_of_scope_subdomains", [])
    subdomain_name = subdomain_name.lower()

    # Validate domain/IP format
    valid_domain = (
        validators.domain(subdomain_name) or validators.ipv4(subdomain_name) or validators.ipv6(subdomain_name)
    )
    if not valid_domain:
        logger.error(f"{subdomain_name} is not a valid domain/IP. Skipping.")
        return None, False

    # Check if subdomain is in scope
    if subdomain_name in out_of_scope_subdomains:
        logger.error(f"{subdomain_name} is out-of-scope. Skipping.")
        return None, False

    # Get domain object and check if we're scanning an IP
    scan = ScanHistory.objects.filter(pk=scan_id).first()
    domain = scan.domain if scan else None

    if not domain:
        logger.error("No domain found in scan history. Skipping.")
        return None, False

    if not is_target_allowed_for_domain(subdomain_name, domain.name, ctx, target_type="subdomain"):
        logger.error(f"{subdomain_name} is not a subdomain of domain {domain.name}. Skipping.")
        return None, False

    # Use Redis distributed locking to prevent race conditions during concurrent scans
    lock_key = f"subdomain_creation:{subdomain_name}:{scan_id}:{domain.id if domain else 'no_domain'}"

    if redis_conn := get_redis_connection():
        try:
            with redis_conn.lock(lock_key, timeout=30, blocking_timeout=5):
                # Use get_or_create within the lock for additional safety against edge cases
                subdomain, created = Subdomain.objects.get_or_create(
                    scan_history=scan,
                    target_domain=domain,
                    name=subdomain_name,
                    defaults={"discovered_date": timezone.now()},
                )

                if created:
                    logger.info(f"Found new subdomain/rDNS: {subdomain_name}")
                else:
                    logger.debug(f"Subdomain {subdomain_name} already exists for scan {scan_id}")

                return subdomain, created

        except LockError:
            # Handle lock contention (could log or raise a custom exception)
            logger.warning(f"Could not acquire Redis lock for subdomain {subdomain_name}")
            # Fall through to fallback logic
        except RedisError as e:
            # Handle Redis connection or other Redis-related errors
            logger.warning(f"Redis error for subdomain {subdomain_name}: {e}")
            # Fall through to fallback logic

    # Fallback logic when Redis is unavailable or lock acquisition fails
    logger.debug(f"Using fallback get_or_create for subdomain {subdomain_name}")

    # Fallback with intelligent retry for race condition handling
    for attempt in range(3):
        try:
            subdomain, created = Subdomain.objects.get_or_create(
                scan_history=scan,
                target_domain=domain,
                name=subdomain_name,
                defaults={"discovered_date": timezone.now()},
            )

            if created:
                logger.info(f"Found new subdomain/rDNS: {subdomain_name}")

            return subdomain, created

        except IntegrityError:
            # Handle race condition - another process created the subdomain
            if attempt < 2:  # Don't sleep on the last attempt
                time.sleep(0.1 * (attempt + 1))  # Progressive backoff
            continue

    # Final attempt without exception handling
    try:
        subdomain, created = Subdomain.objects.get_or_create(
            scan_history=scan, target_domain=domain, name=subdomain_name, defaults={"discovered_date": timezone.now()}
        )

        if created:
            logger.info(f"Found new subdomain/rDNS: {subdomain_name}")

        return subdomain, created

    except (IntegrityError, ValidationError) as e:
        # Log database constraint violations but continue processing other subdomains
        logger.warning(f"Database constraint error for subdomain {subdomain_name}: {e}")
        # Return None to indicate this subdomain failed but others can continue
        return None, False
    except Exception as e:
        # Log the exception for debugging and re-raise critical errors
        logger.error(f"Critical error saving subdomain {subdomain_name} in final fallback: {e}", exc_info=True)
        # Re-raise critical exceptions like database connection failures, memory errors, etc.
        # Only suppress if it's a non-critical validation issue
        if isinstance(e, (ConnectionError, MemoryError, SystemExit, KeyboardInterrupt)):
            raise  # Re-raise critical system errors
        # For other exceptions, log and continue with other subdomains
        logger.warning(f"Non-critical error for subdomain {subdomain_name}, continuing with others: {e}")
        return None, False


def save_subdomain_metadata(subdomain, endpoint, extra_datas=None):
    """Save metadata from endpoint to subdomain.

    Args:
        subdomain: Subdomain object
        endpoint: EndPoint object
        extra_datas: Additional metadata to save
    """

    if extra_datas is None:
        extra_datas = {}
    if endpoint and endpoint.is_alive:
        _update_subdomain_with_endpoint_data(endpoint, subdomain, extra_datas)
    elif http_url := extra_datas.get("http_url"):
        subdomain.http_url = http_url
        subdomain.save()
    else:
        logger.warning(f"No HTTP URL found for {subdomain.name}. Skipping.")


def _update_subdomain_with_endpoint_data(endpoint, subdomain, extra_datas):
    logger.info(f"Saving HTTP metadatas from {endpoint.http_url}")
    subdomain.http_url = endpoint.http_url
    subdomain.http_status = endpoint.http_status
    subdomain.response_time = endpoint.response_time
    subdomain.page_title = endpoint.page_title
    subdomain.content_type = endpoint.content_type
    subdomain.content_length = endpoint.content_length
    subdomain.webserver = endpoint.webserver
    cname = extra_datas.get("cname")
    if cname and is_iterable(cname):
        subdomain.cname = ",".join(cname)
    cdn = extra_datas.get("cdn")
    if cdn and is_iterable(cdn):
        subdomain.is_cdn = ",".join(cdn)
        subdomain.cdn_name = extra_datas.get("cdn_name")
    for tech in endpoint.techs.all():
        subdomain.technologies.add(tech)
    subdomain.save()


def save_ip_address(ip_address, subdomain=None, subscan=None, **kwargs):
    """Save IP address to database and collect for batch geolocalization.

    Args:
        ip_address (str): IP address to save
        subdomain (Subdomain, optional): Associated subdomain
        subscan (SubScan, optional): Associated subscan
        **kwargs: Additional IP attributes

    Returns:
        tuple: (IpAddress object, created boolean)
    """
    if not (validators.ipv4(ip_address) or validators.ipv6(ip_address)):
        logger.info(f"IP {ip_address} is not a valid IP. Skipping.")
        return None, False

    ip, created = IpAddress.objects.get_or_create(address=ip_address)
    if created:
        logger.warning(f"Found new IP {ip_address}")

    # Set extra attributes
    for key, value in kwargs.items():
        setattr(ip, key, value)
    ip.save()

    # Add IP to subdomain
    if subdomain:
        subdomain.ip_addresses.add(ip)
        subdomain.save()

    # Add subscan to IP
    if subscan:
        ip.ip_subscan_ids.add(subscan)

    # Collect IP for batch geolocalization instead of immediate processing
    if created:
        _collect_ip_for_geolocalization(ip_address)

    return ip, created


def _collect_ip_for_geolocalization(ip_address):
    """Collect IP address for batch geolocalization.

    This function adds the IP to a thread-local collection that will be
    processed in batch at the end of the current task.

    Args:
        ip_address (str): IP address to collect
    """
    from reNgine.utilities.data import get_ip_info

    # Check if this is a private/internal IP address
    ip_info = get_ip_info(ip_address)
    if ip_info and ip_info.is_private:
        logger.debug(f"Skipping geolocalization for private IP: {ip_address}")
        return

    # Get or create thread-local storage
    if not hasattr(_thread_local, "geo_ip_collection"):
        _thread_local.geo_ip_collection = set()

    # Add IP to collection (set automatically handles duplicates)
    _thread_local.geo_ip_collection.add(ip_address)
    logger.debug(f"Collected IP {ip_address} for batch geolocalization")


def trigger_batch_geolocalization():
    """Trigger batch geolocalization for collected IP addresses.

    This function should be called at the end of tasks that collect IPs
    to process them in a single batch operation.

    Returns:
        str: Task ID of the batch geolocalization task, or None if no IPs collected
    """
    from reNgine.tasks.geo import geo_localize_batch

    # Get collected IPs from thread-local storage
    if not hasattr(_thread_local, "geo_ip_collection"):
        logger.debug("No IPs collected for geolocalization")
        return None

    collected_ips = list(_thread_local.geo_ip_collection)

    if not collected_ips:
        logger.debug("No IPs collected for geolocalization")
        return None

    # Clear the collection
    _thread_local.geo_ip_collection.clear()

    # Trigger batch geolocalization
    logger.info(f"Triggering batch geolocalization for {len(collected_ips)} IP addresses")
    task = geo_localize_batch.delay(collected_ips)

    return task.id


def with_batch_geolocalization(func):
    """Decorator to automatically trigger batch geolocalization at the end of tasks.

    This decorator wraps task functions to automatically collect and process
    IP addresses for geolocalization in batch mode, eliminating code duplication.

    The decorator automatically detects internal network scans and skips
    geolocalization for private IP addresses.

    Args:
        func: The task function to wrap

    Returns:
        The wrapped function that handles batch geolocalization
    """
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            # Execute the original function
            result = func(*args, **kwargs)

            # Trigger batch geolocalization for collected IPs
            # (private IPs are automatically filtered out)
            geo_task_id = trigger_batch_geolocalization()
            if geo_task_id:
                logger.info(f"Triggered batch geolocalization task: {geo_task_id}")
            else:
                logger.debug("No public IPs collected for geolocalization")

            return result

        except Exception as e:
            # Still trigger geolocalization even if the main task fails
            # This ensures we don't lose collected IPs
            try:
                geo_task_id = trigger_batch_geolocalization()
                if geo_task_id:
                    logger.info(f"Triggered batch geolocalization task after error: {geo_task_id}")
                else:
                    logger.debug("No public IPs collected for geolocalization after error")
            except Exception as geo_error:
                logger.error(f"Failed to trigger batch geolocalization after error: {geo_error}")

            # Re-raise the original exception
            raise e

    return wrapper


def save_vulnerability(**vuln_data):
    references = vuln_data.pop("references", [])
    cve_ids = vuln_data.pop("cve_ids", [])
    cwe_ids = vuln_data.pop("cwe_ids", [])
    tags = vuln_data.pop("tags", [])
    subscan = vuln_data.pop("subscan", None)

    # remove nulls
    vuln_data = replace_nulls(vuln_data)

    # Create vulnerability
    vuln, created = Vulnerability.objects.get_or_create(**vuln_data)
    if created:
        vuln.discovered_date = timezone.now()
        vuln.open_status = True
        vuln.save()

    # Save vuln tags
    for tag_name in tags or []:
        tag, created = VulnerabilityTags.objects.get_or_create(name=tag_name)
        if tag:
            vuln.tags.add(tag)
            vuln.save()

    # Save CVEs
    for cve_id in cve_ids or []:
        cve, created = CveId.objects.get_or_create(name=cve_id)
        if cve:
            vuln.cve_ids.add(cve)
            vuln.save()

    # Save CWEs
    for cve_id in cwe_ids or []:
        cwe, created = CweId.objects.get_or_create(name=cve_id)
        if cwe:
            vuln.cwe_ids.add(cwe)
            vuln.save()

    # Save vuln reference
    if references:
        vuln.references = references
        vuln.save()

    # Save subscan id in vuln object
    if subscan:
        vuln.vuln_subscan_ids.add(subscan)
        vuln.save()

    return vuln, created


def save_email(email_address, scan_history=None):
    if not validators.email(email_address):
        logger.info(f"Email {email_address} is invalid. Skipping.")
        return None, False
    email, created = Email.objects.get_or_create(address=email_address)
    if created:
        logger.info(f"Found new email address {email_address}")

    # Add email to ScanHistory
    if scan_history:
        scan_history.emails.add(email)
        scan_history.save()

    return email, created


def save_employee(name, designation, scan_history=None):
    employee, created = Employee.objects.get_or_create(name=name, designation=designation)
    if created:
        logger.warning(f"Found new employee {name}")

    # Add employee to ScanHistory
    if scan_history:
        scan_history.employees.add(employee)
        scan_history.save()

    return employee, created


def create_scan_object(host_id, engine_id, initiated_by_id=None):
    """
    create task with pending status so that celery task will execute when
    threads are free
    Args:
        host_id: int: id of Domain model
        engine_id: int: id of EngineType model
        initiated_by_id: int : id of User model (Optional)
    """
    from reNgine.definitions import INITIATED_TASK
    from scanEngine.models import EngineType

    # get current time
    current_scan_time = timezone.now()
    # fetch engine and domain object
    engine = EngineType.objects.get(pk=engine_id)
    domain = Domain.objects.get(pk=host_id)
    scan = ScanHistory()
    scan.scan_status = INITIATED_TASK
    scan.domain = domain
    scan.scan_type = engine
    scan.start_scan_date = current_scan_time
    if initiated_by_id:
        user = User.objects.get(pk=initiated_by_id)
        scan.initiated_by = user
    scan.save()
    # save last scan date for domain model
    domain.start_scan_date = current_scan_time
    domain.save()
    return scan.id


def create_scan_activity(scan_history_id, message, status):
    scan_activity = ScanActivity()
    scan_activity.scan_of = ScanHistory.objects.get(pk=scan_history_id)
    scan_activity.title = message
    scan_activity.time = timezone.now()
    scan_activity.status = status
    scan_activity.save()
    return scan_activity.id


def save_imported_subdomains(subdomains, ctx=None):
    """Take a list of subdomains imported and write them to from_imported.txt.

    This function processes imported subdomains, saving them to the database and
    recording successfully imported ones to a text file. The file is written using
    atomic operations to prevent corruption.

    Args:
        subdomains (list): List of subdomain names.
        ctx (dict): Context dict with domain_id, results_dir, etc.
    """
    import os
    import tempfile

    if ctx is None:
        ctx = {}
    domain_id = ctx["domain_id"]
    domain = Domain.objects.get(pk=domain_id)
    results_dir = ctx.get("results_dir", RENGINE_RESULTS)

    # Validate each subdomain and de-duplicate entries
    subdomains = list({subdomain for subdomain in subdomains if domain.name == get_domain_from_subdomain(subdomain)})
    if not subdomains:
        return

    logger.warning(f"Found {len(subdomains)} imported subdomains.")

    # Track statistics for reporting
    success_count = 0
    failed_count = 0
    failed_subdomains = []
    successfully_imported = []

    # Process all subdomains first (DB operations)
    for subdomain in subdomains:
        subdomain_name = subdomain.strip()
        subdomain_obj, _ = validate_and_save_subdomain(subdomain_name, ctx=ctx)
        if subdomain_obj is None:
            failed_count += 1
            failed_subdomains.append(subdomain_name)
            logger.warning(f"Failed to import subdomain: {subdomain_name}")
            continue

        subdomain_obj.is_imported_subdomain = True
        subdomain_obj.save()
        successfully_imported.append(subdomain_name)
        success_count += 1

        # Create base endpoint (for scan)
        create_default_endpoint_for_subdomain(subdomain_obj, ctx)

    # Write results to file atomically using temporary file + rename
    # This ensures the file is never in a partially written state
    final_path = f"{results_dir}/from_imported.txt"
    try:
        # Create temp file in same directory for atomic rename
        fd, temp_path = tempfile.mkstemp(dir=results_dir, prefix=".from_imported_", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as output_file:
                for subdomain_name in successfully_imported:
                    output_file.write(f"{subdomain_name}\n")
            # Atomic rename - file appears complete or not at all
            os.replace(temp_path, final_path)
        except Exception:
            # Clean up temp file if write/rename fails
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise
    except Exception as e:
        logger.error(f"Failed to write imported subdomains file: {e}", exc_info=True)
        # Don't propagate - DB operations already succeeded
        # File can be regenerated from DB if needed

    # Report import statistics
    logger.info(f"Imported subdomains: {success_count} succeeded, {failed_count} failed")
    if failed_subdomains:
        logger.warning(
            f"Failed imported subdomains: {', '.join(failed_subdomains[:10])}"
            f"{' and ' + str(len(failed_subdomains) - 10) + ' more...' if len(failed_subdomains) > 10 else ''}"
        )


def create_default_endpoint_for_subdomain(subdomain_obj, ctx=None):
    """
    Create a default endpoint for a subdomain with metadata.

    Args:
        subdomain_obj: Subdomain object to create endpoint for
        ctx: Context dictionary containing scan information

    Returns:
        tuple: (endpoint, created) - endpoint object and whether it was created
    """
    if not ctx:
        ctx = {}

    url_filter = ctx.get("url_filter")
    http_url = f"{subdomain_obj.name}{url_filter}" if url_filter else subdomain_obj.name

    endpoint, created = save_endpoint(http_url=http_url, ctx=ctx, is_default=True, subdomain=subdomain_obj)

    if endpoint:
        save_subdomain_metadata(subdomain_obj, endpoint)
        logger.info(f"Created default endpoint for subdomain {subdomain_obj.name}: {http_url}")

    return endpoint, created


def save_metadata_info(meta_dict):
    """Extract metadata from Google Search.

    Args:
        meta_dict (dict): Info dict.

    Returns:
        list: List of startScan.MetaFinderDocument objects.
    """
    from dotted_dict import DottedDict
    from metafinder.extractor import extract_metadata_from_google_search

    from reNgine.utilities.proxy import get_random_proxy

    logger.warning(f"Getting metadata for {meta_dict.osint_target}")

    scan_history = ScanHistory.objects.get(id=meta_dict.scan_id)

    # Proxy settings
    get_random_proxy()

    # Get metadata
    result = extract_metadata_from_google_search(meta_dict.osint_target, meta_dict.documents_limit)
    if not result:
        logger.error(f"No metadata result from Google Search for {meta_dict.osint_target}.")
        return []

    # Add metadata info to DB
    results = []
    for metadata_name, data in result.get_metadata().items():
        subdomain = Subdomain.objects.get(scan_history=meta_dict.scan_id, name=meta_dict.osint_target)
        metadata = DottedDict(dict(data.items()))
        meta_finder_document = MetaFinderDocument(
            subdomain=subdomain,
            target_domain=meta_dict.domain,
            scan_history=scan_history,
            url=metadata.url,
            doc_name=metadata_name,
            http_status=metadata.status_code,
            producer=metadata.metadata.get("Producer"),
            creator=metadata.metadata.get("Creator"),
            creation_date=metadata.metadata.get("CreationDate"),
            modified_date=metadata.metadata.get("ModDate"),
            author=metadata.metadata.get("Author"),
            title=metadata.metadata.get("Title"),
            os=metadata.metadata.get("OSInfo"),
        )
        meta_finder_document.save()
        results.append(data)
    return results


def save_fuzzing_file(name, url, http_status, length=0, words=0, lines=0, content_type=None):
    """
    Save or retrieve DirectoryFile with Redis-based distributed locking for race condition prevention.

    Uses our reusable DistributedLock class for clean, modular distributed locking
    that ensures only one process can create a specific file record at a time.

    Args:
        name (str): File/directory name
        url (str): Full URL
        http_status (int): HTTP status code
        length (int): Content length
        words (int): Word count
        lines (int): Line count
        content_type (str): Content type header

    Returns:
        tuple: (DirectoryFile, created) where created is boolean
    """
    # Create a unique lock key based on name + url + status combination
    lock_key = f"fuzzing_file_lock:{hashlib.md5(f'{name}:{url}:{http_status}'.encode()).hexdigest()}"

    # Create the base data for querying
    base_data = {"name": name, "url": url, "http_status": http_status}

    # Create full data for creation
    full_data = base_data.copy()
    full_data.update(
        {
            "length": length,  # DirectoryFile uses 'length', not 'content_length'
            "lines": lines,
            "words": words,
            "content_type": content_type or "",
        }
    )

    # Use our reusable DistributedLock for race condition protection
    directory_file = DistributedLock.safe_get_or_create_with_lock(
        model_class=DirectoryFile,
        lock_key=lock_key,
        get_kwargs=base_data,
        create_kwargs=full_data,
        update_existing_callback=lambda obj: _update_directory_file_fields(obj, full_data),
    )

    if directory_file:
        # Return the created flag from our DistributedLock implementation
        was_created = getattr(directory_file, "_was_created", False)
        return directory_file, was_created
    else:
        # Fallback failed, return None
        return None, False


def _update_directory_file_fields(directory_file, full_data):
    """Helper function to update DirectoryFile fields when record exists."""
    fields_to_update = []

    # Compare and update fields if they differ (using correct field names)
    if directory_file.length != full_data["length"]:
        directory_file.length = full_data["length"]
        fields_to_update.append("length")
    if directory_file.lines != full_data["lines"]:
        directory_file.lines = full_data["lines"]
        fields_to_update.append("lines")
    if directory_file.words != full_data["words"]:
        directory_file.words = full_data["words"]
        fields_to_update.append("words")
    if directory_file.content_type != full_data["content_type"]:
        directory_file.content_type = full_data["content_type"]
        fields_to_update.append("content_type")

    if fields_to_update:
        directory_file.save(update_fields=fields_to_update)

    return directory_file


def get_task_cache_key(func_name, *args, **kwargs):
    args_str = "_".join([str(arg) for arg in args])
    kwargs_str = "_".join([f"{k}={v}" for k, v in kwargs.items() if k not in RENGINE_TASK_IGNORE_CACHE_KWARGS])
    return f"{func_name}__{args_str}__{kwargs_str}"
