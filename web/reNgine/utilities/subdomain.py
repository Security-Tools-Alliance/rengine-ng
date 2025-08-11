from celery.utils.log import get_task_logger
from django.db.models import Q
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain
from .lookup import get_lookup_keywords

logger = get_task_logger(__name__)


#-------------------#
# SubDomain queries #
#-------------------#

def get_subdomains(write_filepath=None, exclude_subdomains=False, ctx=None):
    """Get Subdomain objects from DB.

    Args:
        write_filepath (str): Write info back to a file.
        exclude_subdomains (bool): Exclude subdomains, only return subdomain matching domain.
        ctx (dict): ctx

    Returns:
        list: List of subdomains matching query.
    """
    if ctx is None:
        ctx = {}
    domain_id = ctx.get('domain_id')
    scan_id = ctx.get('scan_history_id')
    subdomain_id = ctx.get('subdomain_id')
    exclude_subdomains = ctx.get('exclude_subdomains', False)
    url_filter = ctx.get('url_filter', '')
    domain = Domain.objects.filter(pk=domain_id).first()
    scan = ScanHistory.objects.filter(pk=scan_id).first()

    query = Subdomain.objects
    if domain:
        query = query.filter(target_domain=domain)
    if scan:
        query = query.filter(scan_history=scan)
    if subdomain_id:
        query = query.filter(pk=subdomain_id)
    elif domain and exclude_subdomains:
        query = query.filter(name=domain.name)
    subdomain_query = query.distinct('name').order_by('name')
    subdomains = [
        subdomain.name
        for subdomain in subdomain_query.all()
        if subdomain.name
    ]
    if not subdomains:
        logger.error('No subdomains were found in query !')

    if url_filter:
        subdomains = [f'{subdomain}/{url_filter}' for subdomain in subdomains]

    if write_filepath:
        with open(write_filepath, 'w') as f:
            f.write('\n'.join(subdomains))

    return subdomains


def get_new_added_subdomain(scan_id, domain_id):
    """Find domains added during the last scan.

    Args:
        scan_id (int): startScan.models.ScanHistory ID.
        domain_id (int): startScan.models.Domain ID.

    Returns:
        django.models.querysets.QuerySet: query of newly added subdomains.
    """
    scan = (
        ScanHistory.objects
        .filter(domain=domain_id)
        .filter(tasks__overlap=['subdomain_discovery'])
        .filter(id__lte=scan_id)
    )
    if scan.count() <= 1:
        return
    last_scan = scan.order_by('-start_scan_date')[1]
    scanned_host_q1 = (
        Subdomain.objects
        .filter(scan_history__id=scan_id)
        .values('name')
    )
    scanned_host_q2 = (
        Subdomain.objects
        .filter(scan_history__id=last_scan.id)
        .values('name')
    )
    added_subdomain = scanned_host_q1.difference(scanned_host_q2)
    return (
        Subdomain.objects
        .filter(scan_history=scan_id)
        .filter(name__in=added_subdomain)
    )


def get_removed_subdomain(scan_id, domain_id):
    """Find domains removed during the last scan.

    Args:
        scan_id (int): startScan.models.ScanHistory ID.
        domain_id (int): startScan.models.Domain ID.

    Returns:
        django.models.querysets.QuerySet: query of newly added subdomains.
    """
    scan_history = (
        ScanHistory.objects
        .filter(domain=domain_id)
        .filter(tasks__overlap=['subdomain_discovery'])
        .filter(id__lte=scan_id)
    )
    if scan_history.count() <= 1:
        return
    last_scan = scan_history.order_by('-start_scan_date')[1]
    scanned_host_q1 = (
        Subdomain.objects
        .filter(scan_history__id=scan_id)
        .values('name')
    )
    scanned_host_q2 = (
        Subdomain.objects
        .filter(scan_history__id=last_scan.id)
        .values('name')
    )
    removed_subdomains = scanned_host_q2.difference(scanned_host_q1)
    return (
        Subdomain.objects
        .filter(scan_history=last_scan)
        .filter(name__in=removed_subdomains)
    )


def get_interesting_subdomains(scan_history=None, domain_id=None):
    """Get Subdomain objects matching InterestingLookupModel conditions.

    Args:
        scan_history (startScan.models.ScanHistory, optional): Scan history.
        domain_id (int, optional): Domain id.

    Returns:
        django.db.Q: QuerySet object.
    """
    from scanEngine.models import InterestingLookupModel
    
    lookup_keywords = get_lookup_keywords()
    lookup_obj = (
        InterestingLookupModel.objects
        .filter(custom_type=True)
        .order_by('-id').first())
    if not lookup_obj:
        return Subdomain.objects.none()

    url_lookup = lookup_obj.url_lookup
    title_lookup = lookup_obj.title_lookup
    condition_200_http_lookup = lookup_obj.condition_200_http_lookup

    # Filter on domain_id, scan_history_id
    query = Subdomain.objects
    if domain_id:
        query = query.filter(target_domain__id=domain_id)
    elif scan_history:
        query = query.filter(scan_history__id=scan_history)

    # Filter on HTTP status code 200
    if condition_200_http_lookup:
        query = query.filter(http_status__exact=200)

    # Build subdomain lookup / page title lookup queries
    url_lookup_query = Q()
    title_lookup_query = Q()
    for key in lookup_keywords:
        if url_lookup:
            url_lookup_query |= Q(name__icontains=key)
        if title_lookup:
            title_lookup_query |= Q(page_title__iregex=f"\\y{key}\\y")

    # Filter on url / title queries
    url_lookup_query = query.filter(url_lookup_query)
    title_lookup_query = query.filter(title_lookup_query)

    # Return OR query
    return url_lookup_query | title_lookup_query 