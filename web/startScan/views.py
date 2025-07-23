import markdown, json

from celery import group
from pathlib import Path
from weasyprint import HTML, CSS
from datetime import datetime, timedelta
from django.contrib import messages
from django.core.serializers.json import DjangoJSONEncoder
from django.db.models import Count
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.template.loader import get_template
from django.urls import reverse
from django.utils import timezone
from django.utils.html import mark_safe
from django_celery_beat.models import ClockedSchedule, IntervalSchedule, PeriodicTask
from rolepermissions.decorators import has_permission_decorator
from django.db.models.functions import Lower

from api.serializers import IpSerializer
from reNgine.celery import app
from reNgine.utilities.database import create_scan_activity, create_scan_object
from reNgine.utilities.subdomain import get_interesting_subdomains
from reNgine.utilities.data import safe_int_cast
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)
from reNgine.settings import RENGINE_RESULTS
from reNgine.definitions import ABORTED_TASK, SUCCESS_TASK, RUNNING_TASK, LIVE_SCAN, SCHEDULED_SCAN, PERM_INITATE_SCANS_SUBSCANS, PERM_MODIFY_SCAN_RESULTS, PERM_MODIFY_SCAN_REPORT, PERM_MODIFY_SYSTEM_CONFIGURATIONS, FOUR_OH_FOUR_URL
from reNgine.tasks import initiate_scan, run_command
from scanEngine.models import EngineType, VulnerabilityReportSetting
from startScan.models import ScanHistory, SubScan, Email, Employee, Subdomain, EndPoint, Vulnerability, VulnerabilityTags, IpAddress, CountryISO, ScanActivity, CveId, CweId
from targetApp.models import Domain, Organization


def scan_history(request, slug):
    host = ScanHistory.objects.filter(domain__project__slug=slug).order_by('-start_scan_date')
    context = {'scan_history_active': 'active', "scan_history": host}
    return render(request, 'startScan/history.html', context)


def subscan_history(request, slug):
    subscans = SubScan.objects.filter(scan_history__domain__project__slug=slug).order_by('-start_scan_date')
    context = {'scan_history_active': 'active', "subscans": subscans}
    return render(request, 'startScan/subscan_history.html', context)

def detail_scan(request, id, slug):
    ctx = {}

    # Get scan objects
    scan = get_object_or_404(ScanHistory, id=id)
    domain_id = safe_int_cast( scan.domain.id)
    scan_engines = EngineType.objects.annotate(
        lower_name=Lower('engine_name')
    ).order_by('lower_name')
    recent_scans = ScanHistory.objects.filter(domain__id=domain_id)
    last_scans = (
        ScanHistory.objects
        .filter(domain__id=domain_id)
        .filter(tasks__overlap=['subdomain_discovery'])
        .filter(id__lte=id)
        .filter(scan_status=2)
    )

    # Get all kind of objects associated with our ScanHistory object
    emails = Email.objects.filter(emails__in=[scan])
    employees = Employee.objects.filter(employees__in=[scan])
    subdomains = Subdomain.objects.filter(scan_history=scan)
    endpoints = EndPoint.objects.filter(scan_history=scan)
    vulns = Vulnerability.objects.filter(scan_history=scan)
    vulns_tags = VulnerabilityTags.objects.filter(vuln_tags__in=vulns)
    ip_addresses = IpAddress.objects.filter(
        ip_addresses__in=subdomains
    ).distinct('address')
    ip_serializer = IpSerializer(
        ip_addresses.all(), 
        many=True, 
        context={
            'scan_id': id,
            'target_id': domain_id
        }
    )
    geo_isos = CountryISO.objects.filter(ipaddress__in=ip_addresses)
    scan_activity = ScanActivity.objects.filter(scan_of__id=id).order_by('time')
    cves = CveId.objects.filter(cve_ids__in=vulns)
    cwes = CweId.objects.filter(cwe_ids__in=vulns)

    # HTTP statuses
    http_statuses = (
        subdomains
        .exclude(http_status=0)
        .values('http_status')
        .annotate(Count('http_status'))
    )

    # CVEs / CWes
    common_cves = (
        cves
        .annotate(nused=Count('cve_ids'))
        .order_by('-nused')
        .values('name', 'nused')
        [:10]
    )
    common_cwes = (
        cwes
        .annotate(nused=Count('cwe_ids'))
        .order_by('-nused')
        .values('name', 'nused')
        [:10]
    )

    # Tags
    common_tags = (
        vulns_tags
        .annotate(nused=Count('vuln_tags'))
        .order_by('-nused')
        .values('name', 'nused')
        [:7]
    )

    # Countries
    asset_countries = (
        geo_isos
        .annotate(count=Count('iso'))
        .order_by('-count')
    )

    # Subdomains
    subdomain_count = (
        subdomains
        .values('name')
        .distinct()
        .count()
    )
    alive_count = (
        subdomains
        .values('name')
        .distinct()
        .filter(http_status__gt=0)
        .count()
    )
    important_count = (
        subdomains
        .values('name')
        .distinct()
        .filter(is_important=True)
        .count()
    )

    # Endpoints
    endpoint_count = (
        endpoints
        .values('http_url')
        .distinct()
        .count()
    )
    endpoint_alive_count = (
        endpoints
        .filter(http_status__gt=0) # TODO: use is_alive() func as it's more precise
        .values('http_url')
        .distinct()
        .count()
    )

    # Vulnerabilities
    common_vulns = (
        vulns
        .exclude(severity=0)
        .values('name', 'severity')
        .annotate(count=Count('name'))
        .order_by('-count')
        [:10]
    )
    info_count = vulns.filter(severity=0).count()
    low_count = vulns.filter(severity=1).count()
    medium_count = vulns.filter(severity=2).count()
    high_count = vulns.filter(severity=3).count()
    critical_count = vulns.filter(severity=4).count()
    unknown_count = vulns.filter(severity=-1).count()
    total_count = vulns.count()
    total_count_ignore_info = vulns.exclude(severity=0).count()

    # Emails
    exposed_count = emails.exclude(password__isnull=True).count()

    # Build render context
    ctx = {
        'scan_history_id': id,
        'history': scan,
        'scan_activity': scan_activity,
        'ip_addresses': json.dumps(ip_serializer.data, cls=DjangoJSONEncoder),
        'subdomain_count': subdomain_count,
        'alive_count': alive_count,
        'important_count': important_count,
        'endpoint_count': endpoint_count,
        'endpoint_alive_count': endpoint_alive_count,
        'info_count': info_count,
        'low_count': low_count,
        'medium_count': medium_count,
        'high_count': high_count,
        'critical_count': critical_count,
        'unknown_count': unknown_count,
        'total_vulnerability_count': total_count,
        'total_vul_ignore_info_count': total_count_ignore_info,
        'vulnerability_list': vulns.order_by('-severity').all(),
        'scan_history_active': 'active',
        'scan_engines': scan_engines,
        'exposed_count': exposed_count,
        'email_count': emails.count(),
        'employees_count': employees.count(),
        'most_recent_scans': recent_scans.order_by('-start_scan_date')[:1],
        'http_status_breakdown': http_statuses,
        'most_common_cve': common_cves,
        'most_common_cwe': common_cwes,
        'most_common_tags': common_tags,
        'most_common_vulnerability': common_vulns,
        'asset_countries': asset_countries,
    }

    # Find number of matched GF patterns
    if scan.used_gf_patterns:
        count_gf = {}
        for gf in scan.used_gf_patterns.split(','):
            count_gf[gf] = (
                endpoints
                .filter(matched_gf_patterns__icontains=gf)
                .count()
            )
            ctx['matched_gf_count'] = count_gf

    # Find last scan for this domain
    if last_scans.count() > 1:
        last_scan = last_scans.order_by('-start_scan_date')[1]
        ctx['last_scan'] = last_scan

    return render(request, 'startScan/detail_scan.html', ctx)


def all_subdomains(request, slug):
    subdomains = Subdomain.objects.filter(target_domain__project__slug=slug)
    scan_engines = EngineType.objects.annotate(
        lower_name=Lower('engine_name')
    ).order_by('lower_name')
    alive_subdomains = subdomains.filter(http_status__gt=0) # TODO: replace this with is_alive() function
    important_subdomains = (
        subdomains
        .filter(is_important=True)
        .values('name')
        .distinct()
        .count()
    )
    context = {
        'scan_history_id': id,
        'scan_history_active': 'active',
        'scan_engines': scan_engines,
        'subdomain_count': subdomains.values('name').distinct().count(),
        'alive_count': alive_subdomains.values('name').distinct().count(),
        'important_count': important_subdomains
    }
    return render(request, 'startScan/subdomains.html', context)

def detail_vuln_scan(request, slug, id=None):
    if id:
        history = get_object_or_404(ScanHistory, id=id)
        context = {'scan_history_id': id, 'history': history}
    else:
        context = {'vuln_scan_active': 'true'}
    return render(request, 'startScan/vulnerabilities.html', context)

def all_endpoints(request, slug):
    context = {
        'scan_history_active': 'active'
    }
    return render(request, 'startScan/endpoints.html', context)


def start_scan_ui(request, slug, domain_id):
    domain = get_object_or_404(Domain, id=domain_id)
    if request.method == "POST":
        # Get imported and out-of-scope subdomains
        subdomains_in = request.POST['importSubdomainTextArea'].split()
        subdomains_in = [s.rstrip() for s in subdomains_in if s]
        subdomains_out = request.POST['outOfScopeSubdomainTextarea'].split()
        subdomains_out = [s.rstrip() for s in subdomains_out if s]
        paths = request.POST['filterPath'].split()
        filterPath = [s.rstrip() for s in paths if s]
        if len(filterPath) > 0:
            filterPath = filterPath[0]
        else:
            filterPath = ''

        # Get engine type
        engine_id = safe_int_cast(request.POST['scan_mode'])

        # Create ScanHistory object
        scan_history_id = create_scan_object(
            host_id=domain_id,
            engine_id=engine_id,
            initiated_by_id=request.user.id
        )
        scan = ScanHistory.objects.get(pk=scan_history_id)

        # Start the celery task
        kwargs = {
            'scan_history_id': scan.id,
            'domain_id': domain.id,
            'engine_id': engine_id,
            'scan_type': LIVE_SCAN,
            'results_dir': RENGINE_RESULTS,
            'imported_subdomains': subdomains_in,
            'out_of_scope_subdomains': subdomains_out,
            'url_filter': filterPath,
            'initiated_by_id': request.user.id
        }
        initiate_scan.apply_async(kwargs=kwargs)
        scan.save()

        # Send start notif
        messages.add_message(
            request,
            messages.INFO,
            f'Scan Started for {domain.name}')
        return HttpResponseRedirect(reverse('scan_history', kwargs={'slug': slug}))

    # GET request
    engine = EngineType.objects.annotate(
        lower_name=Lower('engine_name')
    ).order_by('lower_name')
    custom_engine_count = (
        EngineType.objects
        .filter(default_engine=False)
        .count()
    )
    context = {
        'scan_history_active': 'active',
        'domain': domain,
        'engines': engine,
        'custom_engine_count': custom_engine_count}
    return render(request, 'startScan/start_scan_ui.html', context)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def start_multiple_scan(request, slug):
    # domain = get_object_or_404(Domain, id=host_id)
    if request.method == "POST":
        if request.POST.get('scan_mode', 0):
            # if scan mode is available, then start the scan
            # get engine type
            engine_id = safe_int_cast( request.POST['scan_mode'])
            list_of_domains = request.POST['list_of_domain_id']

            grouped_scans = []

            for domain_id in list_of_domains.split(","):
                # Start the celery task
                scan_history_id = create_scan_object(
                    host_id=domain_id,
                    engine_id=engine_id,
                    initiated_by_id=request.user.id
                )
                # domain = get_object_or_404(Domain, id=domain_id)

                kwargs = {
                    'scan_history_id': scan_history_id,
                    'domain_id': domain_id,
                    'engine_id': engine_id,
                    'scan_type': LIVE_SCAN,
                    'results_dir': RENGINE_RESULTS,
                    'initiated_by_id': request.user.id
                    # TODO: Add this to multiple scan view
                    # 'imported_subdomains': subdomains_in,
                    # 'out_of_scope_subdomains': subdomains_out
                }

                _scan_task = initiate_scan.si(**kwargs)
                grouped_scans.append(_scan_task)

            celery_group = group(grouped_scans)
            celery_group.apply_async()

            # Send start notif
            messages.add_message(
                request,
                messages.INFO,
                'Scan Started for multiple targets')

            return HttpResponseRedirect(reverse('scan_history', kwargs={'slug': slug}))

        else:
            # this else condition will have post request from the scan page
            # containing all the targets id
            list_of_domain_name = []
            list_of_domain_id = []
            for key, value in request.POST.items():
                if key != "list_target_table_length" and key != "csrfmiddlewaretoken":
                    domain = get_object_or_404(Domain, id=value)
                    list_of_domain_name.append(domain.name)
                    list_of_domain_id.append(value)
            domain_ids = ",".join(list_of_domain_id)

    # GET request
    engines = EngineType.objects
    custom_engine_count = (
        engines
        .filter(default_engine=False)
        .count()
    )
    context = {
        'scan_history_active': 'active',
        'engines': engines,
        'domain_list': list_of_domain_name,
        'domain_ids': domain_ids,
        'custom_engine_count': custom_engine_count
    }
    return render(request, 'startScan/start_multiple_scan_ui.html', context)

def export_subdomains(request, slug, scan_id):
    subdomain_list = Subdomain.objects.filter(scan_history__id=scan_id)
    scan = ScanHistory.objects.get(id=scan_id)
    response_body = ""
    for domain in subdomain_list:
        response_body += response_body + domain.name + "\n"
    scan_start_date_str = str(scan.start_scan_date.date())
    domain_name = scan.domain.name
    response = HttpResponse(response_body, content_type='text/plain')
    response['Content-Disposition'] = (
        f'attachment; filename="subdomains_{domain_name}_{scan_start_date_str}.txt"'
    )
    return response


def export_endpoints(request, slug, scan_id):
    endpoint_list = EndPoint.objects.filter(scan_history__id=scan_id)
    scan = ScanHistory.objects.get(id=scan_id)
    response_body = ""
    for endpoint in endpoint_list:
        response_body += endpoint.http_url + "\n"
    scan_start_date_str = str(scan.start_scan_date.date())
    domain_name = scan.domain.name
    response = HttpResponse(response_body, content_type='text/plain')
    response['Content-Disposition'] = (
        f'attachment; filename="endpoints_{domain_name}_{scan_start_date_str}.txt"'
    )
    return response


def export_urls(request, slug, scan_id):
    urls_list = Subdomain.objects.filter(scan_history__id=scan_id)
    scan = ScanHistory.objects.get(id=scan_id)
    response_body = ""
    for url in urls_list:
        if url.http_url:
            response_body += response_body + url.http_url + "\n"
    scan_start_date_str = str(scan.start_scan_date.date())
    domain_name = scan.domain.name
    response = HttpResponse(response_body, content_type='text/plain')
    response['Content-Disposition'] = (
        f'attachment; filename="urls_{domain_name}_{scan_start_date_str}.txt"'
    )
    return response


@has_permission_decorator(PERM_MODIFY_SCAN_RESULTS, redirect_url=FOUR_OH_FOUR_URL)
def delete_scan(request, slug, id):
    obj = get_object_or_404(ScanHistory, id=id)
    if request.method == "POST":
        delete_dir = obj.results_dir
        run_command('rm -rf ' + delete_dir)
        obj.delete()
        messageData = {'status': 'true'}
        messages.add_message(
            request,
            messages.INFO,
            'Scan history successfully deleted!'
        )
    else:
        messageData = {'status': 'false'}
        messages.add_message(
            request,
            messages.INFO,
            'Oops! something went wrong!'
        )
    return JsonResponse(messageData)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def stop_scan(request, slug, id):
    if request.method == "POST":
        scan = get_object_or_404(ScanHistory, id=id)
        scan.scan_status = ABORTED_TASK
        scan.save()
        try:
            for task_id in scan.celery_ids:
                app.control.revoke(task_id, terminate=True, signal='SIGKILL')
            tasks = (
                ScanActivity.objects
                .filter(scan_of=scan)
                .filter(status=RUNNING_TASK)
                .order_by('-pk')
            )
            for task in tasks:
                task.status = ABORTED_TASK
                task.time = timezone.now()
                task.save()
            create_scan_activity(scan.id, "Scan aborted", SUCCESS_TASK)
            response = {'status': True}
            messages.add_message(
                request,
                messages.INFO,
                'Scan successfully stopped!'
            )
        except Exception as e:
            logger.error(e)
            response = {'status': False}
            messages.add_message(
                request,
                messages.ERROR,
                f'Scan failed to stop ! Error: {str(e)}'
            )
        return JsonResponse(response)
    return scan_history(request)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def schedule_scan(request, host_id, slug):
    domain = Domain.objects.get(id=host_id)
    if request.method == "POST":
        scheduled_mode = request.POST['scheduled_mode']
        engine_type = int(request.POST['scan_mode'])

        # Get imported and out-of-scope subdomains
        subdomains_in = request.POST['importSubdomainTextArea'].split()
        subdomains_in = [s.rstrip() for s in subdomains_in if s]
        subdomains_out = request.POST['outOfScopeSubdomainTextarea'].split()
        subdomains_out = [s.rstrip() for s in subdomains_out if s]

        # Get engine type
        engine = get_object_or_404(EngineType, id=engine_type)
        timestr = str(datetime.strftime(timezone.now(), '%Y_%m_%d_%H_%M_%S'))
        task_name = f'{engine.engine_name} for {domain.name}: {timestr}'
        if scheduled_mode == 'periodic':
            frequency_value = int(request.POST['frequency'])
            frequency_type = request.POST['frequency_type']
            if frequency_type == 'minutes':
                period = IntervalSchedule.MINUTES
            elif frequency_type == 'hours':
                period = IntervalSchedule.HOURS
            elif frequency_type == 'days':
                period = IntervalSchedule.DAYS
            elif frequency_type == 'weeks':
                period = IntervalSchedule.DAYS
                frequency_value *= 7
            elif frequency_type == 'months':
                period = IntervalSchedule.DAYS
                frequency_value *= 30
            schedule, _ = IntervalSchedule.objects.get_or_create(
                every=frequency_value,
                period=period)
            kwargs = {
                'domain_id': host_id,
                'engine_id': engine.id,
                'scan_history_id': 1,
                'scan_type': SCHEDULED_SCAN,
                'imported_subdomains': subdomains_in,
                'out_of_scope_subdomains': subdomains_out,
                'initiated_by_id': request.user.id
            }
            PeriodicTask.objects.create(
                interval=schedule,
                name=task_name,
                task='initiate_scan',
                kwargs=json.dumps(kwargs)
            )
        elif scheduled_mode == 'clocked':
            schedule_time = request.POST['scheduled_time']
            timezone_offset = int(request.POST.get('timezone_offset', 0))
            # Convert received hour in UTC
            local_time = datetime.strptime(schedule_time, '%Y-%m-%d %H:%M')
            # Adjust hour to UTC
            utc_time = local_time + timedelta(minutes=timezone_offset)
            # Make hour "aware" in UTC
            utc_time = timezone.make_aware(utc_time, timezone.utc)
            clock, _ = ClockedSchedule.objects.get_or_create(
                clocked_time=utc_time)
            kwargs = {
                'scan_history_id': 0,
                'domain_id': host_id,
                'engine_id': engine.id,
                'scan_type': SCHEDULED_SCAN,
                'imported_subdomains': subdomains_in,
                'out_of_scope_subdomains': subdomains_out,
                'initiated_by_id': request.user.id
            }
            PeriodicTask.objects.create(
                clocked=clock,
                one_off=True,
                name=task_name,
                task='initiate_scan',
                kwargs=json.dumps(kwargs)
            )
        messages.add_message(
            request,
            messages.INFO,
            f'Scan Scheduled for {domain.name}'
        )
        return HttpResponseRedirect(reverse('scheduled_scan_view', kwargs={'slug': slug}))

    # GET request
    engines = EngineType.objects
    custom_engine_count = (
        engines
        .filter(default_engine=False)
        .count()
    )
    context = {
        'scan_history_active': 'active',
        'domain': domain,
        'engines': engines,
        'custom_engine_count': custom_engine_count}
    return render(request, 'startScan/schedule_scan_ui.html', context)


def scheduled_scan_view(request, slug):
    scheduled_tasks = (
        PeriodicTask.objects
        .all()
        .exclude(name='celery.backend_cleanup')
    )
    context = {
        'scheduled_scan_active': 'active',
        'scheduled_tasks': scheduled_tasks,
    }
    return render(request, 'startScan/schedule_scan_list.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_RESULTS, redirect_url=FOUR_OH_FOUR_URL)
def delete_scheduled_task(request, slug, id):
    task_object = get_object_or_404(PeriodicTask, id=id)
    if request.method == "POST":
        task_object.delete()
        messageData = {'status': 'true'}
        messages.add_message(
            request,
            messages.INFO,
            'Scheduled Scan successfully deleted!')
    else:
        messageData = {'status': 'false'}
        messages.add_message(
            request,
            messages.INFO,
            'Oops! something went wrong!')
    return JsonResponse(messageData)


@has_permission_decorator(PERM_MODIFY_SCAN_RESULTS, redirect_url=FOUR_OH_FOUR_URL)
def change_scheduled_task_status(request, slug, id):
    if request.method == 'POST':
        task = PeriodicTask.objects.get(id=id)
        task.enabled = not task.enabled
        task.save()
    return HttpResponse('')


def change_vuln_status(request, slug, id):
    if request.method == 'POST':
        vuln = Vulnerability.objects.get(id=id)
        vuln.open_status = not vuln.open_status
        vuln.save()
    return HttpResponse('')


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def delete_all_scan_results(request, slug):
    if request.method == 'POST':
        ScanHistory.objects.filter(project__slug=slug).delete()
        messageData = {'status': 'true'}
        messages.add_message(
            request,
            messages.INFO,
            'All Scan History successfully deleted!')
    return JsonResponse(messageData)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def delete_all_screenshots(request, slug):
    if request.method == 'POST':
        domains = Domain.objects.filter(project__slug=slug)
        for domain in domains:
            run_command(f'rm -rf {str(Path(RENGINE_RESULTS) / domain.name)}')
        messageData = {'status': 'true'}
        messages.add_message(
            request,
            messages.INFO,
            'Screenshots successfully deleted!')
    return JsonResponse(messageData)


def visualise(request, id):
    scan = ScanHistory.objects.get(id=id)
    context = {
        'scan_id': id,
        'scan_history': scan,
    }
    return render(request, 'startScan/visualise.html', context)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def start_organization_scan(request, id, slug):
    organization = get_object_or_404(Organization, id=id)
    if request.method == "POST":
        engine_id = safe_int_cast( request.POST['scan_mode'])

        # Start Celery task for each organization's domains
        for domain in organization.get_domains():
            scan_history_id = create_scan_object(
                host_id=domain.id,
                engine_id=engine_id,
                initiated_by_id=request.user.id
            )
            scan = ScanHistory.objects.get(pk=scan_history_id)

            kwargs = {
                'scan_history_id': scan.id,
                'domain_id': domain.id,
                'engine_id': engine_id,
                'scan_type': LIVE_SCAN,
                'results_dir': RENGINE_RESULTS,
                'initiated_by_id': request.user.id,
                # TODO: Add this to multiple scan view
                # 'imported_subdomains': subdomains_in,
                # 'out_of_scope_subdomains': subdomains_out
            }
            initiate_scan.apply_async(kwargs=kwargs)
            scan.save()


        # Send start notif
        ndomains = len(organization.get_domains())
        messages.add_message(
            request,
            messages.INFO,
            f'Scan Started for {ndomains} domains in organization {organization.name}')
        return HttpResponseRedirect(reverse('scan_history', kwargs={'slug': slug}))

    # GET request
    engine = EngineType.objects.annotate(
        lower_name=Lower('engine_name')
    ).order_by('lower_name')
    custom_engine_count = EngineType.objects.filter(default_engine=False).count()
    domain_list = organization.get_domains()
    context = {
        'organization_data_active': 'true',
        'list_organization_li': 'active',
        'organization': organization,
        'engines': engine,
        'domain_list': domain_list,
        'custom_engine_count': custom_engine_count}
    return render(request, 'organization/start_scan.html', context)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def schedule_organization_scan(request, slug, id):
    organization =Organization.objects.get(id=id)
    if request.method == "POST":
        engine_type = int(request.POST['scan_mode'])
        engine = get_object_or_404(EngineType, id=engine_type)
        scheduled_mode = request.POST['scheduled_mode']
        for domain in organization.get_domains():
            timestr = str(datetime.strftime(timezone.now(), '%Y_%m_%d_%H_%M_%S'))
            task_name = f'{engine.engine_name} for {domain.name}: {timestr}'

            # Period task
            if scheduled_mode == 'periodic':
                frequency_value = int(request.POST['frequency'])
                frequency_type = request.POST['frequency_type']
                if frequency_type == 'minutes':
                    period = IntervalSchedule.MINUTES
                elif frequency_type == 'hours':
                    period = IntervalSchedule.HOURS
                elif frequency_type == 'days':
                    period = IntervalSchedule.DAYS
                elif frequency_type == 'weeks':
                    period = IntervalSchedule.DAYS
                    frequency_value *= 7
                elif frequency_type == 'months':
                    period = IntervalSchedule.DAYS
                    frequency_value *= 30

                schedule, _ = IntervalSchedule.objects.get_or_create(
                    every=frequency_value,
                    period=period
                )
                _kwargs = json.dumps({
                    'domain_id': domain.id,
                    'engine_id': engine.id,
                    'scan_history_id': 0,
                    'scan_type': SCHEDULED_SCAN,
                    'imported_subdomains': None,
                    'initiated_by_id': request.user.id
                })
                PeriodicTask.objects.create(
                    interval=schedule,
                    name=task_name,
                    task='initiate_scan',
                    kwargs=_kwargs
                )

            # Clocked task
            elif scheduled_mode == 'clocked':
                schedule_time = request.POST['scheduled_time']
                clock, _ = ClockedSchedule.objects.get_or_create(
                    clocked_time=schedule_time
                )
                _kwargs = json.dumps({
                    'domain_id': domain.id,
                    'engine_id': engine.id,
                    'scan_history_id': 0,
                    'scan_type': LIVE_SCAN,
                    'imported_subdomains': None,
                    'initiated_by_id': request.user.id
                })
                PeriodicTask.objects.create(clocked=clock,
                    one_off=True,
                    name=task_name,
                    task='initiate_scan',
                    kwargs=_kwargs
                )

        # Send start notif
        ndomains = len(organization.get_domains())
        messages.add_message(
            request,
            messages.INFO,
            f'Scan started for {ndomains} domains in organization {organization.name}'
        )
        return HttpResponseRedirect(reverse('scheduled_scan_view', kwargs={'slug': slug}))

    # GET request
    engine = EngineType.objects.annotate(
        lower_name=Lower('engine_name')
    ).order_by('lower_name')
    custom_engine_count = EngineType.objects.filter(default_engine=False).count()
    context = {
        'scan_history_active': 'active',
        'organization': organization,
        'domain_list': organization.get_domains(),
        'engines': engine,
        'custom_engine_count': custom_engine_count
    }
    return render(request, 'organization/schedule_scan_ui.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_RESULTS, redirect_url=FOUR_OH_FOUR_URL)
def delete_scans(request, slug):
    if request.method == "POST":
        for key, value in request.POST.items():
            if key == 'scan_history_table_length' or key == 'csrfmiddlewaretoken':
                continue
            scan = get_object_or_404(ScanHistory, id=value)
            delete_dir = scan.results_dir
            run_command('rm -rf ' + delete_dir)
            scan.delete()
        messages.add_message(
            request,
            messages.INFO,
            'All Scans deleted!')
    return HttpResponseRedirect(reverse('scan_history', kwargs={'slug': slug}))


@has_permission_decorator(PERM_MODIFY_SCAN_REPORT, redirect_url=FOUR_OH_FOUR_URL)
def customize_report(request, id):
    scan = ScanHistory.objects.get(id=id)
    context = {
        'scan_id': id,
        'scan_history': scan,
    }
    return render(request, 'startScan/customize_report.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_REPORT, redirect_url=FOUR_OH_FOUR_URL)
def create_report(request, slug, id):
    primary_color = '#FFB74D'
    secondary_color = '#212121'
    # get report type
    report_type = request.GET['report_type'] if 'report_type' in request.GET  else 'full'
    is_ignore_info_vuln = True if 'ignore_info_vuln' in request.GET else False
    if report_type == 'recon':
        show_recon = True
        show_vuln = False
        report_name = 'Reconnaissance Report'
    elif report_type == 'vulnerability':
        show_recon = False
        show_vuln = True
        report_name = 'Vulnerability Report'
    else:
        # default
        show_recon = True
        show_vuln = True
        report_name = 'Full Scan Report'

    scan = ScanHistory.objects.get(id=id)
    vulns = (
        Vulnerability.objects
        .filter(scan_history=scan)
        .order_by('-severity')
    ) if not is_ignore_info_vuln else (
        Vulnerability.objects
        .filter(scan_history=scan)
        .exclude(severity=0)
        .order_by('-severity')
    )
    unique_vulns = (
        Vulnerability.objects
        .filter(scan_history=scan)
        .values("name", "severity")
        .annotate(count=Count('name'))
        .order_by('-severity', '-count')
    ) if not is_ignore_info_vuln else (
        Vulnerability.objects
        .filter(scan_history=scan)
        .exclude(severity=0)
        .values("name", "severity")
        .annotate(count=Count('name'))
        .order_by('-severity', '-count')
    )

    subdomains = (
        Subdomain.objects
        .filter(scan_history=scan)
        .order_by('-content_length')
    )
    subdomain_alive_count = (
        Subdomain.objects
        .filter(scan_history__id=id)
        .values('name')
        .distinct()
        .filter(http_status__gt=0)
        .count()
    )
    interesting_subdomains = get_interesting_subdomains(scan_history=id)
    ip_addresses = (
        IpAddress.objects
        .filter(ip_addresses__in=subdomains)
        .prefetch_related(
            'ports',
        )
        .distinct()
    )
    
    data = {
        'scan_object': scan,
        'unique_vulnerabilities': unique_vulns,
        'all_vulnerabilities': vulns,
        'all_vulnerabilities_count': vulns.count(),
        'subdomain_alive_count': subdomain_alive_count,
        'interesting_subdomains': interesting_subdomains,
        'subdomains': subdomains,
        'ip_addresses': ip_addresses,
        'ip_addresses_count': ip_addresses.count(),
        'show_recon': show_recon,
        'show_vuln': show_vuln,
        'report_name': report_name,
        'is_ignore_info_vuln': is_ignore_info_vuln,
    }

    # Get report related config
    vuln_report_query = VulnerabilityReportSetting.objects.all()
    if vuln_report_query.exists():
        report = vuln_report_query[0]
        data['company_name'] = report.company_name
        data['company_address'] = report.company_address
        data['company_email'] = report.company_email
        data['company_website'] = report.company_website
        data['show_rengine_banner'] = report.show_rengine_banner
        data['show_footer'] = report.show_footer
        data['footer_text'] = report.footer_text
        data['show_executive_summary'] = report.show_executive_summary

        # Replace executive_summary_description with template syntax
        description = report.executive_summary_description
        description = description.replace('{scan_date}', scan.start_scan_date.strftime('%d %B, %Y'))
        description = description.replace('{company_name}', report.company_name)
        description = description.replace('{target_name}', scan.domain.name)
        description = description.replace('{subdomain_count}', str(subdomains.count()))
        description = description.replace('{vulnerability_count}', str(vulns.count()))
        description = description.replace('{critical_count}', str(vulns.filter(severity=4).count()))
        description = description.replace('{high_count}', str(vulns.filter(severity=3).count()))
        description = description.replace('{medium_count}', str(vulns.filter(severity=2).count()))
        description = description.replace('{low_count}', str(vulns.filter(severity=1).count()))
        description = description.replace('{info_count}', str(vulns.filter(severity=0).count()))
        description = description.replace('{unknown_count}', str(vulns.filter(severity=-1).count()))
        if scan.domain.description:
            description = description.replace('{target_description}', scan.domain.description)

        # Convert to Markdown
        data['executive_summary_description'] = markdown.markdown(description)

        primary_color = report.primary_color
        secondary_color = report.secondary_color

    data['primary_color'] = primary_color
    data['secondary_color'] = secondary_color

    # Configure WeasyPrint with the necessary CSS styles
    css = CSS(string='''
        /* General styles */
        body { font-family: Arial, sans-serif; }
        
        /* Styles for markdown */
        h1, h2, h3, h4 { margin-top: 1em; }
        ul, ol { margin-left: 2em; }
        pre, code { 
            background-color: #f5f5f5;
            padding: 0.2em 0.4em;
            border-radius: 3px;
        }
        
        /* Styles for tables */
        table { 
            border-collapse: collapse;
            width: 100%;
            margin: 1em 0;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
    ''')

    # Preprocess HTML/Markdown fields
    for vuln in data['all_vulnerabilities']:
        if vuln.description:
            vuln.description = mark_safe(vuln.description)
        if vuln.impact:
            vuln.impact = mark_safe(vuln.impact)
        if vuln.remediation:
            vuln.remediation = mark_safe(vuln.remediation)
        if vuln.references:
            vuln.references = mark_safe(vuln.references)

    template = get_template('report/template.html')
    html = template.render(data)

    # Generate the PDF with the CSS styles
    pdf = HTML(string=html).write_pdf(
        stylesheets=[css],
        presentational_hints=True
    )

    if 'download' in request.GET:
        response = HttpResponse(pdf, content_type='application/octet-stream')
    else:
        response = HttpResponse(pdf, content_type='application/pdf')

    return response
