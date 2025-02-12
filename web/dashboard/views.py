import json
import logging

from datetime import datetime, timedelta

from django.contrib import messages
from django.contrib.auth import get_user_model, update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.db.models import Count
from django.db.models.functions import TruncDay
from django.dispatch import receiver
from django.shortcuts import redirect, render, get_object_or_404
from django.utils import timezone
from django.utils.text import slugify
from django.http import HttpResponseRedirect, HttpResponseBadRequest, JsonResponse
from django.urls import reverse
from django.template.defaultfilters import slugify
from rolepermissions.roles import assign_role, clear_roles
from rolepermissions.decorators import has_permission_decorator

from dashboard.utils import get_user_projects, get_user_groups
from targetApp.models import Domain
from startScan.models import (
    EndPoint, ScanHistory, Subdomain, Vulnerability, ScanActivity,
    IpAddress, Port, Technology, CveId, CweId, VulnerabilityTags, CountryISO
)
from dashboard.models import Project, OpenAiAPIKey, NetlasAPIKey
from dashboard.forms import ProjectForm
from reNgine.definitions import PERM_MODIFY_SYSTEM_CONFIGURATIONS, FOUR_OH_FOUR_URL

logger = logging.getLogger(__name__)

def index(request, slug):
    try:
        project = Project.objects.get(slug=slug)
    except Project.DoesNotExist as e:
        # if project not found redirect to 404
        return HttpResponseRedirect(reverse('page_not_found'))

    domains = Domain.objects.filter(project=project)
    subdomains = Subdomain.objects.filter(scan_history__domain__project__slug=project)
    endpoints = EndPoint.objects.filter(scan_history__domain__project__slug=project)
    scan_histories = ScanHistory.objects.filter(domain__project=project)
    vulnerabilities = Vulnerability.objects.filter(scan_history__domain__project__slug=project)
    scan_activities = ScanActivity.objects.filter(scan_of__in=scan_histories)

    domain_count = domains.count()
    endpoint_count = endpoints.count()
    scan_count = scan_histories.count()
    subdomain_count = subdomains.count()
    subdomain_with_ip_count = subdomains.filter(ip_addresses__isnull=False).count()
    alive_count = subdomains.exclude(http_status__exact=0).count()
    endpoint_alive_count = endpoints.filter(http_status__gt=0).count()

    info_count = vulnerabilities.filter(severity=0).count()
    low_count = vulnerabilities.filter(severity=1).count()
    medium_count = vulnerabilities.filter(severity=2).count()
    high_count = vulnerabilities.filter(severity=3).count()
    critical_count = vulnerabilities.filter(severity=4).count()
    unknown_count = vulnerabilities.filter(severity=-1).count()

    vulnerability_feed = vulnerabilities.order_by('-discovered_date')[:50]
    activity_feed = scan_activities.order_by('-time')[:50]
    total_vul_count = info_count + low_count + \
        medium_count + high_count + critical_count + unknown_count
    total_vul_ignore_info_count = low_count + \
        medium_count + high_count + critical_count
    last_week = timezone.now() - timedelta(days=7)

    count_targets_by_date = domains.filter(
        insert_date__gte=last_week).annotate(
        date=TruncDay('insert_date')).values("date").annotate(
            created_count=Count('id')).order_by("-date")
    count_subdomains_by_date = subdomains.filter(
        discovered_date__gte=last_week).annotate(
        date=TruncDay('discovered_date')).values("date").annotate(
            count=Count('id')).order_by("-date")
    count_vulns_by_date = vulnerabilities.filter(
        discovered_date__gte=last_week).annotate(
        date=TruncDay('discovered_date')).values("date").annotate(
            count=Count('id')).order_by("-date")
    count_scans_by_date = scan_histories.filter(
        start_scan_date__gte=last_week).annotate(
        date=TruncDay('start_scan_date')).values("date").annotate(
            count=Count('id')).order_by("-date")
    count_endpoints_by_date = endpoints.filter(
        discovered_date__gte=last_week).annotate(
        date=TruncDay('discovered_date')).values("date").annotate(
            count=Count('id')).order_by("-date")

    last_7_dates = [(timezone.now() - timedelta(days=i)).date()
                    for i in range(0, 7)]

    targets_in_last_week = []
    subdomains_in_last_week = []
    vulns_in_last_week = []
    scans_in_last_week = []
    endpoints_in_last_week = []

    for date in last_7_dates:
        aware_date = timezone.make_aware(datetime.combine(date, datetime.min.time()))
        _target = count_targets_by_date.filter(date=aware_date)
        _subdomain = count_subdomains_by_date.filter(date=aware_date)
        _vuln = count_vulns_by_date.filter(date=aware_date)
        _scan = count_scans_by_date.filter(date=aware_date)
        _endpoint = count_endpoints_by_date.filter(date=aware_date)
        if _target:
            targets_in_last_week.append(_target[0]['created_count'])
        else:
            targets_in_last_week.append(0)
        if _subdomain:
            subdomains_in_last_week.append(_subdomain[0]['count'])
        else:
            subdomains_in_last_week.append(0)
        if _vuln:
            vulns_in_last_week.append(_vuln[0]['count'])
        else:
            vulns_in_last_week.append(0)
        if _scan:
            scans_in_last_week.append(_scan[0]['count'])
        else:
            scans_in_last_week.append(0)
        if _endpoint:
            endpoints_in_last_week.append(_endpoint[0]['count'])
        else:
            endpoints_in_last_week.append(0)

    targets_in_last_week.reverse()
    subdomains_in_last_week.reverse()
    vulns_in_last_week.reverse()
    scans_in_last_week.reverse()
    endpoints_in_last_week.reverse()

    context = {
        'dashboard_data_active': 'active',
        'domain_count': domain_count,
        'endpoint_count': endpoint_count,
        'scan_count': scan_count,
        'subdomain_count': subdomain_count,
        'subdomain_with_ip_count': subdomain_with_ip_count,
        'alive_count': alive_count,
        'endpoint_alive_count': endpoint_alive_count,
        'info_count': info_count,
        'low_count': low_count,
        'medium_count': medium_count,
        'high_count': high_count,
        'critical_count': critical_count,
        'unknown_count': unknown_count,
        'total_vul_count': total_vul_count,
        'total_vul_ignore_info_count': total_vul_ignore_info_count,
        'vulnerability_feed': vulnerability_feed,
        'activity_feed': activity_feed,
        'targets_in_last_week': targets_in_last_week,
        'subdomains_in_last_week': subdomains_in_last_week,
        'vulns_in_last_week': vulns_in_last_week,
        'scans_in_last_week': scans_in_last_week,
        'endpoints_in_last_week': endpoints_in_last_week,
        'last_7_dates': last_7_dates,
    }

    ip_addresses = IpAddress.objects.filter(ip_addresses__in=subdomains)

    context['total_ips'] = ip_addresses.count()
    context['most_used_port'] = Port.objects.filter(
        ports__in=ip_addresses
    ).annotate(
        count=Count('ports')
    ).order_by('-count')[:7]
    context['most_used_ip'] = ip_addresses.annotate(
        count=Count('ip_addresses')
    ).order_by('-count').exclude(
        ip_addresses__isnull=True
    )[:7]
    context['most_used_tech'] = Technology.objects.filter(technologies__in=subdomains).annotate(count=Count('technologies')).order_by('-count')[:7]

    context['most_common_cve'] = CveId.objects.filter(cve_ids__in=vulnerabilities).annotate(nused=Count('cve_ids')).order_by('-nused').values('name', 'nused')[:7]
    context['most_common_cwe'] = CweId.objects.filter(cwe_ids__in=vulnerabilities).annotate(nused=Count('cwe_ids')).order_by('-nused').values('name', 'nused')[:7]
    context['most_common_tags'] = VulnerabilityTags.objects.filter(vuln_tags__in=vulnerabilities).annotate(nused=Count('vuln_tags')).order_by('-nused').values('name', 'nused')[:7]

    context['asset_countries'] = CountryISO.objects.filter(ipaddress__in=ip_addresses).annotate(count=Count('ipaddress')).order_by('-count')

    return render(request, 'dashboard/index.html', context)

def profile(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(
                request,
                'Your password was successfully changed!')
            return redirect('profile')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'dashboard/profile.html', {
        'form': form
    })


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def admin_interface(request):
    UserModel = get_user_model()
    users = UserModel.objects.all().order_by('date_joined')
    return render(
        request,
        'dashboard/admin.html',
        {
            'users': users
        }
    )

class UserModificationError(Exception):
    def __init__(self, message, status_code=403):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

def check_user_modification_permissions(current_user, target_user, mode):
    """Check if current user has permission to modify target user."""
    if not target_user:
        raise UserModificationError('User ID not provided', 404)

    # Security checks for superusers and sys_admins
    if target_user.is_superuser and not current_user.is_superuser:
        raise UserModificationError('Only superadmin can modify another superadmin')
    
    # Prevent self-modification for both superusers and sys_admins
    if (current_user == target_user and 
        mode in ['delete', 'change_status'] and 
        (current_user.is_superuser or get_user_groups(current_user) == 'sys_admin')):
        raise UserModificationError('Administrators cannot delete or deactivate themselves')

@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def admin_interface_update(request):
    mode = request.GET.get('mode')
    method = request.method
    target_user = get_user_from_request(request)

    try:
        if mode and mode != 'create':
            check_user_modification_permissions(request.user, target_user, mode)

        # Check if the request is for user creation
        if method == 'POST' and mode == 'create':
            return handle_post_request(request, mode, None)

        if method == 'GET':
            return handle_get_request(request, mode, target_user)
        elif method == 'POST':
            return handle_post_request(request, mode, target_user)

    except UserModificationError as e:
        return JsonResponse({'status': False, 'error': e.message}, status=e.status_code)

    return HttpResponseRedirect(reverse('admin_interface'))


def get_user_from_request(request):
    if user_id := request.GET.get('user'):
        UserModel = get_user_model()
        return UserModel.objects.filter(id=user_id).first()  # Use first() to avoid exceptions
    return None


def handle_get_request(request, mode, user):
    if mode == 'change_status':
        user.is_active = not user.is_active
        user.save()
        if user.is_active:
            messages.add_message(
                request,
                messages.INFO,
                f'User {user.username} successfully activated.'
            )
        else:
            messages.add_message(
                request,
                messages.INFO,
                f'User {user.username} successfully deactivated.'
            )
        return HttpResponseRedirect(reverse('admin_interface'))
    return HttpResponseBadRequest(reverse('admin_interface'), status=400)


def handle_post_request(request, mode, user):
    if mode == 'delete':
        return handle_delete_user(request, user)
    elif mode == 'update':
        return handle_update_user(request, user)
    elif mode == 'create':
        return handle_create_user(request)
    return JsonResponse({'status': False, 'error': 'Invalid mode'}, status=400)


def handle_delete_user(request, user):
    try:
        user.delete()
        messages.add_message(
            request,
            messages.INFO,
            f'User {user.username} successfully deleted.'
        )
        return JsonResponse({'status': True})
    except (ValueError, KeyError) as e:
        logger.error("Error deleting user: %s", e)
        return JsonResponse({'status': False, 'error': 'An error occurred while deleting the user'})


def handle_update_user(request, user):
    try:
        response = json.loads(request.body)
        role = response.get('role')
        change_password = response.get('change_password')
        projects = response.get('projects', [])
        
        clear_roles(user)
        assign_role(user, role)
        if change_password:
            user.set_password(change_password)

        # Update projects
        user.projects.clear()  # Remove all existing projects
        for project_id in projects:
            project = Project.objects.get(id=project_id)
            user.projects.add(project)

        user.save()
        return JsonResponse({'status': True})
    except (ValueError, KeyError) as e:
        logger.error("Error updating user: %s", e)
        return JsonResponse({'status': False, 'error': 'An error occurred while updating the user'})


def handle_create_user(request):
    try:
        response = json.loads(request.body)
        if not response.get('password'):
            return JsonResponse({'status': False, 'error': 'Empty passwords are not allowed'})

        UserModel = get_user_model()
        user = UserModel.objects.create_user(
            username=response.get('username'),
            password=response.get('password')
        )
        assign_role(user, response.get('role'))

        # Add projects
        projects = response.get('projects', [])
        for project_id in projects:
            project = Project.objects.get(id=project_id)
            user.projects.add(project)

        return JsonResponse({'status': True})
    except (ValueError, KeyError) as e:
        logger.error("Error creating user: %s", e)
        return JsonResponse({'status': False, 'error': 'An error occurred while creating the user'})


@receiver(user_logged_out)
def on_user_logged_out(sender, request, **kwargs):
    messages.add_message(
        request,
        messages.INFO,
        'You have been successfully logged out. Thank you ' +
        'for using reNgine-ng.')


@receiver(user_logged_in)
def on_user_logged_in(sender, request, **kwargs):
    user = kwargs.get('user')
    messages.add_message(
        request,
        messages.INFO,
        'Hi @' +
        user.username +
        ' welcome back!')


def search(request):
    return render(request, 'dashboard/search.html')


def four_oh_four(request):
    return render(request, '404.html')

def projects(request):
    context = {'projects': get_user_projects(request.user)}
    return render(request, 'dashboard/projects.html', context)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def delete_project(request, id):
    obj = get_object_or_404(Project, id=id)
    if request.method == "POST":
        obj.delete()
        responseData = {
            'status': 'true'
        }
        messages.add_message(
            request,
            messages.INFO,
            'Project successfully deleted!')
    else:
        responseData = {'status': 'false'}
        messages.add_message(
            request,
            messages.ERROR,
            'Oops! Project could not be deleted!')
    return JsonResponse(responseData)

def onboarding(request):
    error = ''
    if request.method == "POST":
        project_name = request.POST.get('project_name')
        slug = slugify(project_name)
        create_username = request.POST.get('create_username')
        create_password = request.POST.get('create_password')
        create_user_role = request.POST.get('create_user_role')
        key_openai = request.POST.get('key_openai')
        key_netlas = request.POST.get('key_netlas')

        insert_date = timezone.now()

        try:
            Project.objects.create(
                name=project_name,
                slug=slug,
                insert_date=insert_date
            )
        except Exception as e:
            logger.error(f' Could not create project, Error: {e}')
            error = 'Could not create project, check logs for more details'


        try:
            if create_username and create_password and create_user_role:
                UserModel = get_user_model()
                user = UserModel.objects.create_user(
                    username=create_username,
                    password=create_password
                )
                assign_role(user, create_user_role)
        except Exception as e:
            logger.error(f'Could not create User, Error: {e}')
            error = 'Could not create User, check logs for more details'



        if key_openai:
            openai_api_key = OpenAiAPIKey.objects.first()
            if openai_api_key:
                openai_api_key.key = key_openai
                openai_api_key.save()
            else:
                OpenAiAPIKey.objects.create(key=key_openai)

        if key_netlas:
            netlas_api_key = NetlasAPIKey.objects.first()
            if netlas_api_key:
                netlas_api_key.key = key_netlas
                netlas_api_key.save()
            else:
                NetlasAPIKey.objects.create(key=key_netlas)

    context = {}
    context['error'] = error

    # Get first available project
    project = get_user_projects(request.user).first()

    context['openai_key'] = OpenAiAPIKey.objects.first()
    context['netlas_key'] = NetlasAPIKey.objects.first()

    # then redirect to the dashboard
    if project:
        slug = project.slug
        return HttpResponseRedirect(reverse('dashboardIndex', kwargs={'slug': slug}))

    # else redirect to the onboarding
    return render(request, 'dashboard/onboarding.html', context)

def list_projects(request):
    projects = get_user_projects(request.user)
    return render(request, 'dashboard/projects.html', {'projects': projects})

@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def edit_project(request, slug):
    project = get_object_or_404(Project, slug=slug)
    if not project.is_user_authorized(request.user):
        messages.error(request, "You don't have permission to edit this project.")
        return redirect('list_projects')
    
    User = get_user_model()
    all_users = User.objects.all()

    if request.method == 'POST':
        form = ProjectForm(request.POST, instance=project)
        if form.is_valid():
            # Generate new slug from the project name
            new_slug = slugify(form.cleaned_data['name'])
            
            # Check if the new slug already exists (excluding the current project)
            if Project.objects.exclude(id=project.id).filter(slug=new_slug).exists():
                form.add_error('name', 'A project with a similar name already exists. Please choose a different name.')
            else:
                # Save the form without committing to the database
                updated_project = form.save(commit=False)
                # Set the new slug
                updated_project.slug = new_slug
                # Now save to the database
                updated_project.save()
                # If your form has many-to-many fields, you need to call this
                form.save_m2m()
                
                messages.success(request, 'Project updated successfully.')
                return redirect('list_projects')
    else:
        form = ProjectForm(instance=project)
    
    return render(request, 'dashboard/edit_project.html', {
        'form': form,
        'edit_project': project,
        'users': all_users
    })

def set_current_project(request, slug):
    if request.method == 'GET':
        project = get_object_or_404(Project, slug=slug)
        response = HttpResponseRedirect(reverse('dashboardIndex', kwargs={'slug': slug}))
        response.set_cookie('currentProjectId', project.id, path='/', samesite='Strict', httponly=True, secure=request.is_secure())
        messages.success(request, f'Project {project.name} set as current project.')
        return response
    return HttpResponseBadRequest('Invalid request method. Only GET is allowed.', status=400)
