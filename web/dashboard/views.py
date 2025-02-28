import json
import logging

from datetime import timedelta

from django.contrib import messages
from django.contrib.auth import get_user_model, update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from django.shortcuts import redirect, render, get_object_or_404
from django.utils import timezone
from django.http import HttpResponseRedirect, HttpResponseBadRequest, JsonResponse
from django.urls import reverse
from django.template.defaultfilters import slugify
from rolepermissions.roles import assign_role, clear_roles
from rolepermissions.decorators import has_permission_decorator

from dashboard.utils import get_user_projects, get_user_groups
from targetApp.models import Domain
from startScan.models import (
    EndPoint, ScanHistory, SubScan, Subdomain, Vulnerability, ScanActivity,
    IpAddress, Port, Technology, CountryISO
)
from dashboard.models import Project, OpenAiAPIKey, NetlasAPIKey
from dashboard.forms import ProjectForm
from reNgine.definitions import PERM_MODIFY_SYSTEM_CONFIGURATIONS, FOUR_OH_FOUR_URL

logger = logging.getLogger(__name__)

def index(request, slug):
    try:
        project = Project.get_from_slug(slug)
    except Project.DoesNotExist:
        return HttpResponseRedirect(reverse('page_not_found'))

    # Get activity feed
    scan_histories = ScanHistory.objects.filter(domain__project=project)
    scan_activities = ScanActivity.objects.filter(scan_of__in=scan_histories)
    activity_feed = scan_activities.order_by('-time')[:50]

    last_week = timezone.now() - timedelta(days=7)
    date_range = [last_week + timedelta(days=i) for i in range(7)]

    # Get timeline data from each model
    timeline_data = {
        'targets': Domain.get_project_timeline(project, date_range),
        'subdomains': Subdomain.get_project_timeline(project, date_range),
        'vulns': Vulnerability.get_project_timeline(project, date_range),
        'endpoints': EndPoint.get_project_timeline(project, date_range),
        'scans': {
            'pending': ScanHistory.get_project_timeline(project, date_range, status=0),
            'running': ScanHistory.get_project_timeline(project, date_range, status=1),
            'completed': ScanHistory.get_project_timeline(project, date_range, status=2),
            'failed': ScanHistory.get_project_timeline(project, date_range, status=3)
        },
        'subscans': {
            'pending': SubScan.get_project_timeline(project, date_range, status=0),
            'running': SubScan.get_project_timeline(project, date_range, status=1),
            'completed': SubScan.get_project_timeline(project, date_range, status=2),
            'failed': SubScan.get_project_timeline(project, date_range, status=3)
        }
    }

    # Get project data from all models
    ip_data = IpAddress.get_project_data(project)
    port_data = Port.get_project_data(project)
    tech_data = Technology.get_project_data(project)
    country_data = CountryISO.get_project_data(project)
    vulnerability_data = Vulnerability.get_project_data(project)

    # Get all counts using project-specific methods
    domain_counts = Domain.get_project_counts(project)
    subdomain_counts = Subdomain.get_project_counts(project)
    endpoint_counts = EndPoint.get_project_counts(project)
    scan_history_counts = ScanHistory.get_project_counts(project)
    subscan_counts = SubScan.get_project_counts(project)

    context = {
        'dashboard_data_active': 'active',
        'domain_count': domain_counts['total'],
        'scan_count': scan_history_counts,
        'subscan_count': subscan_counts,
        'subdomain_count': subdomain_counts['total'],
        'subdomain_with_ip_count': subdomain_counts['with_ip'],
        'alive_count': subdomain_counts['alive'],
        'endpoint_count': endpoint_counts['total'],
        'endpoint_alive_count': endpoint_counts['alive'],
        'info_count': subdomain_counts['vuln_info'],
        'low_count': subdomain_counts['vuln_low'],
        'medium_count': subdomain_counts['vuln_medium'],
        'high_count': subdomain_counts['vuln_high'],
        'critical_count': subdomain_counts['vuln_critical'],
        'unknown_count': subdomain_counts['vuln_unknown'],
        'total_vul_count': subdomain_counts['total_vuln_count'],
        'total_vul_ignore_info_count': subdomain_counts['total_vuln_ignore_info_count'],
        'vulnerability_feed': vulnerability_data['feed'],
        'activity_feed': activity_feed,
        'total_ips': ip_data['total_count'],
        'most_used_ip': ip_data['most_used'],
        'most_used_port': port_data['most_used'],
        'most_used_tech': tech_data['most_used'],
        'asset_countries': country_data['asset_countries'],
        'targets_in_last_week': timeline_data['targets'],
        'subdomains_in_last_week': timeline_data['subdomains'],
        'vulns_in_last_week': timeline_data['vulns'],
        'endpoints_in_last_week': timeline_data['endpoints'],
        'scans_in_last_week': timeline_data['scans'],
        'subscans_in_last_week': timeline_data['subscans'],
        'most_common_cve': vulnerability_data['most_common_cve'],
        'most_common_cwe': vulnerability_data['most_common_cwe'],
        'most_common_tags': vulnerability_data['most_common_tags'],
    }

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
