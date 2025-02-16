import glob
import json
import os
import re
import shutil

from datetime import datetime
from django import http
from django.contrib import messages
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from rolepermissions.decorators import has_permission_decorator

from reNgine.common_func import get_open_ai_key
from reNgine.definitions import OLLAMA_INSTANCE, DEFAULT_GPT_MODELS
from reNgine.tasks import run_command, send_discord_message, send_slack_message, send_lark_message, send_telegram_message, run_gf_list
from scanEngine.forms import AddEngineForm, UpdateEngineForm, AddWordlistForm, ExternalToolForm, InterestingLookupForm, NotificationForm, ProxyForm, HackeroneForm, ReportForm
from scanEngine.models import EngineType, Wordlist, InstalledExternalTool, InterestingLookupModel, Notification, Hackerone, Proxy, VulnerabilityReportSetting
from dashboard.models import OpenAiAPIKey, NetlasAPIKey, OllamaSettings
from reNgine.definitions import PERM_MODIFY_SCAN_CONFIGURATIONS, PERM_MODIFY_SCAN_REPORT, PERM_MODIFY_WORDLISTS, PERM_MODIFY_INTERESTING_LOOKUP, PERM_MODIFY_SYSTEM_CONFIGURATIONS, FOUR_OH_FOUR_URL
from reNgine.settings import RENGINE_WORDLISTS, RENGINE_HOME, RENGINE_TOOL_GITHUB_PATH
from pathlib import Path
import requests

def index(request):
    engine_type = EngineType.objects.order_by('engine_name').all()
    context = {
        'engine_ul_show': 'show',
        'engine_li': 'active',
        'scan_engine_nav_active': 'active',
        'engine_type': engine_type,
    }
    return render(request, 'scanEngine/index.html', context)

def clean_quotes(data):
    if isinstance(data, dict):
        return {key: clean_quotes(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [clean_quotes(item) for item in data]
    elif isinstance(data, str):
        return data.replace('"', '')
    return data

@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def add_engine(request):
    form = AddEngineForm()

    # load default yaml config
    with open(RENGINE_HOME + '/config/default_yaml_config.yaml', 'r', encoding='utf-8') as yaml_file:
        default_config = yaml_file.read()

    if request.method == "POST":
        form = AddEngineForm(request.POST)
        if form.is_valid():
            cleaned_data = {key: clean_quotes(value) for key, value in form.cleaned_data.items()}
            for key, value in cleaned_data.items():
                setattr(form.instance, key, value) 
            form.instance.save()
            messages.add_message(
                request,
                messages.INFO,
                'Scan Engine Added successfully')
            return http.HttpResponseRedirect(reverse('scan_engine_index'))
    else:
        # fill form with default yaml config
        form = AddEngineForm(initial={'yaml_configuration': default_config})

    context = {
        'scan_engine_nav_active': 'active',
        'form': form
    }
    return render(request, 'scanEngine/add_engine.html', context)

@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def delete_engine(request, id):
    obj = get_object_or_404(EngineType, id=id)
    if request.method == "POST":
        obj.delete()
        responseData = {'status': 'true'}
        messages.add_message(
            request,
            messages.INFO,
            'Engine successfully deleted!')
    else:
        responseData = {'status': 'false'}
        messages.add_message(
            request,
            messages.ERROR,
            'Oops! Engine could not be deleted!')
    return http.JsonResponse(responseData)

@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def update_engine(request, id):
    engine = get_object_or_404(EngineType, id=id)
    form = UpdateEngineForm(
        initial={
            'yaml_configuration': engine.yaml_configuration,
            'engine_name': engine.engine_name
    })
    if request.method == "POST":
        form = UpdateEngineForm(request.POST, instance=engine)
        if form.is_valid():
            cleaned_data = {key: clean_quotes(value) for key, value in form.cleaned_data.items()}
            for key, value in cleaned_data.items():
                setattr(form.instance, key, value) 
            form.instance.save()
            messages.add_message(
                request,
                messages.INFO,
                'Engine edited successfully')
            return http.HttpResponseRedirect(reverse('scan_engine_index'))
    context = {
        'scan_engine_nav_active': 'active',
        'form': form
    }
    return render(request, 'scanEngine/update_engine.html', context)

@has_permission_decorator(PERM_MODIFY_WORDLISTS, redirect_url=FOUR_OH_FOUR_URL)
def wordlist_list(request):
    wordlists = Wordlist.objects.all().order_by('id')
    context = {
            'scan_engine_nav_active': 'active',
            'wordlist_li': 'active',
            'wordlists': wordlists}
    return render(request, 'scanEngine/wordlist/index.html', context)

@has_permission_decorator(PERM_MODIFY_WORDLISTS, redirect_url=FOUR_OH_FOUR_URL)
def add_wordlist(request):
    context = {'scan_engine_nav_active': 'active', 'wordlist_li': 'active'}
    form = AddWordlistForm(request.POST or None, request.FILES or None)
    if request.method == "POST":
        if form.is_valid() and 'upload_file' in request.FILES:
            txt_file = request.FILES['upload_file']
            if txt_file.content_type == 'text/plain':
                wordlist_content = txt_file.read().decode('UTF-8', "ignore")
                wordlist_file = open(
                    Path(RENGINE_WORDLISTS) / f"{form.cleaned_data['short_name']}.txt",
                    'w',
                    encoding='utf-8',
                )
                wordlist_file.write(wordlist_content)
                Wordlist.objects.create(
                    name=form.cleaned_data['name'],
                    short_name=form.cleaned_data['short_name'],
                    count=wordlist_content.count('\n'))
                messages.add_message(
                    request,
                    messages.INFO,
                    'Wordlist ' + form.cleaned_data['name'] +
                    ' added successfully')
                return http.HttpResponseRedirect(reverse('wordlist_list'))
    context['form'] = form
    return render(request, 'scanEngine/wordlist/add.html', context)

@has_permission_decorator(PERM_MODIFY_WORDLISTS, redirect_url=FOUR_OH_FOUR_URL)
def delete_wordlist(request, id):
    obj = get_object_or_404(Wordlist, id=id)
    if request.method == "POST":
        obj.delete()
        try:
            os.remove(Path(RENGINE_WORDLISTS) / f'{obj.short_name}.txt')
            responseData = {'status': True}
        except Exception as e:
            responseData = {'status': False}
        messages.add_message(
            request,
            messages.INFO,
            'Wordlist successfully deleted!')
    else:
        responseData = {'status': 'false'}
        messages.add_message(
            request,
            messages.ERROR,
            'Oops! Wordlist could not be deleted!')
    return http.JsonResponse(responseData)

@has_permission_decorator(PERM_MODIFY_INTERESTING_LOOKUP, redirect_url=FOUR_OH_FOUR_URL)
def interesting_lookup(request):
    lookup_keywords = InterestingLookupModel.objects.filter(custom_type=True).order_by('-id').first()
    form = InterestingLookupForm(instance=lookup_keywords)

    if not lookup_keywords:
        form.initial_checkbox()

    if request.method == "POST":
        form = InterestingLookupForm(request.POST, instance=lookup_keywords)
        if form.is_valid():
            form.save()
            messages.info(request, 'Lookup Keywords updated successfully')
            return http.HttpResponseRedirect(reverse('interesting_lookup'))

    context = {
        'scan_engine_nav_active': 'active',
        'interesting_lookup_li': 'active',
        'engine_ul_show': 'show',
        'form': form,
        'interesting_lookup_found': bool(lookup_keywords),
        'default_lookup': InterestingLookupModel.objects.filter(id=1)
    }
    return render(request, 'scanEngine/lookup.html', context)

@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def tool_specific_settings(request):
    context = {}
    # check for incoming form requests
    if request.method == "POST":
        handle_post_request(request)
        return http.HttpResponseRedirect(reverse('tool_settings'))

    context = {
        'settings_nav_active': 'active',
        'tool_settings_li': 'active',
        'settings_ul_show': 'show',
        'gf_patterns': get_gf_patterns(request),
        'nuclei_templates': list(glob.glob(str(Path.home() / "nuclei-templates" / "*.yaml")))
    }
    return render(request, 'scanEngine/settings/tool.html', context)

def handle_post_request(request):
    handlers = {
        'gfFileUpload': handle_gf_upload,
        'nucleiFileUpload': handle_nuclei_upload,
        'nuclei_config_text_area': lambda r: update_config(r, 'nuclei', 'Nuclei'),
        'subfinder_config_text_area': lambda r: update_config(r, 'subfinder', 'Subfinder'),
        'naabu_config_text_area': lambda r: update_config(r, 'naabu', 'Naabu'),
        'amass_config_text_area': lambda r: update_config(r, 'amass', 'Amass', 'config', '.ini'),
        'theHarvester_config_text_area': lambda r: update_config(r, 'theHarvester', 'theHarvester', 'api-keys', '.yaml'),
        'gau_config_text_area': lambda r: update_config(r, 'gau', 'GAU', 'config', '.toml'),
    }
    for key, handler in handlers.items():
        if key in request.FILES or key in request.POST:
            handler(request)
            break

def handle_gf_upload(request):
    handle_file_upload(request, 'gfFileUpload', '.gf', 'json', 'GF Pattern')

def handle_nuclei_upload(request):
    handle_file_upload(request, 'nucleiFileUpload', 'nuclei-templates', 'yaml', 'Nuclei Pattern')

def handle_file_upload(request, file_key, directory, expected_extension, pattern_name):
    uploaded_file = request.FILES[file_key]
    file_extension = uploaded_file.name.split('.')[-1]
    if file_extension != expected_extension:
        messages.error(request, f'Invalid {pattern_name}, upload only *.{expected_extension} extension')
    else:
        filename = re.sub(r'[\\/*?:"<>|]', "", uploaded_file.name)
        file_path = Path.home() / directory / filename
        with open(file_path, "w", encoding='utf-8') as file:
            file.write(uploaded_file.read().decode("utf-8"))
        messages.info(request, f'{pattern_name} {uploaded_file.name[:4]} successfully uploaded')

def update_config(request, tool_name, display_name, file_name='config', file_extension='.yaml'):
    config_path = Path.home() / '.config' / tool_name / f'{file_name}{file_extension}'
    with open(config_path, "w", encoding='utf-8') as fhandle:
        fhandle.write(request.POST.get(f'{tool_name}_config_text_area'))
    messages.info(request, f'{display_name} config updated!')

def get_gf_patterns(request):
    try:
        gf_result = run_gf_list.delay().get(timeout=30)
        if gf_result['status']:
            return sorted(gf_result['output'])
        messages.error(request, f"Error fetching GF patterns: {gf_result['message']}")
    except Exception as e:
        messages.error(request, f"Error fetching GF patterns: {str(e)}")
    return []

@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def rengine_settings(request):
    total, used, _ = shutil.disk_usage("/")
    total_gb = total // (2**30)
    used_gb = used // (2**30)

    context = {
        'total': total_gb,
        'used': used_gb,
        'free': total_gb - used_gb,
        'consumed_percent': int(100 * float(used) / float(total)),
        'settings_nav_active': 'active',
        'rengine_settings_li': 'active',
        'settings_ul_show': 'show'
    }

    return render(request, 'scanEngine/settings/rengine.html', context)

@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def notification_settings(request):
    notification = Notification.objects.first()
    form = NotificationForm(instance=notification)

    if request.method == "POST":
        form = NotificationForm(request.POST, instance=notification)
        if form.is_valid():
            form.save()
            for service in [send_slack_message, send_lark_message, send_telegram_message]:
                service('*reNgine*\nCongratulations! your notification services are working.')
            send_discord_message('**reNgine**\nCongratulations! your notification services are working.')
            messages.info(request, 'Notification Settings updated successfully and test message was sent.')
            return http.HttpResponseRedirect(reverse('notification_settings'))
    
    context = {
        'form': form,
        'settings_nav_active': 'active',
        'notification_settings_li': 'active',
        'settings_ul_show': 'show'
    }
    return render(request, 'scanEngine/settings/notification.html', context)

@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def proxy_settings(request):
    proxy = Proxy.objects.first()
    form = ProxyForm(instance=proxy)

    if request.method == "POST":
        form = ProxyForm(request.POST, instance=proxy)
        if form.is_valid():
            form.save()
            messages.info(request, 'Proxies updated.')
            return http.HttpResponseRedirect(reverse('proxy_settings'))

    context = {
        'form': form,
        'settings_nav_active': 'active',
        'proxy_settings_li': 'active',
        'settings_ul_show': 'show'
    }
    return render(request, 'scanEngine/settings/proxy.html', context)

@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def test_hackerone(request):
    if request.method == "POST":
        body = json.loads(request.body)
        response = requests.get(
            'https://api.hackerone.com/v1/hackers/payments/balance',
            auth=(body['username'], body['api_key']),
            headers={'Accept': 'application/json'}
        )
        return http.JsonResponse({"status": response.status_code})
    return http.JsonResponse({"status": 401})

@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def hackerone_settings(request):
    hackerone = Hackerone.objects.first()
    form = HackeroneForm(instance=hackerone)

    if request.method == "POST":
        form = HackeroneForm(request.POST, instance=hackerone)
        if form.is_valid():
            form.save()
            messages.info(request, 'Hackerone Settings updated.')
            return http.HttpResponseRedirect(reverse('hackerone_settings'))

    context = {
        'form': form,
        'settings_nav_active': 'active',
        'hackerone_settings_li': 'active',
        'settings_ul_show': 'show'
    }
    return render(request, 'scanEngine/settings/hackerone.html', context)

@has_permission_decorator(PERM_MODIFY_SCAN_REPORT, redirect_url=FOUR_OH_FOUR_URL)
def report_settings(request):
    primary_color = '#FFB74D'
    secondary_color = '#212121'

    if report := VulnerabilityReportSetting.objects.first():
        form = ReportForm(instance=report)
        primary_color = report.primary_color
        secondary_color = report.secondary_color
    else:
        form = ReportForm()
        form.set_initial()

    if request.method == "POST":
        form = ReportForm(request.POST, instance=report) if report else ReportForm(request.POST)
        if form.is_valid():
            form.save()
            messages.info(request, 'Report Settings updated.')
            return http.HttpResponseRedirect(reverse('report_settings'))

    context = {
        'form': form,
        'settings_nav_active': 'active',
        'report_settings_li': 'active',
        'settings_ul_show': 'show',
        'primary_color': primary_color,
        'secondary_color': secondary_color
    }
    return render(request, 'scanEngine/settings/report.html', context)

@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def tool_arsenal_section(request):
    return render(request, 'scanEngine/settings/tool_arsenal.html', {
        'installed_tools': InstalledExternalTool.objects.all().order_by('id')
    })

@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def api_vault_delete(request):
    response = {"status": "error"}
    if request.method == "POST":
        handler = {"key_openai": OpenAiAPIKey, "key_netlas": NetlasAPIKey}
        response["deleted"] = []
        for key in json.loads(request.body.decode("utf-8"))["keys"]:
            try:
                handler[key].objects.first().delete()
                response["deleted"].append(key)
            except KeyError:
                # Ignore the KeyError if the key does not exist
                pass
        response["status"] = "OK"
    else:
        response["message"] = "Method not allowed"
    return http.JsonResponse(response)

def llm_toolkit_section(request):
    all_models = DEFAULT_GPT_MODELS.copy()
    response = requests.get(f'{OLLAMA_INSTANCE}/api/tags')
    if response.status_code == 200:
        ollama_models = response.json().get('models', [])
        date_format = "%Y-%m-%dT%H:%M:%S"
        all_models.extend([{**model, 
            'modified_at': datetime.strptime(model['modified_at'].split('.')[0], date_format),
            'is_local': True,
        } for model in ollama_models])

    selected_model = OllamaSettings.objects.first()
    selected_model_name = selected_model.selected_model if selected_model else 'gpt-3.5-turbo'

    for model in all_models:
        if model['name'] == selected_model_name:
            model['selected'] = True

    context = {
        'installed_models': all_models,
        'openai_key_error': not get_open_ai_key() and 'gpt' in selected_model_name
    }
    return render(request, 'scanEngine/settings/llm_toolkit.html', context)

@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def api_vault(request):
    if request.method == "POST":
        if (key_openai := request.POST.get('key_openai')) and len(key_openai) > 0:
            if openai_api_key := OpenAiAPIKey.objects.first():
                openai_api_key.key = key_openai
                openai_api_key.save()
            else:
                OpenAiAPIKey.objects.create(key=key_openai)

        if (key_netlas := request.POST.get('key_netlas')) and len(key_netlas) > 0:
            if netlas_api_key := NetlasAPIKey.objects.first():
                netlas_api_key.key = key_netlas
                netlas_api_key.save()
            else:
                NetlasAPIKey.objects.create(key=key_netlas)

    # FIXME: This should be better handled via forms, formviews & formsets
    context = {"apiKeys": [
        {
            "recommended": True,
            "optional": True,
            "experimental": True,
            "name": "OpenAI",
            "text": "OpenAI keys will be used to generate vulnerability description, remediation, impact and vulnerability report writing using ChatGPT.",
            "hasKey": OpenAiAPIKey.objects.first() is not None
        },
        {
            "name": "Netlas",
            "text": "Netlas keys will be used to get whois information and other OSINT data.",
            "optional": True,
            "hasKey": NetlasAPIKey.objects.first() is not None
        }
    ]}
    return render(request, 'scanEngine/settings/api.html', context)

@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def add_tool(request):
    form = ExternalToolForm()
    if request.method == "POST":
        form = ExternalToolForm(request.POST)
        if form.is_valid():
            # add tool
            install_command = form.data['install_command']
            github_clone_path = None

            # Only modify install_command if it contains 'git clone'
            if 'git clone' in install_command:
                project_name = install_command.split('/')[-1]
                install_command = f'{install_command} {RENGINE_TOOL_GITHUB_PATH}/{project_name} && pip install -r {RENGINE_TOOL_GITHUB_PATH}/{project_name}/requirements.txt'
                github_clone_path = f'{RENGINE_TOOL_GITHUB_PATH}/{project_name}'

            run_command(install_command)
            run_command.apply_async(args=(install_command,))
            saved_form = form.save()

            if github_clone_path:
                tool = InstalledExternalTool.objects.get(id=saved_form.pk)
                tool.github_clone_path = github_clone_path
                tool.save()

            messages.add_message(
                request,
                messages.INFO,
                'External Tool Successfully Added!')
            return http.HttpResponseRedirect(reverse('tool_arsenal'))
    context = {
        'settings_nav_active': 'active',
        'form': form
    }
    return render(request, 'scanEngine/settings/add_tool.html', context)

@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def modify_tool_in_arsenal(request, id):
    external_tool = get_object_or_404(InstalledExternalTool, id=id)
    form = ExternalToolForm()
    if request.method == "POST":
        form = ExternalToolForm(request.POST, instance=external_tool)
        if form.is_valid():
            form.save()
            messages.add_message(
                request,
                messages.INFO,
                'Tool modified successfully')
            return http.HttpResponseRedirect(reverse('tool_arsenal'))
    else:
        form.set_value(external_tool)
    context = {
            'scan_engine_nav_active':
            'active', 'form': form}
    return render(request, 'scanEngine/settings/update_tool.html', context)
