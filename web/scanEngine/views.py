import json
from pathlib import Path
import shutil

from django import http
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.db.models import CharField, F, Func, Q, Value
from django.db.models.functions import Coalesce, Lower
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
import requests
from rolepermissions.decorators import has_permission_decorator

from api.views import LLMModelsManager
from dashboard.models import NetlasAPIKey, OpenAiAPIKey
from reNgine.core.path import safe_unlink
from reNgine.definitions import (
    FOUR_OH_FOUR_URL,
    PERM_MODIFY_INTERESTING_LOOKUP,
    PERM_MODIFY_SCAN_CONFIGURATIONS,
    PERM_MODIFY_SCAN_REPORT,
    PERM_MODIFY_SYSTEM_CONFIGURATIONS,
    PERM_MODIFY_WORDLISTS,
)
from reNgine.settings import (
    RENGINE_GF_PATTERNS_DIR,
    RENGINE_HOME,
    RENGINE_NUCLEI_TEMPLATES_DIR,
    RENGINE_WORDLISTS,
)
from reNgine.utilities.error import get_safe_user_message
from reNgine.utilities.logger import get_module_logger
from reNgine.utilities.notification import (
    send_discord_message,
    send_lark_message,
    send_slack_message,
    send_telegram_message,
)
from reNgine.validators import validate_short_name as validate_wordlist_short_name
from scanEngine.forms import (
    AddEngineForm,
    AddWordlistForm,
    HackeroneForm,
    InterestingLookupForm,
    NotificationForm,
    ProxyForm,
    ReportForm,
    SecatorProfileForm,
    SecatorScanForm,
    SecatorWorkerForm,
    SecatorWorkflowForm,
    UpdateEngineForm,
)
from scanEngine.models import (
    EngineType,
    Hackerone,
    InterestingLookupModel,
    Notification,
    Proxy,
    SecatorProfile,
    SecatorScan,
    SecatorTask,
    SecatorWorker,
    SecatorWorkflow,
    VulnerabilityReportSetting,
    Wordlist,
)
from scanEngine.services.worker_ssh import get_public_key_content
from scanEngine.tool_assets import list_asset_files, save_uploaded_assets
from scanEngine.wordlists import (
    is_txt_filename as _wordlist_is_txt_filename,
)
from scanEngine.wordlists import (
    save_one as _wordlist_save_one,
)
from scanEngine.wordlists import (
    short_name_from_stem as _wordlist_short_name_from_stem,
)
from startScan.models import ScanHistory


PREFIX_SCAN_ENGINE_VIEWS = "[SCAN_ENGINE_VIEWS]"
logger = get_module_logger(__name__)


def index(request):
    # Get engines based on scan type - filter out legacy engines
    # Legacy engines are kept only for retrocompatibility of old scans
    engine_type = EngineType.objects.filter(is_legacy=False).order_by("engine_name")
    context = {
        "engine_ul_show": "show",
        "engine_li": "active",
        "scan_engine_nav_active": "active",
        "engine_type": engine_type,
    }
    return render(request, "scanEngine/index.html", context)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def add_engine(request):
    form = AddEngineForm()

    # load default yaml config
    with open(f"{RENGINE_HOME}/config/default_yaml_config.yaml", "r", encoding="utf-8") as yaml_file:
        default_config = yaml_file.read()

    if request.method == "POST":
        form = AddEngineForm(request.POST)
        if form.is_valid():
            for key, value in form.cleaned_data.items():
                setattr(form.instance, key, value)
            form.instance.save()
            messages.add_message(request, messages.INFO, "Scan Engine Added successfully")
            return http.HttpResponseRedirect(reverse("scan_engine_index"))
    else:
        # fill form with default yaml config
        form = AddEngineForm(initial={"yaml_configuration": default_config})

    context = {"scan_engine_nav_active": "active", "form": form}
    return render(request, "scanEngine/add_engine.html", context)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def duplicate_engine(request, id):
    """Duplicate an existing scan engine with unique name generation"""
    original_engine = get_object_or_404(EngineType, id=id)

    # Generate unique name by checking existing engines
    base_name = original_engine.engine_name
    new_name = f"{base_name} (Copy)"
    counter = 1

    # Check if name already exists and increment counter if needed
    while EngineType.objects.filter(engine_name=new_name).exists():
        counter += 1
        new_name = f"{base_name} (Copy {counter})"

    # Create a copy of the engine with unique name
    duplicated_engine = EngineType(
        engine_name=new_name,
        yaml_configuration=original_engine.yaml_configuration,
        default_engine=False,  # Duplicated engines are always custom
        scan_type=original_engine.scan_type,
    )
    duplicated_engine.save()

    messages.add_message(
        request, messages.SUCCESS, f"Engine '{original_engine.engine_name}' successfully duplicated as '{new_name}'!"
    )
    return http.HttpResponseRedirect(reverse("scan_engine_index"))


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def delete_engine(request, id):
    obj = get_object_or_404(EngineType, id=id)
    if request.method == "POST":
        obj.delete()
        response_data = {"status": True}
        messages.add_message(request, messages.INFO, "Engine successfully deleted!")
    else:
        response_data = {"status": False}
        messages.add_message(request, messages.ERROR, "Oops! Engine could not be deleted!")
    return http.JsonResponse(response_data)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def update_engine(request, id):
    engine = get_object_or_404(EngineType, id=id)
    form = UpdateEngineForm(
        initial={
            "yaml_configuration": engine.yaml_configuration,
            "engine_name": engine.engine_name,
            "scan_type": engine.get_scan_type_from_yaml(),
        }
    )
    if request.method == "POST":
        form = UpdateEngineForm(request.POST, instance=engine)
        if form.is_valid():
            for key, value in form.cleaned_data.items():
                setattr(form.instance, key, value)
            form.save()
            messages.add_message(request, messages.INFO, "Engine edited successfully")
            return http.HttpResponseRedirect(reverse("scan_engine_index"))
    context = {"scan_engine_nav_active": "active", "form": form}
    return render(request, "scanEngine/update_engine.html", context)


def _wordlist_add_page_context(form) -> dict:
    """Build context dict for the add wordlist template (reduces duplication on validation errors)."""
    return {"scan_engine_nav_active": "active", "wordlist_li": "active", "form": form}


@has_permission_decorator(PERM_MODIFY_WORDLISTS, redirect_url=FOUR_OH_FOUR_URL)
def wordlist_list(request):
    wordlists = Wordlist.objects.all().order_by("id")
    context = {"scan_engine_nav_active": "active", "wordlist_li": "active", "wordlists": wordlists}
    return render(request, "scanEngine/wordlist/index.html", context)


@has_permission_decorator(PERM_MODIFY_WORDLISTS, redirect_url=FOUR_OH_FOUR_URL)
def add_wordlist(request):
    form = AddWordlistForm(request.POST or None, request.FILES or None)
    if request.method != "POST":
        return render(request, "scanEngine/wordlist/add.html", _wordlist_add_page_context(form))

    files = request.FILES.getlist("upload_file") if request.FILES else []
    if not form.is_valid():
        if not files:
            form.add_error("upload_file", "Please select at least one .txt file.")
        return render(request, "scanEngine/wordlist/add.html", _wordlist_add_page_context(form))

    if not files:
        form.add_error("upload_file", "Please select at least one .txt file.")
        return render(request, "scanEngine/wordlist/add.html", _wordlist_add_page_context(form))

    if len(files) == 1:
        if not _wordlist_is_txt_filename(files[0].name):
            form.add_error("upload_file", "Only .txt files are allowed.")
            return render(request, "scanEngine/wordlist/add.html", _wordlist_add_page_context(form))
        stem = Path(files[0].name).stem
        name = (form.cleaned_data.get("name") or stem).strip()
        short_name_raw = form.cleaned_data.get("short_name") or _wordlist_short_name_from_stem(stem)
        if not name or not short_name_raw:
            if not name:
                form.add_error("name", "Name is required for single-file upload.")
            if not short_name_raw:
                form.add_error("short_name", "Short name is required for single-file upload.")
            return render(request, "scanEngine/wordlist/add.html", _wordlist_add_page_context(form))
        try:
            validate_wordlist_short_name(short_name_raw)
        except ValidationError:
            form.add_error("short_name", "Invalid short name.")
            return render(request, "scanEngine/wordlist/add.html", _wordlist_add_page_context(form))
        short_name, err = _wordlist_save_one(name, short_name_raw, uploaded_file=files[0])
        if err:
            if err == "empty":
                form.add_error("upload_file", "Uploaded wordlist is empty.")
            elif err == "max_retries":
                form.add_error("short_name", "Could not find a unique short name after many attempts.")
            elif err == "encoding":
                form.add_error("upload_file", "Uploaded wordlist must be UTF-8 encoded.")
            else:
                form.add_error("upload_file", "Failed to save wordlist file.")
            return render(request, "scanEngine/wordlist/add.html", _wordlist_add_page_context(form))
        messages.info(
            request,
            f"Wordlist '{name}' added successfully (short_name: {short_name}).",
        )
        return http.HttpResponseRedirect(reverse("wordlist_list"))

    empty_filenames = []
    saved_count = 0
    for uploaded_file in files:
        if not _wordlist_is_txt_filename(uploaded_file.name):
            messages.error(request, f"Skipped {uploaded_file.name}: only .txt files are allowed.")
            continue
        stem = Path(uploaded_file.name).stem
        base_short = _wordlist_short_name_from_stem(stem)
        try:
            validate_wordlist_short_name(base_short)
        except ValidationError:
            messages.error(request, f"Skipped {uploaded_file.name}: invalid short name derived from filename.")
            continue
        name = stem
        short_name, err = _wordlist_save_one(name, base_short, uploaded_file=uploaded_file)
        if err == "empty":
            empty_filenames.append(getattr(uploaded_file, "name", "uploaded file"))
            continue
        if err:
            if err == "max_retries":
                msg = "could not find a unique short name after many attempts."
            elif err == "encoding":
                msg = "file must be UTF-8 encoded."
            else:
                msg = "failed to read or save file."
            messages.error(request, f"Skipped {uploaded_file.name}: {msg}")
            continue
        saved_count += 1
        messages.info(
            request,
            f"Wordlist '{name}' added successfully (short_name: {short_name}).",
        )
    if len(empty_filenames) == len(files):
        messages.error(
            request,
            "All selected files are empty. Please upload at least one non-empty .txt file.",
        )
        return render(request, "scanEngine/wordlist/add.html", _wordlist_add_page_context(form))
    if saved_count == 0:
        form.add_error(
            "upload_file",
            "No wordlist was created. Fix the errors above and try again.",
        )
        return render(request, "scanEngine/wordlist/add.html", _wordlist_add_page_context(form))
    if empty_filenames:
        messages.warning(
            request,
            "The following files were skipped because they are empty: " + ", ".join(empty_filenames),
        )
    return http.HttpResponseRedirect(reverse("wordlist_list"))


@has_permission_decorator(PERM_MODIFY_WORDLISTS, redirect_url=FOUR_OH_FOUR_URL)
def delete_wordlist(request, id):
    obj = get_object_or_404(Wordlist, id=id)
    if request.method == "POST":
        short_name = obj.short_name
        obj.delete()
        file_path = Path(RENGINE_WORDLISTS) / f"{short_name}.txt"
        # safe_unlink no-ops when path is missing or invalid (returns "not_found"); safe for cleanup.
        result = safe_unlink(RENGINE_WORDLISTS, file_path)
        if result not in ("removed", "not_found"):
            logger.log_line(
                PREFIX_SCAN_ENGINE_VIEWS,
                "WORDLIST_CLEANUP",
                "Wordlist file cleanup returned %s for %s" % (result, file_path),
                level="warning",
            )
        response_data = {"status": result in ("removed", "not_found")}
        messages.add_message(request, messages.INFO, "Wordlist successfully deleted!")
    else:
        response_data = {"status": False}
        messages.add_message(request, messages.ERROR, "Oops! Wordlist could not be deleted!")
    return http.JsonResponse(response_data)


@has_permission_decorator(PERM_MODIFY_INTERESTING_LOOKUP, redirect_url=FOUR_OH_FOUR_URL)
def interesting_lookup(request):
    lookup_keywords = InterestingLookupModel.objects.filter(custom_type=True).order_by("-id").first()
    form = InterestingLookupForm(instance=lookup_keywords)

    if not lookup_keywords:
        form.initial_checkbox()

    if request.method == "POST":
        form = InterestingLookupForm(request.POST, instance=lookup_keywords)
        if form.is_valid():
            form.save()
            messages.info(request, "Lookup Keywords updated successfully")
            return http.HttpResponseRedirect(reverse("interesting_lookup"))

    context = {
        "scan_engine_nav_active": "active",
        "interesting_lookup_li": "active",
        "engine_ul_show": "show",
        "form": form,
        "interesting_lookup_found": bool(lookup_keywords),
        "default_lookup": InterestingLookupModel.objects.filter(id=1),
    }
    return render(request, "scanEngine/lookup.html", context)


def _tool_settings_context(request):
    from django.urls import reverse as django_reverse

    return {
        "settings_nav_active": "active",
        "tool_settings_li": "active",
        "settings_ul_show": "show",
        "gf_patterns": list_asset_files(RENGINE_GF_PATTERNS_DIR, "json"),
        "nuclei_templates": list_asset_files(RENGINE_NUCLEI_TEMPLATES_DIR, "yaml"),
        "get_file_contents_url": django_reverse("api:getFileContents"),
    }


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def tool_specific_settings(request):
    if request.method == "POST":
        if "gfFileUpload" in request.FILES:
            result = save_uploaded_assets(
                request,
                "gfFileUpload",
                RENGINE_GF_PATTERNS_DIR,
                "json",
                "GF Pattern",
            )
        elif "nucleiFileUpload" in request.FILES:
            result = save_uploaded_assets(
                request,
                "nucleiFileUpload",
                RENGINE_NUCLEI_TEMPLATES_DIR,
                "yaml",
                "Nuclei template",
            )
        else:
            result = {"saved": 0, "errors": 0}
        if result.get("saved", 0) == 0 and result.get("errors", 0) > 0:
            messages.error(
                request,
                "No files were uploaded. Fix the errors above and try again.",
            )
            return render(request, "scanEngine/settings/tool.html", _tool_settings_context(request))
        return http.HttpResponseRedirect(reverse("tool_settings"))

    return render(request, "scanEngine/settings/tool.html", _tool_settings_context(request))


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def rengine_settings(request):
    total, used, _ = shutil.disk_usage("/")
    total_gb = total // (2**30)
    used_gb = used // (2**30)

    context = {
        "total": total_gb,
        "used": used_gb,
        "free": total_gb - used_gb,
        "consumed_percent": int(100 * float(used) / float(total)),
        "settings_nav_active": "active",
        "rengine_settings_li": "active",
        "settings_ul_show": "show",
    }

    return render(request, "scanEngine/settings/rengine.html", context)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def notification_settings(request):
    notification = Notification.objects.first()
    form = NotificationForm(instance=notification)

    if request.method == "POST":
        form = NotificationForm(request.POST, instance=notification)
        if form.is_valid():
            form.save()
            for service in [send_slack_message, send_lark_message, send_telegram_message]:
                service("*reNgine*\nCongratulations! your notification services are working.")
            send_discord_message("**reNgine**\nCongratulations! your notification services are working.")
            messages.info(request, "Notification Settings updated successfully and test message was sent.")
            return http.HttpResponseRedirect(reverse("notification_settings"))

    context = {
        "form": form,
        "settings_nav_active": "active",
        "notification_settings_li": "active",
        "settings_ul_show": "show",
    }
    return render(request, "scanEngine/settings/notification.html", context)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def proxy_settings(request):
    proxy = Proxy.objects.first()
    form = ProxyForm(instance=proxy)

    if request.method == "POST":
        form = ProxyForm(request.POST, instance=proxy)
        if form.is_valid():
            form.save()
            messages.info(request, "Proxies updated.")
            return http.HttpResponseRedirect(reverse("proxy_settings"))

    context = {"form": form, "settings_nav_active": "active", "proxy_settings_li": "active", "settings_ul_show": "show"}
    return render(request, "scanEngine/settings/proxy.html", context)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def test_hackerone(request):
    if request.method != "POST":
        return http.JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        body = json.loads(request.body or "{}")
    except (TypeError, ValueError):
        return http.JsonResponse(
            {"error": "Invalid JSON payload"},
            status=400,
        )

    username = body.get("username")
    api_key = body.get("api_key")
    if not username or not api_key:
        return http.JsonResponse(
            {"error": "Missing required credentials: 'username' and 'api_key'"},
            status=400,
        )

    try:
        response = requests.get(
            "https://api.hackerone.com/v1/hackers/payments/balance",
            auth=(username, api_key),
            headers={"Accept": "application/json"},
            timeout=10,
        )
    except requests.exceptions.Timeout as exc:
        return http.JsonResponse(
            {
                "error": "Timeout while connecting to HackerOne API",
                "detail": get_safe_user_message(exc, logger),
            },
            status=504,
        )
    except requests.exceptions.RequestException as exc:
        return http.JsonResponse(
            {
                "error": "Failed to reach HackerOne API",
                "detail": get_safe_user_message(exc, logger),
            },
            status=502,
        )

    data = {"status": response.status_code, "ok": response.ok}
    try:
        data["response"] = response.json()
    except ValueError:
        data["response_text"] = response.text[:500]

    return http.JsonResponse(data, status=response.status_code)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def hackerone_settings(request):
    hackerone = Hackerone.objects.first()
    form = HackeroneForm(instance=hackerone)

    if request.method == "POST":
        form = HackeroneForm(request.POST, instance=hackerone)
        if form.is_valid():
            form.save()
            messages.info(request, "Hackerone Settings updated.")
            return http.HttpResponseRedirect(reverse("hackerone_settings"))

    context = {
        "form": form,
        "settings_nav_active": "active",
        "hackerone_settings_li": "active",
        "settings_ul_show": "show",
    }
    return render(request, "scanEngine/settings/hackerone.html", context)


@has_permission_decorator(PERM_MODIFY_SCAN_REPORT, redirect_url=FOUR_OH_FOUR_URL)
def report_settings(request):
    primary_color = "#FFB74D"
    secondary_color = "#212121"

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
            messages.info(request, "Report Settings updated.")
            return http.HttpResponseRedirect(reverse("report_settings"))

    context = {
        "form": form,
        "settings_nav_active": "active",
        "report_settings_li": "active",
        "settings_ul_show": "show",
        "primary_color": primary_color,
        "secondary_color": secondary_color,
    }
    return render(request, "scanEngine/settings/report.html", context)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def api_vault_delete(request):
    response = {"status": "error", "deleted": [], "skipped": []}
    if request.method != "POST":
        response["message"] = "Method not allowed"
        return http.JsonResponse(response, status=405)

    try:
        body = json.loads(request.body.decode("utf-8"))
        keys = body.get("keys", [])
    except (TypeError, ValueError, KeyError):
        response["message"] = "Invalid JSON or missing 'keys' array"
        return http.JsonResponse(response, status=400)

    if not isinstance(keys, list):
        response["message"] = "'keys' must be an array"
        return http.JsonResponse(response, status=400)

    handler = {"key_openai": OpenAiAPIKey, "key_netlas": NetlasAPIKey}
    for key in keys:
        if key not in handler:
            response["skipped"].append({"key": key, "reason": "unknown key type"})
            continue
        obj = handler[key].objects.first()
        if obj is None:
            response["skipped"].append({"key": key, "reason": "no record to delete"})
            continue
        obj.delete()
        response["deleted"].append(key)

    response["status"] = "OK"
    return http.JsonResponse(response)


def llm_toolkit_section(request):
    try:
        # Direct call to the API
        api_response = LLMModelsManager().get(request)
        data = api_response.data

        context = {"installed_models": data["models"], "openai_key_error": data["openai_key_error"]}
        return render(request, "scanEngine/settings/llm_toolkit.html", context)
    except Exception as e:
        messages.error(request, get_safe_user_message(e, logger))
        return render(request, "scanEngine/settings/llm_toolkit.html", {"installed_models": []})


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def api_vault(request):
    if request.method == "POST":
        if (key_openai := request.POST.get("key_openai")) and len(key_openai) > 0:
            if openai_api_key := OpenAiAPIKey.objects.first():
                openai_api_key.key = key_openai
                openai_api_key.save()
            else:
                OpenAiAPIKey.objects.create(key=key_openai)

        if (key_netlas := request.POST.get("key_netlas")) and len(key_netlas) > 0:
            if netlas_api_key := NetlasAPIKey.objects.first():
                netlas_api_key.key = key_netlas
                netlas_api_key.save()
            else:
                NetlasAPIKey.objects.create(key=key_netlas)

    # FIXME: This should be better handled via forms, formviews & formsets
    context = {
        "apiKeys": [
            {
                "recommended": True,
                "optional": True,
                "experimental": True,
                "name": "OpenAI",
                "text": "OpenAI keys will be used to generate vulnerability description, remediation, impact and vulnerability report writing using LLM.",
                "hasKey": OpenAiAPIKey.objects.first() is not None,
            },
            {
                "name": "Netlas",
                "text": "Netlas keys will be used to get whois information and other OSINT data.",
                "optional": True,
                "hasKey": NetlasAPIKey.objects.first() is not None,
            },
        ]
    }
    return render(request, "scanEngine/settings/api.html", context)


# =============================================================================
# WORKFLOW INTEGRATION VIEWS
# =============================================================================


def _get_filtered_workflows(filter_type, search_query):
    """Return SecatorWorkflow queryset filtered by filter_type and search_query."""
    valid_filter_types = {"all", "builtin", "custom"}
    if filter_type not in valid_filter_types:
        filter_type = "all"
    workflows = SecatorWorkflow.objects.all()
    if filter_type == "builtin":
        workflows = workflows.filter(workflow_type="builtin")
    elif filter_type == "custom":
        workflows = workflows.filter(workflow_type="custom")
    if search_query:
        cleaned_query = search_query.strip()
        lower_cleaned_query = cleaned_query.lower()
        workflows = workflows.annotate(
            tags_search=Lower(
                Coalesce(
                    Func(F("tags"), Value(" "), function="array_to_string", output_field=CharField()),
                    Value(""),
                )
            )
        ).filter(
            Q(name__icontains=cleaned_query)
            | Q(description__icontains=cleaned_query)
            | Q(display_name__icontains=cleaned_query)
            | Q(tags_search__icontains=lower_cleaned_query)
        )
    return workflows.order_by("workflow_type", "name")


@login_required
def secator_workflows(request):
    """List workflows with filtering."""
    filter_type = request.GET.get("filter", "all")
    search_query = request.GET.get("search", "")
    workflows = _get_filtered_workflows(filter_type, search_query)
    context = {
        "workflows": workflows,
        "filter_type": filter_type,
        "search_query": search_query,
    }
    return render(request, "scanEngine/workflows.html", context)


@login_required
def secator_workflows_table_partial(request):
    """Return only the workflows table body HTML for dynamic search/filter (no page reload)."""
    filter_type = request.GET.get("filter", "all")
    search_query = request.GET.get("search", "")
    workflows = _get_filtered_workflows(filter_type, search_query)
    return render(request, "scanEngine/_workflows_table_body.html", {"workflows": workflows})


def _get_filtered_tasks(filter_type, search_query):
    """Return SecatorTask queryset filtered by filter_type and search_query."""
    tasks = SecatorTask.objects.all()
    if filter_type == "builtin":
        tasks = tasks.filter(is_builtin=True)
    elif filter_type == "custom":
        tasks = tasks.filter(is_builtin=False)
    elif filter_type == "active":
        tasks = tasks.filter(is_active=True)
    elif filter_type == "inactive":
        tasks = tasks.filter(is_active=False)
    if search_query:
        tasks = tasks.filter(
            Q(name__icontains=search_query)
            | Q(task_type__icontains=search_query)
            | Q(description__icontains=search_query)
            | Q(tags__contains=[search_query.strip()])
        )
    return tasks.order_by("name")


@login_required
def secator_tasks(request):
    """List tasks with filtering."""
    filter_type = request.GET.get("filter", "all")
    search_query = request.GET.get("search", "")
    tasks = _get_filtered_tasks(filter_type, search_query)
    context = {
        "tasks": tasks,
        "filter_type": filter_type,
        "search_query": search_query,
    }
    return render(request, "scanEngine/tasks.html", context)


@login_required
def secator_tasks_table_partial(request):
    """Return only the tasks table body HTML for dynamic search/filter (no page reload)."""
    filter_type = request.GET.get("filter", "all")
    search_query = request.GET.get("search", "")
    tasks = _get_filtered_tasks(filter_type, search_query)
    return render(request, "scanEngine/_tasks_table_body.html", {"tasks": tasks})


@login_required
def secator_task_detail(request, task_id):
    """Detail view for a task."""
    task = get_object_or_404(SecatorTask, id=task_id)

    # Note: No longer showing related scans since we removed the M2M relationship
    # Scans now use YAML configuration instead of direct task relationships

    context = {
        "task": task,
    }

    return render(request, "scanEngine/task_detail.html", context)


@login_required
def secator_scans(request):
    """List scan configurations with filtering."""
    filter_type = request.GET.get("filter", "all")
    search_query = request.GET.get("search", "")

    scans = SecatorScan.objects.all()

    # Apply filters
    if filter_type == "builtin":
        scans = scans.filter(scan_config_type="builtin")
    elif filter_type == "custom":
        scans = scans.filter(scan_config_type="custom")

    # Apply search
    if search_query:
        scans = scans.filter(Q(name__icontains=search_query) | Q(description__icontains=search_query))

    scans = scans.order_by("scan_config_type", "name")

    # Pagination
    paginator = Paginator(scans, 20)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    context = {
        "page_obj": page_obj,
        "filter_type": filter_type,
        "search_query": search_query,
    }

    return render(request, "scanEngine/scans.html", context)


@login_required
def secator_workflow_detail(request, workflow_id):
    """Detail view for a workflow."""
    workflow = get_object_or_404(SecatorWorkflow, id=workflow_id)
    related_scans = list(SecatorScan.objects.filter_by_workflow(workflow))

    context = {
        "workflow": workflow,
        "related_scans": related_scans,
    }

    return render(request, "scanEngine/workflow_detail.html", context)


@login_required
def secator_scan_detail(request, scan_id):
    """Detail view for a scan configuration."""
    scan = get_object_or_404(SecatorScan, id=scan_id)

    # TODO: Filter by this SecatorScan when ScanHistory is linked to SecatorScan.
    # Until then, recent_scans is unfiltered (last 10 non-legacy scans globally).
    recent_scans = (
        ScanHistory.objects.filter(
            scan_type__isnull=False,
            is_legacy_scan=False,
        )
        .select_related("domain__project")
        .prefetch_related("secatorrunner_set__worker")
        .order_by("-start_scan_date")[:10]
    )

    context = {
        "scan": scan,
        "recent_scans": recent_scans,
        "recent_scans_unfiltered": True,
    }

    return render(request, "scanEngine/scan_detail.html", context)


@login_required
def add_workflow(request):
    """Create a new workflow."""
    form = SecatorWorkflowForm()

    if request.method == "POST":
        form = SecatorWorkflowForm(request.POST)
        if form.is_valid():
            for key, value in form.cleaned_data.items():
                setattr(form.instance, key, value)
            # Custom workflows are not built-in
            form.instance.workflow_type = "custom"
            form.instance.save()
            messages.add_message(request, messages.INFO, "Workflow added successfully")
            return http.HttpResponseRedirect(reverse("workflows"))

    context = {"scan_engine_nav_active": "active", "form": form}
    return render(request, "scanEngine/add_workflow.html", context)


@login_required
def update_workflow(request, workflow_id):
    """Update an existing workflow."""
    workflow = get_object_or_404(SecatorWorkflow, id=workflow_id)

    # Check if workflow can be modified (early check for better UX)
    if not workflow.can_modify():
        messages.add_message(request, messages.ERROR, "Built-in workflows cannot be modified!")
        return http.HttpResponseRedirect(reverse("workflows"))

    form = SecatorWorkflowForm(
        initial={
            "name": workflow.name,
            "alias": workflow.alias,
            "description": workflow.description,
            "tags": workflow.tags or [],
            "scan_type": workflow.scan_type,
            "yaml_configuration": workflow.yaml_configuration,
            "is_active": workflow.is_active,
        }
    )

    if request.method == "POST":
        form = SecatorWorkflowForm(request.POST, instance=workflow)
        if form.is_valid():
            try:
                for key, value in form.cleaned_data.items():
                    setattr(form.instance, key, value)
                form.save()
                messages.add_message(request, messages.INFO, "Workflow updated successfully")
                return http.HttpResponseRedirect(reverse("workflows"))
            except PermissionError as e:
                messages.add_message(request, messages.ERROR, get_safe_user_message(e, logger))
                return http.HttpResponseRedirect(reverse("workflows"))

    context = {"scan_engine_nav_active": "active", "form": form, "workflow": workflow}
    return render(request, "scanEngine/update_workflow.html", context)


@login_required
def delete_workflow(request, workflow_id):
    """Delete a workflow."""
    workflow = get_object_or_404(SecatorWorkflow, id=workflow_id)

    # Check if workflow can be deleted (early check for better UX)
    if not workflow.can_delete():
        response_data = {"status": False, "message": "Built-in workflows cannot be deleted!"}
        return http.JsonResponse(response_data)

    if request.method == "POST":
        try:
            workflow_name = workflow.name
            workflow.delete()
            response_data = {"status": True}
            messages.add_message(request, messages.INFO, f"Workflow '{workflow_name}' successfully deleted!")
        except PermissionError as e:
            response_data = {"status": False, "message": get_safe_user_message(e, logger)}
        except Exception:
            response_data = {"status": False, "message": "Oops! Workflow could not be deleted!"}
            messages.add_message(request, messages.ERROR, "Oops! Workflow could not be deleted!")
    else:
        response_data = {"status": False, "message": "Invalid request method"}
        messages.add_message(request, messages.ERROR, "Oops! Workflow could not be deleted!")
    return http.JsonResponse(response_data)


@login_required
def add_scan(request):
    """Create a new scan configuration."""
    form = SecatorScanForm()

    if request.method == "POST":
        form = SecatorScanForm(request.POST)
        if form.is_valid():
            for key, value in form.cleaned_data.items():
                setattr(form.instance, key, value)
            # Custom scan configurations are not built-in
            form.instance.scan_config_type = "custom"
            form.instance.save()
            messages.add_message(request, messages.INFO, "Scan configuration added successfully")
            return http.HttpResponseRedirect(reverse("scans"))

    context = {"scan_engine_nav_active": "active", "form": form}
    return render(request, "scanEngine/add_scan.html", context)


@login_required
def update_scan(request, scan_id):
    """Update an existing scan configuration."""
    scan = get_object_or_404(SecatorScan, id=scan_id)

    # Check if scan can be modified (early check for better UX)
    if not scan.can_modify():
        messages.add_message(request, messages.ERROR, "Built-in scan configurations cannot be modified!")
        return http.HttpResponseRedirect(reverse("scans"))

    form = SecatorScanForm(
        initial={
            "name": scan.name,
            "description": scan.description,
            "scan_type": scan.scan_type,
            "scan_config_type": scan.scan_config_type,
            "yaml_configuration": scan.yaml_configuration,
            "is_default": scan.is_default,
            "is_active": scan.is_active,
        }
    )

    if request.method == "POST":
        form = SecatorScanForm(request.POST, instance=scan)
        if form.is_valid():
            try:
                for key, value in form.cleaned_data.items():
                    setattr(form.instance, key, value)
                form.save()
                messages.add_message(request, messages.INFO, "Scan configuration updated successfully")
                return http.HttpResponseRedirect(reverse("scans"))
            except PermissionError as e:
                messages.add_message(request, messages.ERROR, get_safe_user_message(e, logger))
                return http.HttpResponseRedirect(reverse("scans"))

    context = {"scan_engine_nav_active": "active", "form": form, "scan": scan}
    return render(request, "scanEngine/update_scan.html", context)


@login_required
def delete_scan(request, scan_id):
    """Delete a scan configuration."""
    scan = get_object_or_404(SecatorScan, id=scan_id)

    # Check if scan can be deleted (early check for better UX)
    if not scan.can_delete():
        response_data = {"status": False, "message": "Built-in scan configurations cannot be deleted!"}
        return http.JsonResponse(response_data)

    if request.method == "POST":
        try:
            scan_name = scan.name
            scan.delete()
            response_data = {"status": True}
            messages.add_message(request, messages.INFO, f"Scan configuration '{scan_name}' successfully deleted!")
        except PermissionError as e:
            response_data = {"status": False, "message": str(e)}
        except Exception:
            response_data = {"status": False, "message": "Oops! Scan configuration could not be deleted!"}
            messages.add_message(request, messages.ERROR, "Oops! Scan configuration could not be deleted!")
    else:
        response_data = {"status": False, "message": "Invalid request method"}
        messages.add_message(request, messages.ERROR, "Oops! Scan configuration could not be deleted!")
    return http.JsonResponse(response_data)


# =============================================================================
# PROFILE INTEGRATION VIEWS
# =============================================================================


@login_required
def secator_profiles(request):
    """List profiles with filtering."""
    filter_type = request.GET.get("filter", "all")
    search_query = request.GET.get("search", "")

    # Validate filter_type
    valid_filter_types = {"all", "builtin", "custom"}
    if filter_type not in valid_filter_types:
        filter_type = "all"

    profiles = SecatorProfile.objects.all()

    # Apply filters
    if filter_type == "builtin":
        profiles = profiles.filter(profile_type="builtin")
    elif filter_type == "custom":
        profiles = profiles.filter(profile_type="custom")

    # Apply search
    if search_query:
        profiles = profiles.filter(Q(name__icontains=search_query) | Q(description__icontains=search_query))

    profiles = profiles.order_by("profile_type", "category", "name")

    # Pagination
    paginator = Paginator(profiles, 20)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    context = {
        "page_obj": page_obj,
        "filter_type": filter_type,
        "search_query": search_query,
    }

    return render(request, "scanEngine/profiles.html", context)


@login_required
def secator_profile_detail(request, profile_id):
    """Detail view for a profile."""
    profile = get_object_or_404(SecatorProfile, id=profile_id)

    context = {
        "profile": profile,
    }

    return render(request, "scanEngine/profile_detail.html", context)


@login_required
def add_profile(request):
    """Create a new profile."""
    form = SecatorProfileForm()

    if request.method == "POST":
        form = SecatorProfileForm(request.POST)
        if form.is_valid():
            try:
                for key, value in form.cleaned_data.items():
                    setattr(form.instance, key, value)
                # Custom profiles are not built-in
                form.instance.profile_type = "custom"
                form.instance.save()

                messages.add_message(request, messages.INFO, "Profile added successfully")
                return http.HttpResponseRedirect(reverse("profiles"))
            except Exception as e:
                logger.log_line(
                    PREFIX_SCAN_ENGINE_VIEWS,
                    "PROFILE",
                    "Error saving profile: %s" % (e,),
                    level="error",
                    exc_info=True,
                )
                messages.add_message(request, messages.ERROR, get_safe_user_message(e, logger))
                context = {"scan_engine_nav_active": "active", "form": form}
                return render(request, "scanEngine/add_profile.html", context)

    context = {"scan_engine_nav_active": "active", "form": form}
    return render(request, "scanEngine/add_profile.html", context)


@login_required
def update_profile(request, profile_id):
    """Update an existing profile."""
    profile = get_object_or_404(SecatorProfile, id=profile_id)

    # Check if profile can be modified (early check for better UX)
    if not profile.can_modify():
        messages.add_message(request, messages.ERROR, "Built-in profiles cannot be modified!")
        return http.HttpResponseRedirect(reverse("profiles"))

    form = SecatorProfileForm(
        initial={
            "name": profile.name,
            "category": profile.category,
            "description": profile.description,
            "enforce": profile.enforce,
            "opts": profile.opts,
            "is_active": profile.is_active,
        }
    )

    if request.method == "POST":
        form = SecatorProfileForm(request.POST, instance=profile)
        if form.is_valid():
            try:
                for key, value in form.cleaned_data.items():
                    setattr(form.instance, key, value)
                form.save()

                messages.add_message(request, messages.INFO, "Profile updated successfully")
                return http.HttpResponseRedirect(reverse("profiles"))
            except PermissionError as e:
                messages.add_message(request, messages.ERROR, get_safe_user_message(e, logger))
                return http.HttpResponseRedirect(reverse("profiles"))
            except Exception as e:
                logger.log_line(
                    PREFIX_SCAN_ENGINE_VIEWS,
                    "PROFILE",
                    "Error updating profile: %s" % (e,),
                    level="error",
                    exc_info=True,
                )
                messages.add_message(request, messages.ERROR, get_safe_user_message(e, logger))
                context = {"scan_engine_nav_active": "active", "form": form, "profile": profile}
                return render(request, "scanEngine/update_profile.html", context)

    context = {"scan_engine_nav_active": "active", "form": form, "profile": profile}
    return render(request, "scanEngine/update_profile.html", context)


@login_required
def set_default_profile(request, profile_id):
    """Set a profile as default for its category."""
    profile = get_object_or_404(SecatorProfile, id=profile_id)

    if request.method == "POST":
        try:
            # Unset other defaults in the same category
            SecatorProfile.objects.filter(category=profile.category, is_default=True).exclude(pk=profile.pk).update(
                is_default=False
            )

            # Set this profile as default
            if profile.profile_type == "builtin":
                # Use bypass_builtin_constraints for builtin profiles
                profile.is_default = True
                profile.save(bypass_builtin_constraints=True)
            else:
                profile.is_default = True
                profile.save()

            response_data = {
                "status": True,
                "message": f"Profile '{profile.name}' set as default for {profile.get_category_display()} category",
            }
            messages.add_message(request, messages.INFO, response_data["message"])
        except Exception as e:
            response_data = {"status": False, "message": get_safe_user_message(e, logger)}
            messages.add_message(request, messages.ERROR, response_data["message"])
    else:
        response_data = {"status": False, "message": "Invalid request method"}
    return http.JsonResponse(response_data)


@login_required
def delete_profile(request, profile_id):
    """Delete a profile."""
    profile = get_object_or_404(SecatorProfile, id=profile_id)

    # Check if profile can be deleted (early check for better UX)
    if not profile.can_delete():
        response_data = {"status": False, "message": "Built-in profiles cannot be deleted!"}
        return http.JsonResponse(response_data)

    if request.method == "POST":
        try:
            profile_name = profile.name
            profile.delete()
            response_data = {"status": True}
            messages.add_message(request, messages.INFO, f"Profile '{profile_name}' successfully deleted!")
        except PermissionError as e:
            response_data = {"status": False, "message": get_safe_user_message(e, logger)}
        except Exception:
            response_data = {"status": False, "message": "Oops! Profile could not be deleted!"}
            messages.add_message(request, messages.ERROR, "Oops! Profile could not be deleted!")
    else:
        response_data = {"status": False, "message": "Invalid request method"}
        messages.add_message(request, messages.ERROR, "Oops! Profile could not be deleted!")
    return http.JsonResponse(response_data)


@login_required
def worker_list(request):
    """List Secator workers; actions (deploy, refresh, disable, delete) are performed via API from JS."""
    workers = SecatorWorker.objects.all().order_by("name").prefetch_related("secatorrunner_set")
    context = {
        "scan_engine_nav_active": "active",
        "workers": workers,
    }
    return render(request, "scanEngine/workers.html", context)


@login_required
def worker_add(request):
    """Add a new Secator worker (form); optional deploy after create."""
    form = SecatorWorkerForm()
    if request.method == "POST":
        form = SecatorWorkerForm(request.POST)
        if form.is_valid():
            worker = form.save()
            messages.add_message(request, messages.SUCCESS, f"Worker '{worker.name}' created.")
            return http.HttpResponseRedirect(reverse("worker_list"))
    context = {
        "scan_engine_nav_active": "active",
        "form": form,
        "ssh_public_key_content": get_public_key_content() or "",
    }
    return render(request, "scanEngine/worker_form.html", context)


@login_required
def worker_update(request, worker_id):
    """Update a Secator worker; password left unchanged if empty."""
    worker = get_object_or_404(SecatorWorker, id=worker_id)
    form = SecatorWorkerForm(instance=worker)
    if request.method == "POST":
        worker.refresh_from_db()
        old_api = (
            worker.api_access_type,
            worker.api_tunnel_port,
            (worker.api_url or "").strip(),
        )
        form = SecatorWorkerForm(request.POST, instance=worker)
        if form.is_valid():
            if not form.cleaned_data.get("ssh_password_encrypted") and getattr(worker, "ssh_password_encrypted", None):
                form.cleaned_data["ssh_password_encrypted"] = worker.ssh_password_encrypted
            form.save()
            worker.refresh_from_db()
            new_api = (
                worker.api_access_type,
                worker.api_tunnel_port,
                (worker.api_url or "").strip(),
            )
            if old_api != new_api:
                from scanEngine.services.worker_deploy import push_env_and_restart_worker

                ok, err = push_env_and_restart_worker(worker)
                if ok:
                    messages.add_message(
                        request,
                        messages.SUCCESS,
                        f"Worker '{worker.name}' updated; .env pushed and container restarted.",
                    )
                else:
                    messages.add_message(
                        request,
                        messages.WARNING,
                        f"Worker '{worker.name}' updated but remote update failed: {err}",
                    )
            else:
                messages.add_message(request, messages.SUCCESS, f"Worker '{worker.name}' updated.")
            return http.HttpResponseRedirect(reverse("worker_list"))
    worker_check_connection_url = reverse(
        "api:secator-workers-check-connection",
        kwargs={"pk": worker.id},
    )
    worker_install_public_key_url = reverse(
        "api:secator-workers-install-public-key",
        kwargs={"pk": worker.id},
    )
    context = {
        "scan_engine_nav_active": "active",
        "form": form,
        "worker": worker,
        "ssh_public_key_content": get_public_key_content() or "",
        "worker_check_connection_url": worker_check_connection_url,
        "worker_install_public_key_url": worker_install_public_key_url,
    }
    return render(request, "scanEngine/worker_form.html", context)
