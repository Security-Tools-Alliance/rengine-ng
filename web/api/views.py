from collections import defaultdict
from datetime import datetime
import json
from pathlib import Path
import re
import threading

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.conf import settings as django_settings
from django.core.cache import cache
from django.db.models import Case, CharField, Count, F, IntegerField, OuterRef, Prefetch, Q, Subquery, Value, When
from django.db.models.functions import Coalesce
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.template.defaultfilters import slugify
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
import requests
from rest_framework import viewsets
from rest_framework.decorators import action, api_view
from rest_framework.exceptions import PermissionDenied
from rest_framework.parsers import JSONParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.status import (
    HTTP_200_OK,
    HTTP_202_ACCEPTED,
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_410_GONE,
)
from rest_framework.views import APIView
import validators

from api.helpers.datatables import (
    DATATABLE_COLUMN_MAP_DIRECTORY,
    DATATABLE_COLUMN_MAP_ENDPOINT,
    DATATABLE_COLUMN_MAP_ENDPOINT_CHANGES,
    DATATABLE_COLUMN_MAP_EXPLOIT,
    DATATABLE_COLUMN_MAP_INTERESTING_ENDPOINT,
    DATATABLE_COLUMN_MAP_INTERESTING_SUBDOMAIN,
    DATATABLE_COLUMN_MAP_IPS,
    DATATABLE_COLUMN_MAP_ORGANIZATIONS,
    DATATABLE_COLUMN_MAP_S3_BUCKETS,
    DATATABLE_COLUMN_MAP_SCAN_ENGINE,
    DATATABLE_COLUMN_MAP_SCAN_HISTORY,
    DATATABLE_COLUMN_MAP_SCHEDULED_SCANS,
    DATATABLE_COLUMN_MAP_SCOPES,
    DATATABLE_COLUMN_MAP_SECRET,
    DATATABLE_COLUMN_MAP_SUBDOMAIN,
    DATATABLE_COLUMN_MAP_SUBDOMAIN_CHANGES,
    DATATABLE_COLUMN_MAP_SUBSCAN_HISTORY,
    DATATABLE_COLUMN_MAP_TARGETS,
    DATATABLE_COLUMN_MAP_VULNERABILITY,
    DATATABLE_COLUMN_MAP_WORDLIST,
    DATATABLE_NULLS_LAST_FIELDS,
    FILTER_PARAM_BUCKET_NAME,
    FILTER_PARAM_ENGINE_NAME,
    FILTER_PARAM_HAS_SCAN,
    FILTER_PARAM_HTTP_STATUS,
    FILTER_PARAM_NAME,
    FILTER_PARAM_ORGANIZATION,
    FILTER_PARAM_PAGE_TITLE,
    FILTER_PARAM_SCAN_ENGINE,
    FILTER_PARAM_SCOPE,
    FILTER_PARAM_SEVERITY,
    FILTER_PARAM_SOURCE,
    FILTER_PARAM_STATUS,
    FILTER_PARAM_SUBDOMAIN,
    FILTER_PARAM_TARGET,
    apply_datatables_order,
    apply_filter_list_in,
    apply_filter_list_in_by_param,
    apply_filter_scan_status,
    apply_filter_scope_type,
    apply_filter_task_status,
    get_datatable_filter_warnings,
    get_datatables_column_search_value,
    get_datatables_order_column,
    get_nuclei_severity_codes_for_labels,
    get_request_filter_list,
    get_scan_status_filter_labels,
    get_task_status_filter_labels,
)
from api.helpers.query import build_subdomain_datatable_queryset, get_ip_subdomain_data, get_scan_status_querysets
from api.mixins import (
    DatatableListMixin,
    DatatablePaginationMixin,
    build_datatables_serverside_response,
)
from api.pagination import parse_limit_from_request, parse_pagination_params
from api.permissions import HasAPIKeyOrIsAuthenticated
from api.scan_file import get_scan_file_urls
from api.secator_api_base import SecatorAPIBase
from dashboard.models import OllamaSettings, OpenAiAPIKey, Project, SearchHistory
from recon_note.models import TodoNote

# NOTE: Legacy tasks removed (query_ip_history, query_reverse_whois, query_whois,
# run_cmseek, run_command, run_gf_list, run_wafw00f) - functionality now in Secator
from reNgine.core.data import get_data_from_post_request, get_request_worker_id, safe_int_cast
from reNgine.core.exceptions import FindingOutOfScopeError
from reNgine.definitions import (
    ABORTED_TASK,
    GENERIC_USER_ERROR_MESSAGE,
    MAX_ASSET_PREVIEW_BYTES,
    NUCLEI_SEVERITY_MAP,
    RUNNING_TASK,
)
from reNgine.llm.config import DEFAULT_GPT_MODELS, MODEL_REQUIREMENTS, OLLAMA_INSTANCE, RECOMMENDED_MODELS
from reNgine.llm.llm import LLMAttackSuggestionGenerator
from reNgine.llm.utils import convert_markdown_to_html, get_default_llm_model, is_empty_attack_surface

# NOTE: Legacy task functions removed - functionality now in Secator
from reNgine.secator.selected_targets import resolve_selected_targets
from reNgine.secator.service import run_per_task_secator_scans, start_secator_scan
from reNgine.secator.services.target_builder_service import TargetBuilderService
from reNgine.secator.synthetic_id import synthetic_id_skipped_scope
from reNgine.settings import (
    RENGINE_GF_PATTERNS_DIR,
    RENGINE_NUCLEI_TEMPLATES_DIR,
)
from reNgine.tasks import (
    llm_vulnerability_report,
    send_hackerone_report,
)
from reNgine.utilities.db import count_subquery, count_subquery_related
from reNgine.utilities.domain import get_domain_by_id
from reNgine.utilities.endpoint import get_interesting_endpoints
from reNgine.utilities.error import get_safe_user_message
from reNgine.utilities.external import get_open_ai_key
from reNgine.utilities.logger import get_module_logger
from reNgine.utilities.lookup import get_lookup_keywords
from reNgine.utilities.subdomain import get_interesting_subdomains
from reNgine.utilities.url import is_apex_domain
from scanEngine.models import (
    EngineType,
    SecatorScan,
    SecatorTask,
    SecatorWorker,
    SecatorWorkflow,
    Wordlist,
)
from scanEngine.services.worker_config_sync import sync_all_custom_configs_to_worker
from scanEngine.services.worker_deploy import (
    deploy_worker,
    refresh_worker_status,
    restart_worker_container,
    teardown_worker_remote,
)
from scanEngine.services.worker_ssh import (
    get_public_key_content,
    get_ssh_client,
    install_public_key_on_host,
    run_remote_command,
    validate_deploy_path,
)
from startScan.models import (
    Certificate,
    Command,
    DirectoryFile,
    DirectoryScan,
    Domain,
    Dork,
    Email,
    Employee,
    EndPoint,
    Exploit,
    IpAddress,
    LLMVulnerabilityReport,
    MetaFinderDocument,
    Port,
    S3Bucket,
    ScanActivity,
    ScanHistory,
    ScanSchedule,
    Secret,
    Subdomain,
    SubScan,
    Technology,
    Vulnerability,
)
from startScan.secator.runner_sync import is_all_runners_completed, sync_runner_with_scan_history
from startScan.secator.sync_service import submit_sync as secator_submit_sync
from targetApp.constants import TARGET_TYPE_HOST
from targetApp.models import Organization, Scope, Target

from .serializers import (
    CertificateSerializer,
    CommandSerializer,
    DirectoryFileSerializer,
    DirectoryScanSerializer,
    DomainSerializer,
    DorkCountSerializer,
    DorkSerializer,
    EmailSerializer,
    EmployeeSerializer,
    EndPointChangesSerializer,
    EndpointOnlyURLsSerializer,
    EndpointSerializer,
    EngineSerializer,
    EngineTypeDatatableSerializer,
    ExploitSerializer,
    InterestingEndPointSerializer,
    InterestingSubdomainSerializer,
    IpSerializer,
    IpSubdomainSerializer,
    MetafinderDocumentSerializer,
    MetafinderUserSerializer,
    OnlySubdomainNameSerializer,
    OrganizationDatatableSerializer,
    OrganizationSerializer,
    OrganizationTargetsSerializer,
    ProjectSerializer,
    ReconNoteSerializer,
    S3BucketDatatableSerializer,
    ScanActivitySerializer,
    ScanHistoryDatatableSerializer,
    ScanHistorySerializer,
    ScanScheduleDatatableSerializer,
    ScopeDatatableSerializer,
    SearchHistorySerializer,
    SecatorWorkerCreateUpdateSerializer,
    SecatorWorkerDetailSerializer,
    SecatorWorkerListSerializer,
    SecretSerializer,
    SubdomainChangesSerializer,
    SubdomainSerializer,
    SubScanDatatableSerializer,
    SubScanResultSerializer,
    SubScanSerializer,
    TargetSerializer,
    TechnologyCountSerializer,
    VisualiseDataSerializer,
    VulnerabilitySerializer,
    WordlistDatatableSerializer,
)


PREFIX_API = "[API]"
logger = get_module_logger(__name__)


class AdvancedSearchMixin:
    """
    Mixin providing advanced search functionality with operators.

    Supports operators: = (equals), > (greater than), < (less than), ! (exclude)
    Supports logic: & (AND), | (OR)

    Subclasses must define search_config attribute with the following structure:
    {
        'general_fields': [Q(...), Q(...), ...],  # Q objects for general text search
        'special_fields': {
            'field_name': 'model__field__lookup',  # Mapping for special searches
            ...
        },
        'numeric_fields': {
            'field_name': 'model__field',  # Fields supporting >, < operators
            ...
        },
        'boolean_fields': {
            'field_name': ('model__field', true_value, false_value),
            ...
        },
        'custom_handlers': {
            'field_name': callable,  # Custom handler function(queryset, operator, value)
            ...
        }
    }
    """

    search_config = None

    def apply_advanced_search(self, queryset, search_value):
        """Apply advanced search with support for complex queries using & and | operators."""
        if not search_value:
            return queryset

        has_operators = any(op in search_value for op in ["=", "&", "|", ">", "<", "!"])

        if not has_operators:
            return self.general_lookup(queryset, search_value)

        if "&" in search_value:
            complex_query = search_value.split("&")
            for query in complex_query:
                if query.strip():
                    queryset = queryset & self.special_lookup(queryset, query.strip())
        elif "|" in search_value:
            new_queryset = queryset.none()
            complex_query = search_value.split("|")
            for query in complex_query:
                if query.strip():
                    new_queryset = self.special_lookup(queryset, query.strip()) | new_queryset
            queryset = new_queryset
        else:
            queryset = self.special_lookup(queryset, search_value)

        return queryset

    def general_lookup(self, queryset, search_value):
        """Perform general search across configured fields."""
        if not self.search_config or "general_fields" not in self.search_config:
            return queryset

        combined_q = Q()
        for field_q in self.search_config["general_fields"]:
            if callable(field_q):
                combined_q |= field_q(search_value)
            else:
                combined_q |= field_q

        return queryset.filter(combined_q) if combined_q else queryset

    def special_lookup(self, queryset, search_value):
        """Perform special search with operators (=, >, <, !)."""
        if not self.search_config:
            return queryset

        operator = None
        for op in ["=", ">", "<", "!"]:
            if op in search_value:
                operator = op
                break

        if not operator:
            return queryset

        search_param = search_value.split(operator)
        if len(search_param) != 2:
            return queryset

        lookup_title = search_param[0].lower().strip()
        lookup_content = search_param[1].strip()

        special_fields = self.search_config.get("special_fields", {})
        numeric_fields = self.search_config.get("numeric_fields", {})
        boolean_fields = self.search_config.get("boolean_fields", {})
        custom_handlers = self.search_config.get("custom_handlers", {})

        # Check for custom handler first
        if lookup_title in custom_handlers:
            return custom_handlers[lookup_title](queryset, operator, lookup_content)

        # Handle boolean fields
        if lookup_title in boolean_fields:
            field_path, true_val, false_val = boolean_fields[lookup_title]
            if operator == "=":
                bool_value = lookup_content.lower() in ["true", "1", "yes", true_val.lower()]
                return queryset.filter(**{field_path: bool_value})
            elif operator == "!":
                bool_value = lookup_content.lower() in ["true", "1", "yes", true_val.lower()]
                return queryset.exclude(**{field_path: bool_value})

        # Handle numeric comparisons
        if lookup_title in numeric_fields:
            field_path = numeric_fields[lookup_title]
            try:
                int_value = int(lookup_content)
                if operator == "=":
                    return queryset.filter(**{field_path: int_value})
                elif operator == ">":
                    return queryset.filter(**{f"{field_path}__gt": int_value})
                elif operator == "<":
                    return queryset.filter(**{f"{field_path}__lt": int_value})
                elif operator == "!":
                    return queryset.exclude(**{field_path: int_value})
            except (ValueError, TypeError):
                return queryset

        # Handle text field searches
        if lookup_title in special_fields:
            field_path = special_fields[lookup_title]
            if operator == "=":
                return queryset.filter(**{field_path: lookup_content})
            elif operator == "!":
                return queryset.exclude(**{field_path: lookup_content})

        return queryset


class OllamaManager(APIView):
    def clean_channel_name(self, name):
        """Clean channel name to only contain valid characters"""
        return re.sub(r"[^a-zA-Z0-9\-\.]", "-", name)

    def get(self, request):
        model_name = request.query_params.get("model")
        if not model_name:
            return Response({"status": False, "message": "Model name is required"})

        try:
            # Create safe channel name
            channel_name = f"ollama-download-{self.clean_channel_name(model_name)}"
            channel_layer = get_channel_layer()

            def download_task():
                response = None
                session = None
                try:
                    session = requests.Session()

                    # Send initial progress
                    async_to_sync(channel_layer.group_send)(
                        channel_name,
                        {
                            "type": "download_progress",
                            "message": {
                                "status": "downloading",
                                "progress": 0,
                                "total": 100,
                                "message": "Starting download...",
                            },
                        },
                    )

                    response = session.post(
                        f"{OLLAMA_INSTANCE}/api/pull", json={"name": model_name, "stream": True}, stream=True
                    )

                    for line in response.iter_lines():
                        if line:
                            try:
                                data = json.loads(line.decode("utf-8"))
                                logger.log_line(
                                    PREFIX_API,
                                    "OLLAMA",
                                    "Ollama response: %s" % (data,),
                                    level="debug",
                                )

                                if "error" in data:
                                    async_to_sync(channel_layer.group_send)(
                                        channel_name,
                                        {
                                            "type": "download_progress",
                                            "message": {"status": "error", "error": data["error"]},
                                        },
                                    )
                                    break

                                status_data = {
                                    "status": "downloading",
                                    "progress": data.get("completed", 0),
                                    "total": data.get("total", 100),
                                    "message": data.get("status", "Downloading..."),
                                }

                                async_to_sync(channel_layer.group_send)(
                                    channel_name, {"type": "download_progress", "message": status_data}
                                )

                                if data.get("status") == "success":
                                    async_to_sync(channel_layer.group_send)(
                                        channel_name,
                                        {
                                            "type": "download_progress",
                                            "message": {"status": "complete", "message": "Download complete!"},
                                        },
                                    )
                                    break

                            except json.JSONDecodeError as e:
                                logger.log_line(
                                    PREFIX_API,
                                    "OLLAMA",
                                    "JSON decode error: %s" % (e,),
                                    level="error",
                                )
                                async_to_sync(channel_layer.group_send)(
                                    channel_name,
                                    {
                                        "type": "download_progress",
                                        "message": {"status": "error", "error": "Invalid response format"},
                                    },
                                )
                                break

                except Exception as e:
                    logger.log_line(
                        PREFIX_API,
                        "OLLAMA",
                        "Download error: %s" % (e,),
                        level="error",
                    )
                    try:
                        async_to_sync(channel_layer.group_send)(
                            channel_name,
                            {
                                "type": "download_progress",
                                "message": {"status": "error", "error": get_safe_user_message(e, None)},
                            },
                        )
                    except Exception as e2:
                        logger.log_line(
                            PREFIX_API,
                            "OLLAMA",
                            "Error sending error message: %s" % (e2,),
                            level="error",
                        )
                finally:
                    if response:
                        response.close()
                    if session:
                        session.close()

            thread = threading.Thread(target=download_task)
            thread.daemon = True
            thread.start()

            return Response({"status": True, "channel": channel_name, "message": "Download started"})

        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "OLLAMA",
                "Error in OllamaManager: %s" % (e,),
                level="error",
            )
            return Response({"status": False, "error": get_safe_user_message(e, None)}, status=500)


class OllamaDetailManager(APIView):
    def delete(self, request, model_name):
        if not model_name:
            return Response({"status": False, "message": "Model name is required"}, status=400)

        try:
            delete_model_api = f"{OLLAMA_INSTANCE}/api/delete"
            response = requests.delete(delete_model_api, json={"name": model_name})

            # Ollama sends a 200 status code on success
            if response.status_code == 200:
                return Response({"status": True})

            # Try to parse the JSON response if it exists
            try:
                error_data = response.json()
                error_message = error_data.get("error", "Unknown error occurred")
            except ValueError:
                error_message = response.text or "Unknown error occurred"

            return Response({"status": False, "message": error_message}, status=response.status_code)

        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "OLLAMA",
                "Error in OllamaDetailManager DELETE: %s" % (e,),
                level="error",
            )
            return Response({"status": False, "message": "An error occurred while deleting the model."}, status=500)

    def put(self, request, model_name):
        if not model_name:
            return Response({"status": False, "message": "Model name is required"}, status=400)

        try:
            use_ollama = all(model["name"] != model_name for model in DEFAULT_GPT_MODELS)

            OllamaSettings.objects.update_or_create(
                id=1, defaults={"selected_model": model_name, "use_ollama": use_ollama}
            )
            return Response({"status": True, "message": "Model selected successfully"})
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "OLLAMA",
                "Error in OllamaDetailManager PUT: %s" % (e,),
                level="error",
            )
            return Response(
                {"status": False, "message": "An error occurred while updating the model selection."}, status=500
            )


class AvailableOllamaModels(APIView):
    def get(self, request):
        try:
            cache_key = "ollama_available_models"
            if cached_data := cache.get(cache_key):
                return Response(cached_data)

            # Use recommended models from config
            recommended_models = list(RECOMMENDED_MODELS.values())

            # Check installed models
            try:
                response = requests.get(f"{OLLAMA_INSTANCE}/api/tags", timeout=5)
                if response.status_code == 200:
                    installed_models = {model["name"]: model for model in response.json().get("models", [])}

                    # Mark installed models and add their details
                    for model in recommended_models:
                        base_name = model["name"]
                        model["installed_versions"] = [
                            name.replace(f"{base_name}:", "") for name in installed_models if name.startswith(base_name)
                        ]
                        model["installed"] = len(model["installed_versions"]) > 0

                        # Add capabilities from MODEL_REQUIREMENTS if available
                        if base_name in MODEL_REQUIREMENTS:
                            model["capabilities"] = MODEL_REQUIREMENTS[base_name]
                else:
                    logger.log_line(
                        PREFIX_API,
                        "OLLAMA",
                        "Ollama API returned status %s" % (response.status_code,),
                        level="warning",
                    )
                    for model in recommended_models:
                        model["installed"] = False
                        model["installed_versions"] = []
            except requests.exceptions.RequestException as e:
                logger.log_line(
                    PREFIX_API,
                    "OLLAMA",
                    "Error connecting to Ollama API: %s" % (e,),
                    level="error",
                )
                for model in recommended_models:
                    model["installed"] = False
                    model["installed_versions"] = []

            response_data = {"status": True, "models": recommended_models}

            cache.set(cache_key, response_data, 300)
            return Response(response_data)

        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "OLLAMA",
                "Error in AvailableOllamaModels: %s" % (e,),
                level="error",
            )
            return Response({"status": False, "error": get_safe_user_message(e, None)}, status=500)


class LLMAttackSuggestion(APIView):
    def get(self, request):
        req = request
        subdomain_id = safe_int_cast(req.query_params.get("subdomain_id"))
        force_regenerate = req.query_params.get("force_regenerate") == "true"
        check_only = req.query_params.get("check_only") == "true"
        selected_model = req.query_params.get("llm_model")  # Get selected model from request

        if not subdomain_id:
            return Response({"status": False, "error": "Missing GET param Subdomain `subdomain_id`"})

        try:
            subdomain = Subdomain.objects.get(id=subdomain_id)
        except Subdomain.DoesNotExist:
            return Response({"status": False, "error": f"Subdomain not found with id {subdomain_id}"})

        # Return cached result only if not forcing regeneration and not empty
        if subdomain.attack_surface and not force_regenerate and not is_empty_attack_surface(subdomain.attack_surface):
            sanitized_html = subdomain.formatted_attack_surface
            return Response(
                {"status": True, "subdomain_name": subdomain.name, "description": sanitized_html, "cached": True}
            )

        # If check_only, return without generating new analysis
        if check_only:
            return Response({"status": True, "subdomain_name": subdomain.name, "description": None})

        # Generate new analysis
        ip_addrs = subdomain.ip_addresses.prefetch_related("ports").all()
        open_ports = ", ".join(f"{port.number}/{port.service_name}" for ip in ip_addrs for port in ip.ports.all())
        tech_used = ", ".join(tech.name for tech in subdomain.technologies.all())

        input_data = f"""
            Subdomain Name: {subdomain.name}
            Subdomain Page Title: {subdomain.page_title}
            Open Ports: {open_ports}
            HTTP Status: {subdomain.http_status}
            Technologies Used: {tech_used}
            Content type: {subdomain.content_type}
            Web Server: {subdomain.webserver}
            Page Content Length: {subdomain.content_length}
        """

        llm = LLMAttackSuggestionGenerator()
        response = llm.get_attack_suggestion(input_data, selected_model)  # Pass selected model to generator
        response["subdomain_name"] = subdomain.name

        if response.get("status"):
            raw_desc = response.get("description")
            if isinstance(raw_desc, str) and raw_desc.strip():
                # Use the actual selected model name
                markdown_content = f"[LLM:{selected_model}]\n{raw_desc}"
                subdomain.attack_surface = markdown_content
                subdomain.save()
                response["description"] = convert_markdown_to_html(markdown_content)
            else:
                # Do not save empty content
                response["description"] = ""

        return Response(response)

    def delete(self, request):
        subdomain_id = request.query_params.get("subdomain_id")
        if not subdomain_id:
            return Response({"status": False, "error": "Missing subdomain_id parameter"}, status=400)

        try:
            subdomain = Subdomain.objects.get(id=subdomain_id)
            subdomain.attack_surface = None
            subdomain.save()
            return Response({"status": True, "message": "Attack surface analysis deleted successfully"})
        except Subdomain.DoesNotExist:
            return Response({"status": False, "error": f"Subdomain not found with id {subdomain_id}"}, status=404)
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "LLM",
                "Error deleting attack surface analysis: %s" % (e,),
                level="error",
            )
            return Response({"status": False, "error": "An error occurred while deleting the analysis"}, status=500)


class LLMVulnerabilityReportGenerator(APIView):
    def get(self, request):
        req = self.request
        vulnerability_id = safe_int_cast(req.query_params.get("id"))
        if not vulnerability_id:
            return Response({"status": False, "error": "Missing GET param Vulnerability `id`"})
        # Preflight checks for LLM configuration
        # Get default model first - if this fails, log and proceed to task
        try:
            selected_model = get_default_llm_model()
        except Exception as e:
            # If fetching the default model fails, log and proceed to task but keep robustness
            logger.log_line(
                PREFIX_API,
                "LLM",
                "Error fetching default LLM model: %s" % (e,),
                level="error",
            )
            selected_model = None

        try:
            is_gpt = False
            if selected_model:
                gpt_model_names = [model["name"] for model in DEFAULT_GPT_MODELS]
                is_gpt = selected_model in gpt_model_names
        except (KeyError, AttributeError) as e:
            logger.log_line(
                PREFIX_API,
                "LLM",
                "Error determining if selected model is GPT: %s" % (e,),
                level="error",
            )
            is_gpt = False

        openai_key_missing = is_gpt and not OpenAiAPIKey.objects.exists()

        # Detect missing default Ollama selection if Ollama is preferred
        ollama_default_missing = False
        try:
            ollama_settings = OllamaSettings.objects.first()
            if (
                ollama_settings
                and ollama_settings.use_ollama
                and not (ollama_settings.selected_model and ollama_settings.selected_model.strip())
            ):
                ollama_default_missing = True
        except Exception:
            ollama_default_missing = False

        available_ollama_models = []
        ollama_ok = False
        try:
            import requests

            from reNgine.definitions import OLLAMA_INSTANCE

            r = requests.get(f"{OLLAMA_INSTANCE}/api/tags", timeout=3)
            if r.ok:
                data = r.json()
                available_ollama_models = [m.get("name") for m in data.get("models", []) if m.get("name")]
                ollama_ok = len(available_ollama_models) > 0
        except Exception:
            ollama_ok = False

        # If GPT selected without API key, or no default local model selected while Ollama usable
        if openai_key_missing or ollama_default_missing:
            return Response(
                {
                    "status": False,
                    "error_code": "LLM_CONFIG_REQUIRED",
                    "error": "LLM configuration is incomplete.",
                    "is_gpt_selected": is_gpt,
                    "openai_key_missing": openai_key_missing,
                    "ollama_available": ollama_ok,
                    "has_ollama_models": bool(available_ollama_models),
                    "ollama_default_missing": ollama_default_missing,
                },
                status=400,
            )

        force_regenerate = request.query_params.get("force_regenerate") == "true"
        response = llm_vulnerability_report(vulnerability_id, None, force_regenerate)
        return Response(response)

    def delete(self, request):
        req = self.request
        vulnerability_id = safe_int_cast(req.query_params.get("id"))
        if not vulnerability_id:
            return Response({"status": False, "error": "Missing GET param Vulnerability `id`"}, status=400)

        try:
            from urllib.parse import urlparse as _urlparse

            vuln = Vulnerability.objects.get(id=vulnerability_id)
            lookup_url = _urlparse(vuln.http_url)
            title = vuln.name
            path = lookup_url.path

            deleted, _ = LLMVulnerabilityReport.objects.filter(url_path=path, title=title).delete()

            return Response({"status": True, "deleted": deleted})
        except Vulnerability.DoesNotExist:
            return Response(
                {"status": False, "error": f"Vulnerability not found with id {vulnerability_id}"}, status=404
            )
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "LLM",
                "Error deleting LLM vulnerability report: %s" % (e,),
                level="error",
            )
            return Response({"status": False, "error": "An error occurred while deleting the analysis"}, status=500)


class CreateProjectApi(APIView):
    def get(self, request):
        project_name = request.query_params.get("name")
        slug = slugify(project_name)
        insert_date = timezone.now()

        try:
            Project.objects.create(name=project_name, slug=slug, insert_date=insert_date)
            return Response({"status": True, "project_name": project_name})
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "PROJECT",
                "Error in CreateProjectApi: %s" % (e,),
                level="error",
            )
            return Response({"status": False, "message": "Failed to create project."}, status=HTTP_400_BAD_REQUEST)


class QueryInterestingSubdomains(APIView):
    def get(self, request):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        target_or_domain_id = safe_int_cast(req.query_params.get("target_id"))

        if scan_id:
            queryset = get_interesting_subdomains(scan_history=scan_id)
        elif target_or_domain_id:
            queryset = get_interesting_subdomains(target_id=target_or_domain_id)
        else:
            queryset = get_interesting_subdomains()

        queryset = queryset.distinct("name")

        return Response(InterestingSubdomainSerializer(queryset, many=True).data)


class ListTargetsDatatableViewSet(DatatableListMixin, DatatablePaginationMixin, viewsets.ModelViewSet):
    """DataTables list API for targets. Filter params: filter_organization, filter_scope, filter_has_scan. See wiki datatables-api-filters.md."""

    queryset = Target.objects.all()
    serializer_class = TargetSerializer
    datatable_column_map = DATATABLE_COLUMN_MAP_TARGETS

    def get_queryset(self):
        slug = self.request.GET.get("slug", None)
        base_qs = Target.objects.for_project(slug) if slug else self.queryset
        first_scope_name = Scope.objects.filter(targets=OuterRef("pk")).order_by("name").values("name")[:1]
        domain_count_subq = (
            Domain.objects.filter(scan_history__target_id=OuterRef("pk"))
            .values("scan_history__target_id")
            .annotate(c=Count("name", distinct=True))
            .values("c")[:1]
        )
        subdomain_count_subq = (
            Subdomain.objects.filter(scan_history__target_id=OuterRef("pk"))
            .values("scan_history__target_id")
            .annotate(c=Count("name", distinct=True))
            .values("c")[:1]
        )
        endpoint_count_subq = (
            EndPoint.objects.filter(scan_history__target_id=OuterRef("pk"))
            .values("scan_history__target_id")
            .annotate(c=Count("http_url", distinct=True))
            .values("c")[:1]
        )
        vulnerability_count_subq = (
            Vulnerability.objects.filter(scan_history__target_id=OuterRef("pk"))
            .values("scan_history__target_id")
            .annotate(c=Count("id"))
            .values("c")[:1]
        )
        secret_count_subq = (
            Secret.objects.filter(scan_history__target_id=OuterRef("pk"))
            .values("scan_history__target_id")
            .annotate(c=Count("id"))
            .values("c")[:1]
        )
        exploit_count_subq = (
            Exploit.objects.filter(scan_history__target_id=OuterRef("pk"))
            .values("scan_history__target_id")
            .annotate(c=Count("id"))
            .values("c")[:1]
        )
        qs = (
            base_qs.with_last_scan_date()
            .prefetch_related("scopes")
            .annotate(
                domain_count=Coalesce(Subquery(domain_count_subq), Value(0)),
                subdomain_count=Coalesce(Subquery(subdomain_count_subq), Value(0)),
                endpoint_count=Coalesce(Subquery(endpoint_count_subq), Value(0)),
                vulnerability_count=Coalesce(Subquery(vulnerability_count_subq), Value(0)),
                secret_count=Coalesce(Subquery(secret_count_subq), Value(0)),
                exploit_count=Coalesce(Subquery(exploit_count_subq), Value(0)),
                scope_group_name=Coalesce(Subquery(first_scope_name), Value("No scope")),
            )
        )
        return qs

    def filter_queryset(self, qs):
        qs = self.get_queryset()
        search_value = self.request.GET.get("search[value]", None)
        if search_value:
            qs = qs.filter(
                Q(value__icontains=search_value)
                | Q(description__icontains=search_value)
                | Q(organizations__name__icontains=search_value)
            ).distinct()
        # Per-column search values from DataTables (individual column filters).
        # Column map uses "value" for target name; reuse it here.
        name_search = get_datatables_column_search_value(self.request, self.datatable_column_map, "value")
        if name_search:
            qs = qs.filter(value__icontains=name_search)
        qs = apply_filter_list_in_by_param(
            qs, self.request, FILTER_PARAM_ORGANIZATION, "organizations__name__in", distinct=True
        )
        qs = apply_filter_list_in_by_param(qs, self.request, FILTER_PARAM_SCOPE, "scopes__name__in", distinct=True)
        has_scan_values = get_request_filter_list(self.request, FILTER_PARAM_HAS_SCAN)
        has_scan_value = has_scan_values[0] if has_scan_values else None
        if has_scan_value == "scanned":
            qs = qs.filter(last_scan_start_date_annot__isnull=False)
        elif has_scan_value == "never":
            qs = qs.filter(last_scan_start_date_annot__isnull=True)
        return apply_datatables_order(
            qs,
            self.request,
            self.datatable_column_map,
            default_order="-id",
            nulls_last_fields=DATATABLE_NULLS_LAST_FIELDS,
        )


class ListScopesDatatableViewSet(DatatableListMixin, DatatablePaginationMixin, viewsets.GenericViewSet):
    """DataTables list API for scopes, filtered by project slug. Filter params: filter_organization, filter_scope_type. See wiki datatables-api-filters.md."""

    serializer_class = ScopeDatatableSerializer
    datatable_column_map = DATATABLE_COLUMN_MAP_SCOPES

    def get_queryset(self):
        slug = self.request.query_params.get("slug")
        if not slug:
            return Scope.objects.none()
        return (
            Scope.objects.filter(organization__project__slug=slug)
            .select_related("organization")
            .annotate(
                target_count=Count("targets", distinct=True),
                worker_count=Count("workers", distinct=True),
            )
            .order_by("-insert_date")
        )

    def filter_queryset(self, qs):
        search_value = self.request.GET.get("search[value]", None)
        if search_value:
            qs = qs.filter(Q(name__icontains=search_value) | Q(organization__name__icontains=search_value)).distinct()
        name_search = get_datatables_column_search_value(self.request, self.datatable_column_map, "name")
        if name_search:
            qs = qs.filter(name__icontains=name_search)
        organization_search = get_datatables_column_search_value(
            self.request, self.datatable_column_map, "organization__name"
        )
        if organization_search:
            qs = qs.filter(organization__name__icontains=organization_search)
        scope_type_search = get_datatables_column_search_value(self.request, self.datatable_column_map, "scope_type")
        if scope_type_search:
            qs = qs.filter(scope_type__icontains=scope_type_search)
        qs = apply_filter_list_in_by_param(
            qs, self.request, FILTER_PARAM_ORGANIZATION, "organization__name__in", distinct=True
        )
        qs = apply_filter_scope_type(qs, self.request)
        return apply_datatables_order(qs, self.request, self.datatable_column_map, default_order="-insert_date")


class ListOrganizationsDatatableViewSet(DatatableListMixin, DatatablePaginationMixin, viewsets.GenericViewSet):
    """DataTables list API for organizations, filtered by project slug. Filter params: filter_name. See wiki datatables-api-filters.md."""

    serializer_class = OrganizationDatatableSerializer
    datatable_column_map = DATATABLE_COLUMN_MAP_ORGANIZATIONS

    def get_queryset(self):
        slug = self.request.query_params.get("slug")
        if not slug:
            return Organization.objects.none()
        return (
            Organization.objects.filter(project__slug=slug)
            .annotate(
                scope_count=Count("scopes", distinct=True),
                total_targets=Count("targets", distinct=True),
            )
            .order_by("-insert_date")
        )

    def filter_queryset(self, qs):
        search_value = self.request.GET.get("search[value]", None)
        if search_value:
            qs = qs.filter(Q(name__icontains=search_value) | Q(description__icontains=search_value)).distinct()
        name_search = get_datatables_column_search_value(self.request, self.datatable_column_map, "name")
        if name_search:
            qs = qs.filter(name__icontains=name_search)
        description_search = get_datatables_column_search_value(self.request, self.datatable_column_map, "description")
        if description_search:
            qs = qs.filter(description__icontains=description_search)
        qs = apply_filter_list_in_by_param(qs, self.request, FILTER_PARAM_NAME, "name__in", distinct=True)
        return apply_datatables_order(qs, self.request, self.datatable_column_map, default_order="-insert_date")


class ListScheduledScansDatatableViewSet(DatatableListMixin, DatatablePaginationMixin, viewsets.GenericViewSet):
    """DataTables list API for scheduled scans (ScanSchedule)."""

    serializer_class = ScanScheduleDatatableSerializer
    datatable_column_map = DATATABLE_COLUMN_MAP_SCHEDULED_SCANS

    def get_queryset(self):
        return ScanSchedule.objects.all().order_by("-next_run")

    def filter_queryset(self, qs):
        search_value = self.request.GET.get("search[value]", None)
        if search_value:
            qs = qs.filter(name__icontains=search_value)
        return apply_datatables_order(
            qs,
            self.request,
            self.datatable_column_map,
            default_order="-next_run",
        )


class WafDetector(APIView):
    def get(self, request):
        req = self.request
        url = req.query_params.get("url")
        response = {"status": False, "message": "", "results": None}

        if not url:
            response["message"] = "URL parameter is missing"
            return Response(response)

        try:
            logger.log_line(
                PREFIX_API,
                "WAF",
                "WAF detection for URL: %s - Legacy function disabled, use Secator instead" % (url,),
                level="debug",
            )
            response["message"] = "WAF detection is now handled by Secator. Please use the Secator scan interface."
            logger.log_line(
                PREFIX_API,
                "WAF",
                "WAF detection result: %s" % (response,),
                level="debug",
            )
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "WAF",
                "Error during WAF detection: %s" % (e,),
                level="error",
            )
            response["message"] = "An unexpected error occurred. Please try again later."

        return Response(response)


class SearchHistoryView(APIView):
    def get(self, request):
        response = {"status": False}
        scan_history = SearchHistory.objects.all().order_by("-id")[:5]

        if scan_history:
            response["status"] = True
            response["results"] = SearchHistorySerializer(scan_history, many=True).data

        return Response(response)


class UniversalSearch(APIView):
    def get(self, request):
        req = self.request
        query = req.query_params.get("query")

        response = {"status": False}

        if not query:
            response["message"] = "No query parameter provided!"
            return Response(response)

        response["results"] = {}

        # search history to be saved
        SearchHistory.objects.get_or_create(query=query)

        # lookup query in subdomain
        subdomain = Subdomain.objects.filter(
            Q(name__icontains=query)
            | Q(cname__icontains=query)
            | Q(page_title__icontains=query)
            | Q(http_url__icontains=query)
        ).distinct("name")
        subdomain_data = SubdomainSerializer(subdomain, many=True).data
        response["results"]["subdomains"] = subdomain_data

        endpoint = EndPoint.objects.filter(Q(http_url__icontains=query) | Q(page_title__icontains=query)).distinct(
            "http_url"
        )
        endpoint_data = EndpointSerializer(endpoint, many=True).data
        response["results"]["endpoints"] = endpoint_data

        vulnerability = Vulnerability.objects.filter(
            Q(http_url__icontains=query) | Q(name__icontains=query) | Q(description__icontains=query)
        ).distinct()
        vulnerability_data = VulnerabilitySerializer(vulnerability, many=True).data
        response["results"]["vulnerabilities"] = vulnerability_data

        response["results"]["others"] = {}

        if subdomain_data or endpoint_data or vulnerability_data:
            response["status"] = True

        return Response(response)


class FetchMostCommonVulnerability(APIView):
    def post(self, request):
        data = request.data
        response = {"status": False}

        try:
            limit = safe_int_cast(data.get("limit", 20))
            project_slug = data.get("slug")
            scan_history_id = safe_int_cast(data.get("scan_history_id"))
            target_id = safe_int_cast(data.get("target_id"))
            is_ignore_info = data.get("ignore_info", False)

            base_filter = (
                Vulnerability.objects.filter(domain__scan_history__target__project__slug=project_slug)
                if project_slug
                else Vulnerability.objects.all()
            )
            if scan_history_id:
                vuln_query = base_filter.filter(scan_history__id=scan_history_id).values("name", "severity")
            elif target_id:
                vuln_query = base_filter.filter(domain__scan_history__target_id=target_id).values("name", "severity")
            else:
                vuln_query = base_filter.values("name", "severity")

            if is_ignore_info:
                most_common_vulnerabilities = (
                    vuln_query.exclude(severity=0).annotate(count=Count("name")).order_by("-count")[:limit]
                )
            else:
                most_common_vulnerabilities = vuln_query.annotate(count=Count("name")).order_by("-count")[:limit]

            most_common_vulnerabilities = list(most_common_vulnerabilities)

            if most_common_vulnerabilities:
                response["status"] = True
                response["result"] = most_common_vulnerabilities

        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "VULN",
                "Error in FetchMostCommonVulnerability: %s" % (e,),
                level="error",
            )
            response["message"] = "An error occurred while fetching vulnerabilities."

        return Response(response)


class FetchMostVulnerable(APIView):
    def post(self, request):
        req = self.request
        data = req.data

        project_slug = data.get("slug")
        scan_history_id = safe_int_cast(data.get("scan_history_id"))
        target_id = safe_int_cast(data.get("target_id"))
        limit = safe_int_cast(data.get("limit", 20))
        is_ignore_info = data.get("ignore_info", False)

        response = {"status": False}

        if project_slug:
            project = Project.objects.get(slug=project_slug)
            subdomains = Subdomain.objects.filter(domain__scan_history__target__project=project)
            domains = Domain.objects.filter(scan_history__target__project=project)
        else:
            subdomains = Subdomain.objects.all()
            domains = Domain.objects.all()

        if scan_history_id:
            subdomain_query = subdomains.filter(scan_history__id=scan_history_id)
            # Scalar count subquery avoids cartesian products vs annotate(Count(..., distinct=True)).
            vuln_annot = count_subquery(
                Vulnerability,
                "subdomain_id",
                filter_kwargs={"severity__gt": 0} if is_ignore_info else None,
            )
            most_vulnerable_subdomains = (
                subdomain_query.annotate(vuln_count=vuln_annot)
                .order_by("-vuln_count")
                .exclude(vuln_count=0)
                .prefetch_related(
                    "ip_addresses",
                    "ip_addresses__ports",
                    "technologies",
                    "waf",
                    "directories",
                    "scan_history",
                    "domain",
                    *(
                        []
                        if is_ignore_info
                        else [
                            Prefetch(
                                "endpoint_set",
                                queryset=EndPoint.objects.filter(is_default=True),
                                to_attr="default_endpoint_list",
                            ),
                        ]
                    ),
                )[:limit]
            )

            if most_vulnerable_subdomains:
                response["status"] = True
                ctx = {}
                if scan_history_id:
                    interesting = get_interesting_subdomains(scan_history=scan_history_id)
                    ctx["datatable_interesting_names"] = set(interesting.values_list("name", flat=True))
                response["result"] = SubdomainSerializer(most_vulnerable_subdomains, many=True, context=ctx).data

        elif target_id:
            subdomain_query = subdomains.filter(domain__scan_history__target_id=target_id)
            # Scalar count subquery avoids cartesian products vs annotate(Count(..., distinct=True)).
            vuln_annot = count_subquery(
                Vulnerability,
                "subdomain_id",
                filter_kwargs={"severity__gt": 0} if is_ignore_info else None,
            )
            most_vulnerable_subdomains = (
                subdomain_query.annotate(vuln_count=vuln_annot)
                .order_by("-vuln_count")
                .exclude(vuln_count=0)
                .prefetch_related(
                    "ip_addresses",
                    "ip_addresses__ports",
                    "technologies",
                    "waf",
                    "directories",
                    "scan_history",
                    "domain",
                )
            )[:limit]

            if most_vulnerable_subdomains:
                response["status"] = True
                ctx = {}
                interesting = get_interesting_subdomains(target_id=target_id)
                if interesting.exists():
                    ctx["datatable_interesting_names"] = set(interesting.values_list("name", flat=True))
                response["result"] = SubdomainSerializer(most_vulnerable_subdomains, many=True, context=ctx).data
        else:
            # Count Vulnerability rows per domain (each row has one subdomain_id, so same semantics as
            # previous join-based count: one vuln on two subdomains = two Vulnerability rows = count 2).
            domain_vuln_annot = count_subquery_related(
                Vulnerability,
                "subdomain__domain_id",
                filter_kwargs={"severity__gt": 0} if is_ignore_info else None,
            )
            most_vulnerable_targets = (
                domains.annotate(vuln_count=domain_vuln_annot).order_by("-vuln_count").exclude(vuln_count=0)[:limit]
            )

            if most_vulnerable_targets:
                response["status"] = True
                response["result"] = DomainSerializer(most_vulnerable_targets, many=True).data

        return Response(response)


class CVEDetails(APIView):
    def get(self, request):
        req = self.request

        cve_id = req.query_params.get("cve_id")

        if not cve_id:
            return Response({"status": False, "message": "CVE ID not provided"})

        response = requests.get("https://cve.circl.lu/api/cve/" + cve_id)

        if response.status_code != 200:
            return Response({"status": False, "message": "Unknown Error Occured!"})

        if not response.json():
            return Response({"status": False, "message": "CVE ID does not exists."})

        return Response({"status": True, "result": response.json()})


class AddReconNote(APIView):
    def post(self, request):
        req = self.request
        data = req.data

        subdomain_id = safe_int_cast(data.get("subdomain_id"))
        scan_history_id = safe_int_cast(data.get("scan_history_id"))
        title = data.get("title")
        description = data.get("description")
        project = data.get("project")

        if not title:
            return Response({"status": False, "error": "Title is required."}, status=400)
        if not project:
            return Response({"status": False, "error": "Project is required."}, status=400)

        try:
            project = Project.objects.get(slug=project)
            note = TodoNote()
            note.title = title
            note.description = description

            if scan_history_id:
                scan_history = ScanHistory.objects.get(id=scan_history_id)
                note.scan_history = scan_history

            # get scan history for subdomain_id
            if subdomain_id:
                subdomain = Subdomain.objects.get(id=subdomain_id)
                note.subdomain = subdomain

                # also get scan history
                scan_history_id = subdomain.scan_history.id
                scan_history = ScanHistory.objects.get(id=scan_history_id)
                note.scan_history = scan_history

            note.project = project
            note.save()
            return Response({"status": True, "error": False, "id": note.id}, status=200)
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "RECON_NOTE",
                "AddReconNote error: %s" % (e,),
                level="error",
            )
            return Response({"status": False, "error": "An error occurred."}, status=400)


class ToggleSubdomainImportantStatus(APIView):
    def post(self, request):
        req = self.request
        data = req.data

        if not data.get("subdomain_id"):
            response = {"status": False, "message": "No subdomain_id provided"}
            return Response(response)

        subdomain_id = safe_int_cast(data.get("subdomain_id"))

        name = Subdomain.objects.get(id=subdomain_id)
        name.is_important = not name.is_important
        name.save()

        response = {"status": True}

        return Response(response)


class AddTarget(APIView):
    def post(self, request):
        req = self.request
        data = req.data
        h1_team_handle = data.get("h1_team_handle")
        description = data.get("description")
        domain_name = data.get("domain_name")
        organization_name = data.get("organization")
        slug = data.get("slug")

        if not validators.domain(domain_name):
            return Response({"status": False, "message": "Invalid domain or IP"}, status=400)

        project = Project.objects.get(slug=slug)

        if Target.objects.filter(project=project, value=domain_name, target_type=TARGET_TYPE_HOST).exists():
            return Response({"status": False, "message": "Target already exists!"}, status=400)

        target, _ = Target.objects.get_or_create(
            project=project,
            value=domain_name,
            target_type=TARGET_TYPE_HOST,
            defaults={
                "insert_date": timezone.now(),
                "description": description,
                "h1_team_handle": h1_team_handle,
            },
        )

        if organization_name:
            organization_obj, created = Organization.objects.get_or_create(
                name=organization_name,
                project=project,
                defaults={"insert_date": timezone.now()},
            )
            if organization_obj.project_id != target.project_id:
                logger.log_line(
                    PREFIX_API,
                    "ADD_TARGET",
                    "Attempt to attach target from project %s to organization %s (project %s)"
                    % (target.project_id, organization_obj.id, organization_obj.project_id),
                    level="warning",
                )
                return Response(
                    {"detail": "Target and organization belong to different projects."},
                    status=HTTP_400_BAD_REQUEST,
                )
            # Legacy: targets can be attached directly to organization; in the scope-based model, attach targets to scopes instead.
            organization_obj.targets.add(target)

        return Response(
            {
                "status": True,
                "message": "Target successfully added!",
                "domain_name": domain_name,
                "target_id": target.id,
                "initiate_scan_url": reverse("start_scan", kwargs={"slug": slug, "target_id": target.id}),
            }
        )


class FetchSubscanResults(APIView):
    def get(self, request):
        req = self.request
        # data = req.data
        subscan_id = safe_int_cast(req.query_params.get("subscan_id"))
        subscan = SubScan.objects.filter(id=subscan_id)
        if not subscan.exists():
            return Response({"status": False, "error": f"Subscan {subscan_id} does not exist"})

        subscan_data = SubScanResultSerializer(subscan.first(), many=False).data
        task_name = subscan_data["type"]
        subscan_results = []

        # Legacy and Secator task types mapped to result sets
        port_scan_types = ("port_scan", "naabu")
        vuln_scan_types = ("vulnerability_scan", "nuclei")
        fetch_url_types = ("fetch_url", "httpx")
        dir_fuzz_types = ("dir_file_fuzz",)
        subdomain_types = ("subdomain_discovery", "subfinder", "dnsx")

        if task_name in port_scan_types:
            ips_in_subscan = IpAddress.objects.filter(ip_subscan_ids__in=subscan)
            ip_subdomain_data = get_ip_subdomain_data(ips_in_subscan)
            subscan_results = IpSerializer(
                ips_in_subscan, many=True, context={"ip_subdomain_data": ip_subdomain_data}
            ).data

        elif task_name in vuln_scan_types:
            vulns_in_subscan = Vulnerability.objects.filter(vuln_subscan_ids__in=subscan)
            subscan_results = VulnerabilitySerializer(vulns_in_subscan, many=True).data

        elif task_name in fetch_url_types:
            endpoints_in_subscan = EndPoint.objects.filter(endpoint_subscan_ids__in=subscan)
            subscan_results = EndpointSerializer(endpoints_in_subscan, many=True).data

        elif task_name in dir_fuzz_types:
            dirs_in_subscan = DirectoryScan.objects.filter(dir_subscan_ids__in=subscan)
            subscan_results = DirectoryScanSerializer(dirs_in_subscan, many=True).data

        elif task_name in subdomain_types:
            subdomains_in_subscan = Subdomain.objects.filter(subdomain_subscan_ids__in=subscan)
            subscan_results = SubdomainSerializer(subdomains_in_subscan, many=True).data

        elif task_name == "screenshot":
            endpoints_in_subscan = EndPoint.objects.filter(
                endpoint_subscan_ids__in=subscan, screenshot_path__isnull=False
            )
            subscan_results = EndpointSerializer(endpoints_in_subscan, many=True).data

        logger.log_line(
            PREFIX_API,
            "SUBSCAN",
            "FetchSubscanResults: subscan_data received",
            level="info",
        )
        logger.log_line(
            PREFIX_API,
            "SUBSCAN",
            "FetchSubscanResults: subscan_results received",
            level="info",
        )

        subscan_obj = subscan.first()
        project_slug = ""
        if subscan_obj.scan_history and getattr(subscan_obj.scan_history, "target", None):
            target = subscan_obj.scan_history.target
            if getattr(target, "project", None) and getattr(target.project, "slug", None):
                project_slug = target.project.slug

        return Response(
            {
                "subscan": subscan_data,
                "result": subscan_results,
                "endpoint_url": reverse("api:endpoints-list"),
                "vulnerability_url": reverse("api:vulnerabilities-list"),
                "directories_url": reverse("api:directories-list"),
                "project": project_slug,
            }
        )


class ListSubScans(APIView):
    def post(self, request):
        req = self.request
        data = req.data
        subdomain_id = safe_int_cast(data.get("subdomain_id", None))
        scan_history = safe_int_cast(data.get("scan_history_id", None))
        domain_id = safe_int_cast(data.get("domain_id", None))
        target_id = safe_int_cast(data.get("target_id", None))
        limit = parse_limit_from_request(request)

        subscan_base = SubScan.objects.select_related(
            "scan_history", "scan_history__target", "subdomain", "engine", "secator_runner"
        )
        if subdomain_id:
            qs = subscan_base.filter(subdomain__id=subdomain_id).order_by("-stop_scan_date")
        elif scan_history:
            qs = subscan_base.filter(scan_history__id=scan_history).order_by("-stop_scan_date")
        elif target_id:
            scan_history_qs = ScanHistory.objects.filter(target_id=target_id)
            qs = subscan_base.filter(scan_history__in=scan_history_qs).order_by("-stop_scan_date")
        elif domain_id:
            domain = get_domain_by_id(domain_id)
            target_id = domain.scan_history.target_id if (domain and domain.scan_history_id) else None
            if target_id is not None:
                scan_history_qs = ScanHistory.objects.filter(target_id=target_id)
                qs = subscan_base.filter(scan_history__in=scan_history_qs).order_by("-stop_scan_date")
            else:
                qs = subscan_base.none()
        else:
            return Response({"status": False})

        # Ensure deterministic ordering when limiting results
        qs = qs.order_by("-stop_scan_date", "-id")

        total_count = qs.count()
        subscans = list(qs[:limit])
        results = SubScanSerializer(subscans, many=True).data
        response = {
            "status": bool(results),
            "total_count": total_count,
            "limit": limit,
        }
        if results:
            response["results"] = results
        return Response(response)


class ListSubScansDatatableViewSet(DatatableListMixin, DatatablePaginationMixin, viewsets.GenericViewSet):
    """DataTables list API for subscans, filtered by project slug. Filter params: filter_organization, filter_status, filter_target, filter_scan_engine. See wiki datatables-api-filters.md."""

    serializer_class = SubScanDatatableSerializer
    datatable_column_map = DATATABLE_COLUMN_MAP_SUBSCAN_HISTORY

    def get_queryset(self):
        project = self.request.query_params.get("project")
        if not project:
            return SubScan.objects.none()
        return (
            SubScan.objects.filter(scan_history__target__project__slug=project)
            .select_related("scan_history", "scan_history__target", "subdomain", "engine", "secator_runner")
            .order_by("-start_scan_date")
        )

    def filter_queryset(self, qs):
        req = self.request
        search_value = req.GET.get("search[value]", None)
        if search_value:
            qs = qs.filter(
                Q(subdomain__name__icontains=search_value) | Q(scan_history__target__value__icontains=search_value)
            ).distinct()
        qs = apply_filter_list_in_by_param(
            qs, req, FILTER_PARAM_ORGANIZATION, "scan_history__target__organizations__name__in", distinct=True
        )
        qs = apply_filter_task_status(qs, req)
        qs = apply_filter_list_in_by_param(qs, req, FILTER_PARAM_TARGET, "scan_history__target__value__in")
        qs = apply_filter_list_in_by_param(qs, req, FILTER_PARAM_SCAN_ENGINE, "engine__engine_name__in")
        return apply_datatables_order(qs, req, self.datatable_column_map, default_order="-start_scan_date")


class ListS3BucketsDatatableViewSet(DatatableListMixin, DatatablePaginationMixin, viewsets.GenericViewSet):
    """
    DataTables list API for S3 buckets of a scan (scan_history_id).
    Filter params: filter_bucket_name. See wiki datatables-api-filters.md.
    Consuming template: startScan/detail_scan.html (S3 tab). Column map: DATATABLE_COLUMN_MAP_S3_BUCKETS.
    """

    serializer_class = S3BucketDatatableSerializer
    datatable_column_map = DATATABLE_COLUMN_MAP_S3_BUCKETS

    def get_queryset(self):
        scan_history_id = safe_int_cast(self.request.query_params.get("scan_history"))
        if not scan_history_id:
            return S3Bucket.objects.none()
        return S3Bucket.objects.filter(buckets__id=scan_history_id).distinct()

    def filter_queryset(self, qs):
        req = self.request
        search_value = req.GET.get("search[value]", "").strip()
        if search_value:
            qs = qs.filter(
                Q(name__icontains=search_value)
                | Q(region__icontains=search_value)
                | Q(provider__icontains=search_value)
            )
        qs = apply_filter_list_in_by_param(qs, req, FILTER_PARAM_BUCKET_NAME, "name__in")
        return apply_datatables_order(qs, req, self.datatable_column_map, default_order="name")


class ListWordlistsDatatableViewSet(DatatableListMixin, DatatablePaginationMixin, viewsets.GenericViewSet):
    """
    DataTables list API for wordlists. Filter params: filter_name. See wiki datatables-api-filters.md.
    Consuming template: scanEngine/wordlist/index.html. Column map: DATATABLE_COLUMN_MAP_WORDLIST.
    """

    serializer_class = WordlistDatatableSerializer
    datatable_column_map = DATATABLE_COLUMN_MAP_WORDLIST
    datatable_default_ordering = ("id",)

    def get_queryset(self):
        return Wordlist.objects.all().order_by("id")

    def filter_queryset(self, qs):
        req = self.request
        search_value = req.GET.get("search[value]", "").strip()
        if search_value:
            qs = qs.filter(Q(name__icontains=search_value) | Q(short_name__icontains=search_value))
        qs = apply_filter_list_in_by_param(qs, req, FILTER_PARAM_NAME, "name__in")
        return apply_datatables_order(qs, req, self.datatable_column_map, default_order="name")


class ListScanEnginesDatatableViewSet(DatatableListMixin, DatatablePaginationMixin, viewsets.GenericViewSet):
    """
    DataTables list API for scan engines (EngineType). Filter params: filter_engine_name. See wiki datatables-api-filters.md.
    Consuming template: scanEngine/index.html. Column map: DATATABLE_COLUMN_MAP_SCAN_ENGINE.
    """

    serializer_class = EngineTypeDatatableSerializer
    datatable_column_map = DATATABLE_COLUMN_MAP_SCAN_ENGINE
    datatable_default_ordering = ("engine_name",)

    def get_queryset(self):
        return EngineType.objects.all().order_by("engine_name")

    def filter_queryset(self, qs):
        req = self.request
        filter_scan_type = (req.query_params.get("filter_scan_type") or "").strip().lower()
        if filter_scan_type in ("internet", "internal_network"):
            qs = qs.filter(scan_type=filter_scan_type)
        qs = apply_filter_list_in_by_param(qs, req, FILTER_PARAM_ENGINE_NAME, "engine_name__in")
        search_value = req.GET.get("search[value]", "").strip()
        if search_value:
            qs = qs.filter(engine_name__icontains=search_value)
        return apply_datatables_order(qs, req, self.datatable_column_map, default_order="engine_name")


class DeleteMultipleRows(APIView):
    def post(self, request):
        req = self.request
        data = req.data
        subscan_ids = get_data_from_post_request(request, "rows")
        try:
            if data["type"] == "subscan":
                subscan_ids = [int(id) for id in subscan_ids]
                SubScan.objects.filter(id__in=subscan_ids).delete()
                return Response({"status": True})
        except ValueError:
            return Response({"status": False, "message": "Invalid subscan ID provided"}, status=400)
        except Exception as e:
            return Response(
                {"status": False, "message": get_safe_user_message(e, None) or GENERIC_USER_ERROR_MESSAGE},
                status=500,
            )


class StopScan(APIView):
    """
    API endpoint to stop a running scan or subscan.
    Uses SecatorScanController to revoke Celery tasks.
    """

    def post(self, request):
        from reNgine.secator.control import SecatorScanController

        data = request.data
        scan_id = safe_int_cast(data.get("scan_id"))
        subscan_id = safe_int_cast(data.get("subscan_id"))
        response = {}
        scan = None

        if subscan_id:
            try:
                subscan = get_object_or_404(SubScan, id=subscan_id)
                scan = subscan.scan_history

                # Use SecatorScanController to stop the subscan
                controller = SecatorScanController(scan.id)
                success = controller.stop_subscan(subscan_id)

                if success:
                    response["status"] = True
                else:
                    response = {"status": False, "message": "Failed to stop subscan"}
            except Exception as e:
                logger.log_line(
                    PREFIX_API,
                    "STOP_SCAN",
                    "Stop subscan error: %s" % (e,),
                    level="error",
                )
                response = {"status": False, "message": get_safe_user_message(e, None)}
        elif scan_id:
            try:
                scan = get_object_or_404(ScanHistory, id=scan_id)

                # Use SecatorScanController to stop the scan
                controller = SecatorScanController(scan_id)
                success = controller.stop_scan()

                if success:
                    scan.refresh_from_db()
                    scan.aborted_by = request.user
                    scan.stop_scan_date = timezone.now()
                    scan.save()
                    # Send WebSocket update
                    from reNgine.utilities.websocket import send_scan_status_update

                    send_scan_status_update(scan_id)
                    response["status"] = True
                else:
                    response = {"status": False, "message": "Failed to stop scan"}
            except Exception as e:
                logger.log_line(
                    PREFIX_API,
                    "STOP_SCAN",
                    "Stop scan error: %s" % (e,),
                    level="error",
                )
                response = {"status": False, "message": get_safe_user_message(e, None)}

        # Abort running scan activities
        if scan:
            tasks = ScanActivity.objects.filter(scan_of=scan).filter(status=RUNNING_TASK).order_by("-pk")
            for task in tasks:
                task.status = ABORTED_TASK
                task.time = timezone.now()
                task.save()

        return Response(response)


class StopActivity(APIView):
    """
    API endpoint to stop a running ScanActivity.
    Uses SecatorScanController to revoke the associated Celery task.
    """

    def post(self, request):
        from reNgine.secator.control import SecatorScanController

        data = request.data
        activity_id = safe_int_cast(data.get("activity_id"))

        if not activity_id:
            return Response({"status": False, "message": "activity_id is required"}, status=HTTP_400_BAD_REQUEST)

        try:
            activity = get_object_or_404(ScanActivity, id=activity_id)
            scan = activity.scan_of

            if not scan:
                return Response(
                    {"status": False, "message": "Activity has no associated scan"}, status=HTTP_400_BAD_REQUEST
                )

            # Use SecatorScanController to stop the activity
            controller = SecatorScanController(scan.id)
            success = controller.stop_activity(activity_id)

            if success:
                # Send WebSocket update if scan is available
                from reNgine.utilities.websocket import send_scan_status_update

                send_scan_status_update(scan.id)
                return Response({"status": True})
            else:
                return Response({"status": False, "message": "Failed to stop activity"})
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "STOP_ACTIVITY",
                "Stop activity error: %s" % (e,),
                level="error",
            )
            return Response({"status": False, "message": get_safe_user_message(e, None)}, status=HTTP_400_BAD_REQUEST)


class StartScan(APIView):
    """
    API endpoint to start a new Secator scan.

    This endpoint creates a scan history object and initiates a Secator scan task
    using Celery for asynchronous execution.
    """

    parser_classes = [JSONParser]

    def post(self, request):
        """
        Start a new Secator scan.

        Required parameters:
            - target_id (int): ID of the target (required).
            - Either secator_scan_id OR execution_mode with associated parameters

        Secator parameters:
            - secator_scan_id (int): ID of existing SecatorScan configuration
            - execution_mode (str): workflow|tasks|scan
            - workflow_id (int): Required for workflow mode
            - task_ids (list): Required for tasks mode
            - secator_scan_type (str): Required for scan mode (domain|host|network|subdomain|url)

        Secator configuration:
            - secator_config (dict): Configuration parameters (proxy, delay, profiles array)

        reNgine parameters:
            - imported_subdomains (list): List of subdomains to import
            - out_of_scope_subdomains (list): List of subdomains to exclude
            - url_filter (str): URL filter/path to scan

        Returns:
            JSON response with scan details or error message
        """
        data = request.data
        if hasattr(data, "get"):
            target_id = safe_int_cast(data.get("target_id"), default=None)
        else:
            target_id = None
        if target_id is None:
            return Response(
                {"status": False, "error": "target_id is required"},
                status=HTTP_400_BAD_REQUEST,
            )

        # Secator parameters
        if hasattr(data, "get"):
            execution_mode = data.get("execution_mode")
            workflow_id = safe_int_cast(data.get("workflow_id"))
            task_ids = data.get("task_ids", [])
            secator_scan_type = data.get("secator_scan_type")
            secator_scan_id = safe_int_cast(data.get("secator_scan_id"))
        else:
            execution_mode = None
            workflow_id = None
            task_ids = []
            secator_scan_type = None
            secator_scan_id = None

        # Secator configuration
        if hasattr(data, "get"):
            secator_config = data.get("secator_config", {})
            # Ensure profiles is a list
            if "profiles" in secator_config and not isinstance(secator_config["profiles"], list):
                secator_config["profiles"] = []
            # reNgine parameters
            imported_subdomains = data.get("imported_subdomains", [])
            out_of_scope_subdomains = data.get("out_of_scope_subdomains", [])
            url_filter = data.get("url_filter", "")
            raw_selected_targets = data.get("selected_targets") or []
            raw_selected_targets_per_task = data.get("selected_targets_per_task") or {}
            scan_history_id = safe_int_cast(data.get("scan_history_id"), default=None)
        else:
            secator_config = {}
            imported_subdomains = []
            out_of_scope_subdomains = []
            url_filter = ""
            raw_selected_targets = []
            raw_selected_targets_per_task = {}
            scan_history_id = None

        worker_id = get_request_worker_id(request)
        try:
            target = Target.objects.get(pk=target_id)
        except (Target.DoesNotExist, TypeError, ValueError):
            target = None
        if target is not None:
            from targetApp.services.scope_params import (
                get_scope_for_target,
                resolve_worker_for_scope,
            )

            scope = get_scope_for_target(target)
            worker_id = resolve_worker_for_scope(scope, worker_id)

        try:
            resolved = resolve_selected_targets(
                raw_selected_targets,
                raw_selected_targets_per_task,
                execution_mode,
            )
        except ValueError as exc:
            return Response({"error": get_safe_user_message(exc, logger)}, status=HTTP_400_BAD_REQUEST)

        if resolved["use_per_task"]:
            selected_targets_per_task = resolved["selected_targets_per_task"]
            run_result = run_per_task_secator_scans(
                target_id=target_id,
                user_id=request.user.id,
                selected_targets_per_task=selected_targets_per_task,
                task_type_to_id=None,
                imported_subdomains=imported_subdomains,
                out_of_scope_subdomains=out_of_scope_subdomains,
                url_filter=url_filter,
                secator_config=secator_config,
                scan_history_id=scan_history_id,
                worker_id=worker_id,
            )
            per_task_results = [
                {
                    "task_type": err["task_type"],
                    "status": "error",
                    "reason": err["reason"],
                    "detail": err["detail"],
                }
                for err in run_result["validation_errors"]
            ]
            for item in run_result["results"]:
                if item["status"] == "success":
                    per_task_results.append(
                        {
                            "task_type": item["task_type"],
                            "status": "success",
                            "scan_id": item.get("scan_id"),
                        }
                    )
                else:
                    per_task_results.append(
                        {
                            "task_type": item["task_type"],
                            "status": "error",
                            "reason": "start_failed",
                            "detail": item.get("detail", item.get("error", "Unknown error")),
                        }
                    )

            has_unknown_tasks = any(e["reason"] == "unknown_task_type" for e in run_result["validation_errors"])
            if has_unknown_tasks:
                return Response(
                    {
                        "status": False,
                        "error": "One or more requested task types are not known or not active",
                        "results": per_task_results,
                    },
                    status=HTTP_400_BAD_REQUEST,
                )

            if not per_task_results:
                return Response(
                    {
                        "status": False,
                        "error": "No task with selected targets. Select at least one target per task.",
                        "results": per_task_results,
                    },
                    status=HTTP_400_BAD_REQUEST,
                )

            return Response(
                {
                    "status": True,
                    "scan_id": run_result.get("scan_id"),
                    "message": f"Scans started for {len(per_task_results)} task(s)",
                    "results": per_task_results,
                },
                status=HTTP_200_OK,
            )

        targets_override = resolved.get("targets_override")
        if targets_override is not None and not targets_override:
            targets_override = None

        result = start_secator_scan(
            target_id=target_id,
            user_id=request.user.id,
            execution_mode=execution_mode,
            workflow_id=workflow_id,
            task_ids=task_ids,
            secator_scan_type=secator_scan_type,
            secator_scan_id=secator_scan_id,
            imported_subdomains=imported_subdomains,
            out_of_scope_subdomains=out_of_scope_subdomains,
            url_filter=url_filter,
            secator_config=secator_config,
            targets_override=targets_override,
            scan_history_id=scan_history_id,
            worker_id=worker_id,
        )

        # Convert result to Response
        # Use explicit http_status from result, with fallback for backward compatibility
        http_status = result.get("http_status")
        if http_status is None:
            # Backward compatibility / safety net: derive a status code if not provided
            http_status = 200 if result.get("status") else 500
        return Response(result, status=http_status)


class GetSubdomainNames(APIView):
    """
    Returns subdomain id and name for given IDs (from database).
    Used by the subscan modal header to display target names.
    """

    def get(self, request):
        ids_param = request.query_params.get("ids", "")
        if not ids_param:
            return Response({"results": []})
        try:
            subdomain_ids = [int(x.strip()) for x in ids_param.split(",") if x.strip()]
        except ValueError:
            return Response({"results": []}, status=HTTP_400_BAD_REQUEST)
        if not subdomain_ids:
            return Response({"results": []})
        subdomains = Subdomain.objects.filter(id__in=subdomain_ids)
        id_to_subdomain = {s.id: s for s in subdomains}
        results = [{"id": sid, "name": id_to_subdomain[sid].name} for sid in subdomain_ids if sid in id_to_subdomain]
        return Response({"results": results})


class InitiateSubTask(APIView):
    """
    API endpoint to initiate Secator subscans on specific subdomains.

    This endpoint allows launching Secator workflows or tasks on individual subdomains
    for targeted scanning operations.
    """

    parser_classes = [JSONParser]

    def post(self, request):
        data = request.data
        subdomain_ids = safe_int_cast(data.get("subdomain_ids", []))
        scan_history_id = safe_int_cast(data.get("scan_history_id"), default=None)

        # Secator parameters
        workflow_id = safe_int_cast(data.get("workflow_id"))
        workflow_name = data.get("workflow_name")
        task_names = data.get("task_names", [])
        secator_scan_type = data.get("secator_scan_type")
        secator_config = data.get("secator_config", {})

        if not subdomain_ids:
            return Response({"status": False, "error": "Missing subdomain_ids"}, status=400)

        if isinstance(subdomain_ids, int):
            subdomain_ids = [subdomain_ids]

        # Determine execution mode
        execution_mode = None
        workflow_id_for_scan = None
        task_ids_for_scan = None

        if workflow_id:
            # Secator workflow mode
            execution_mode = "workflow"
            try:
                workflow = SecatorWorkflow.objects.get(id=workflow_id)
                workflow_id_for_scan = workflow_id
            except SecatorWorkflow.DoesNotExist:
                return Response({"status": False, "error": f"Workflow with ID {workflow_id} not found"}, status=404)
        elif workflow_name:
            # Secator workflow mode - find by name
            execution_mode = "workflow"
            try:
                workflow = SecatorWorkflow.objects.get(name=workflow_name)
                workflow_id_for_scan = workflow.id
            except SecatorWorkflow.DoesNotExist:
                return Response(
                    {"status": False, "error": f"Workflow with name '{workflow_name}' not found"}, status=404
                )
        elif task_names:
            # Secator tasks mode - convert task names to task IDs
            execution_mode = "tasks"

            # Use unique task names to handle duplicates correctly
            unique_task_names = list(set(task_names))
            tasks = SecatorTask.objects.filter(task_type__in=unique_task_names, is_active=True)
            found_task_types = set(tasks.values_list("task_type", flat=True))
            if len(found_task_types) != len(unique_task_names):
                missing = set(unique_task_names) - found_task_types
                return Response({"status": False, "error": f"Some tasks not found: {', '.join(missing)}"}, status=404)
            task_ids_for_scan = list(tasks.values_list("id", flat=True))
            task_type_to_id = dict(tasks.values_list("task_type", "id"))
        elif secator_scan_type:
            # Secator scan mode
            execution_mode = "scan"
        else:
            return Response(
                {
                    "status": False,
                    "error": "Must provide either workflow_id/workflow_name, task_names, or secator_scan_type",
                },
                status=400,
            )

        # Get subdomains and validate
        try:
            subdomains = Subdomain.objects.filter(id__in=subdomain_ids)
            if not subdomains.exists():
                return Response({"status": False, "error": "No valid subdomains found"}, status=404)

            # Require all subdomains to belong to the same target (they may span multiple Domain/scan)
            target_ids = list(subdomains.values_list("scan_history__target_id", flat=True).distinct())
            target_ids = [tid for tid in target_ids if tid is not None]
            if not target_ids:
                return Response(
                    {"status": False, "error": "Could not resolve target from subdomains"},
                    status=400,
                )
            if len(target_ids) > 1:
                return Response(
                    {"status": False, "error": "All subdomains must belong to the same target"},
                    status=400,
                )
            target_id_from_domain = target_ids[0]

        except Exception as e:
            return Response({"status": False, "error": get_safe_user_message(e, logger)}, status=400)

        # selected_targets_per_task only (no selected_targets here). Use resolve_selected_targets for consistent parsing.
        try:
            resolved = resolve_selected_targets(
                None,
                data.get("selected_targets_per_task") or {},
                "tasks",
            )
        except ValueError as exc:
            return Response({"error": get_safe_user_message(exc, logger)}, status=HTTP_400_BAD_REQUEST)

        selected_targets_per_task = resolved["selected_targets_per_task"]
        scan_results = []

        if execution_mode == "tasks" and selected_targets_per_task:
            if target_id_from_domain is None:
                return Response(
                    {"status": False, "error": "Subdomains have no linked scan/target; cannot run per-task scans"},
                    status=400,
                )
            run_result = run_per_task_secator_scans(
                target_id=target_id_from_domain,
                user_id=request.user.id,
                selected_targets_per_task=selected_targets_per_task,
                task_type_to_id=task_type_to_id,
                imported_subdomains=[],
                out_of_scope_subdomains=[],
                url_filter="",
                secator_config=secator_config,
                subdomain_ids=subdomain_ids,
                scan_history_id=scan_history_id,
            )
            for err in run_result["validation_errors"]:
                scan_results.append({"task_type": err["task_type"], "status": "error", "error": err["detail"]})
            for item in run_result["results"]:
                if item["status"] == "success":
                    scan_results.append(
                        {
                            "task_type": item["task_type"],
                            "scan_id": item.get("scan_id"),
                            "status": "success",
                        }
                    )
                else:
                    scan_results.append(
                        {
                            "task_type": item["task_type"],
                            "status": "error",
                            "error": item.get("error", item.get("detail", "Unknown error")),
                        }
                    )
            if not run_result["results"]:
                return Response(
                    {
                        "status": False,
                        "error": "No task with selected targets. Select at least one target per task.",
                        "results": scan_results,
                    },
                    status=400,
                )
            return Response(
                {
                    "status": True,
                    "scan_id": run_result.get("scan_id"),
                    "message": f"Subscans initiated for {len(scan_results)} task(s)",
                    "results": scan_results,
                },
            )

        # Default: one scan per subdomain; reuse scan_history_id when provided (create SubScans under one ScanHistory)
        scan = None
        subscan_type = ""
        if scan_history_id is not None:
            try:
                scan = ScanHistory.objects.get(pk=scan_history_id)
                if target_id_from_domain is not None and scan.target_id != target_id_from_domain:
                    return Response(
                        {
                            "status": False,
                            "error": "ScanHistory %s does not belong to this target" % (scan_history_id,),
                        },
                        status=400,
                    )
                if execution_mode == "workflow" and workflow_id_for_scan:
                    subscan_type = SecatorWorkflow.objects.get(pk=workflow_id_for_scan).name
                elif execution_mode == "scan" and secator_scan_type:
                    subscan_type = secator_scan_type
                else:
                    subscan_type = execution_mode or "subscan"
            except ScanHistory.DoesNotExist:
                return Response(
                    {"status": False, "error": f"ScanHistory {scan_history_id} not found"},
                    status=404,
                )
            except SecatorWorkflow.DoesNotExist:
                return Response(
                    {"status": False, "error": f"Workflow {workflow_id_for_scan} not found"},
                    status=404,
                )

        for subdomain in subdomains:
            try:
                subscan_id_arg = None
                if scan is not None:
                    subscan = SubScan.objects.create(
                        scan_history=scan,
                        subdomain=subdomain,
                        type=subscan_type,
                        start_scan_date=timezone.now(),
                        status=RUNNING_TASK,
                    )
                    subscan_id_arg = subscan.id

                worker_id = get_request_worker_id(request)
                if target_id_from_domain is not None:
                    try:
                        target_for_scope = Target.objects.get(pk=target_id_from_domain)
                    except (Target.DoesNotExist, TypeError, ValueError):
                        target_for_scope = None
                    if target_for_scope is not None:
                        from targetApp.services.scope_params import (
                            get_scope_for_target,
                            resolve_worker_for_scope,
                        )

                        scope = get_scope_for_target(target_for_scope)
                        worker_id = resolve_worker_for_scope(scope, worker_id)
                result = start_secator_scan(
                    target_id=target_id_from_domain,
                    user_id=request.user.id,
                    execution_mode=execution_mode,
                    workflow_id=workflow_id_for_scan,
                    task_ids=task_ids_for_scan,
                    secator_scan_type=secator_scan_type,
                    imported_subdomains=[subdomain.name],
                    out_of_scope_subdomains=[],
                    url_filter="",
                    subdomain_ids=[subdomain.id],
                    secator_config=secator_config,
                    scan_history_id=scan_history_id if scan else None,
                    subscan_id=subscan_id_arg,
                    worker_id=worker_id,
                )

                if result.get("status"):
                    scan_results.append(
                        {
                            "subdomain_id": subdomain.id,
                            "subdomain_name": subdomain.name,
                            "scan_id": result.get("scan_id"),
                            "status": "success",
                        }
                    )
                    logger.log_line(
                        PREFIX_API,
                        "SECATOR_SUBSCAN",
                        "Secator subscan initiated for subdomain %s (ID: %s)" % (subdomain.name, subdomain.id),
                        level="info",
                    )
                else:
                    scan_results.append(
                        {
                            "subdomain_id": subdomain.id,
                            "subdomain_name": subdomain.name,
                            "status": "error",
                            "error": result.get("error", "Unknown error"),
                        }
                    )
                    logger.log_line(
                        PREFIX_API,
                        "SECATOR_SUBSCAN",
                        "Failed to start subscan for subdomain %s: %s"
                        % (subdomain.name, result.get("error", "Unknown error")),
                        level="error",
                    )

            except Exception as e:
                logger.log_line(
                    PREFIX_API,
                    "SECATOR_SUBSCAN",
                    "Error initiating subscan for subdomain %s: %s" % (subdomain.name, e),
                    level="error",
                )
                scan_results.append(
                    {
                        "subdomain_id": subdomain.id,
                        "subdomain_name": subdomain.name,
                        "status": "error",
                        "error": get_safe_user_message(e, None),
                    }
                )

        return Response(
            {
                "status": True,
                "message": f"Subscans initiated for {len(subdomain_ids)} subdomain(s)",
                "results": scan_results,
            },
        )


def _build_secator_flat_targets_and_by_type(
    target_id: int,
    subdomain_ids: list,
    input_types: list,
) -> tuple:
    """
    Build flat_targets and targets_by_type for one target.

    Returns:
        (flat_targets, targets_by_type) for use by GetSecatorInputTypesAndTargets.
    """
    builder = TargetBuilderService(target_id=target_id, subdomain_ids=subdomain_ids)
    flat_targets = builder.build_flat_targets(input_types)
    targets_by_type = builder.build_targets_by_type(input_types)
    return (flat_targets, targets_by_type)


class GetSecatorInputTypesAndTargets(APIView):
    """
    API endpoint to get input_types and proposed targets for a Secator workflow/scan/task.

    Used by the scan launch UI to display required input types and the targets that will be sent.
    """

    http_method_names = ["get"]
    permission_classes = [IsAuthenticated]

    # Limit targets returned in response to avoid huge payloads; UI can show "first N of total"
    TARGETS_DISPLAY_LIMIT = 500

    def get(self, request):
        workflow_id = request.query_params.get("workflow_id")
        scan_id = request.query_params.get("scan_id")
        task_id = request.query_params.get("task_id")
        target_id_param = request.query_params.get("target_id")
        target_ids_param = request.query_params.get("target_ids")
        domain_id_param = request.query_params.get("domain_id")
        subdomain_ids_param = request.query_params.get("subdomain_ids")

        subdomain_ids = []
        if subdomain_ids_param:
            if isinstance(subdomain_ids_param, str):
                subdomain_ids = [int(x.strip()) for x in subdomain_ids_param.split(",") if x.strip()]
            else:
                subdomain_ids = safe_int_cast(subdomain_ids_param)
            if isinstance(subdomain_ids, int):
                subdomain_ids = [subdomain_ids]

        target_id = None
        target_id_list = None
        if target_ids_param and isinstance(target_ids_param, str) and target_ids_param.strip():
            raw = [x.strip() for x in target_ids_param.split(",") if x.strip()]
            try:
                target_id_list = [int(x) for x in raw]
            except (TypeError, ValueError):
                return Response(
                    {"error": "target_ids must be a comma-separated list of integers"},
                    status=HTTP_400_BAD_REQUEST,
                )
            if not target_id_list:
                return Response(
                    {"error": "target_ids must contain at least one valid id"},
                    status=HTTP_400_BAD_REQUEST,
                )
            target_id = target_id_list[0]
        elif target_id_param:
            try:
                target_id = int(target_id_param)
            except (TypeError, ValueError):
                return Response(
                    {"error": "target_id must be an integer"},
                    status=HTTP_400_BAD_REQUEST,
                )
        elif domain_id_param:
            try:
                domain_id = int(domain_id_param)
            except (TypeError, ValueError):
                return Response(
                    {"error": "domain_id must be an integer"},
                    status=HTTP_400_BAD_REQUEST,
                )
            domain = get_domain_by_id(domain_id)
            if not domain or domain.scan_history_id is None:
                return Response(
                    {"error": "Domain not found or has no linked scan"},
                    status=HTTP_400_BAD_REQUEST,
                )
            target_id = domain.scan_history.target_id
        elif subdomain_ids:
            target_ids = list(
                Subdomain.objects.filter(id__in=subdomain_ids)
                .values_list("scan_history__target_id", flat=True)
                .distinct()
            )
            target_ids = [tid for tid in target_ids if tid is not None]
            if not target_ids:
                return Response(
                    {"error": "Could not resolve target from subdomain_ids"},
                    status=HTTP_400_BAD_REQUEST,
                )
            if len(target_ids) > 1:
                return Response(
                    {"error": "All subdomain_ids must belong to the same target"},
                    status=HTTP_400_BAD_REQUEST,
                )
            target_id = target_ids[0]
        else:
            return Response(
                {"error": "target_id, domain_id, or subdomain_ids is required"},
                status=HTTP_400_BAD_REQUEST,
            )

        workflow_name = request.query_params.get("workflow_name") or ""
        scan_name = request.query_params.get("scan_name") or ""
        task_name = request.query_params.get("task_name") or ""
        has_workflow = (workflow_id is not None and workflow_id != "") or bool(workflow_name.strip())
        has_scan = (scan_id is not None and scan_id != "") or bool(scan_name.strip())
        has_task = (task_id is not None and task_id != "") or bool(task_name.strip())
        provided = sum([has_workflow, has_scan, has_task])
        if provided != 1:
            return Response(
                {
                    "error": "Exactly one of workflow_id/workflow_name, scan_id/scan_name, or task_id/task_name must be provided"
                },
                status=HTTP_400_BAD_REQUEST,
            )

        try:
            from reNgine.definitions import COMMON_WEB_PORTS, UNCOMMON_WEB_PORTS
            from reNgine.secator.services.input_type_service import InputTypeService

            if has_workflow:
                if workflow_id:
                    input_types = InputTypeService.get_input_types(workflow_id=int(workflow_id))
                else:
                    input_types = InputTypeService.get_input_types(workflow_name=workflow_name.strip())
            elif has_scan:
                if scan_id:
                    input_types = InputTypeService.get_input_types(scan_id=int(scan_id))
                else:
                    input_types = InputTypeService.get_input_types(scan_name=scan_name.strip())
            else:
                if task_id:
                    input_types = InputTypeService.get_input_types(task_id=int(task_id))
                else:
                    input_types = InputTypeService.get_input_types(task_name=task_name.strip())

            if target_id_list is not None and len(target_id_list) > 1:
                # Deduplicate by value; flat_targets are plain strings (no type/source).
                # Same value from different target_ids is kept once.
                seen: set = set()
                flat_targets = []
                for tid in target_id_list:
                    one_flat, _ = _build_secator_flat_targets_and_by_type(tid, [], input_types)
                    for t in one_flat:
                        key = t if isinstance(t, str) else str(t)
                        if key not in seen:
                            seen.add(key)
                            flat_targets.append(t)
                # For multi-target we do not compute a combined targets_by_type;
                # return empty dict so the response shape stays consistent.
                targets_by_type = {}
                total_count = len(flat_targets)
                proposed_targets = flat_targets[: self.TARGETS_DISPLAY_LIMIT]
                truncated = total_count > self.TARGETS_DISPLAY_LIMIT
            else:
                flat_targets, targets_by_type = _build_secator_flat_targets_and_by_type(
                    target_id, subdomain_ids, input_types
                )
                total_count = len(flat_targets)
                proposed_targets = flat_targets[: self.TARGETS_DISPLAY_LIMIT]
                truncated = total_count > self.TARGETS_DISPLAY_LIMIT

            apex_hosts = [t for t in proposed_targets if is_apex_domain(t)]
            payload = {
                "input_types": input_types,
                "targets_by_type": targets_by_type,
                "proposed_targets": proposed_targets,
                "total_count": total_count,
                "truncated": truncated,
                "apex_hosts": apex_hosts,
                "common_web_ports": list(COMMON_WEB_PORTS),
                "uncommon_web_ports": list(UNCOMMON_WEB_PORTS),
            }
            return Response(payload)
        except (SecatorWorkflow.DoesNotExist, SecatorScan.DoesNotExist, SecatorTask.DoesNotExist):
            return Response({"error": "Workflow, scan or task not found"}, status=404)
        except ValueError:
            return Response({"error": "Invalid request parameters"}, status=HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "SECATOR_TARGETS",
                "GetSecatorInputTypesAndTargets error: %s" % (e,),
                level="error",
                exc_info=True,
            )
            return Response({"error": "Unexpected error building targets"}, status=500)


class GetSecatorSelection(APIView):
    """
    API endpoint to get Secator selection HTML (workflows, tasks, scans).

    This endpoint is used by the subscan modal to dynamically load selection options.
    Access is restricted to authenticated users and AJAX (XMLHttpRequest) requests.
    """

    http_method_names = ["get"]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from startScan.secator.ajax import render_secator_selection_json

        # Prefer AJAX requests to avoid exposing template HTML broadly
        # Note: This check is advisory - if other clients need access in future,
        # consider moving this enforcement to middleware or making it optional
        # DRF provides request.headers which is case-insensitive
        x_requested_with = request.headers.get("X-Requested-With", "")
        if x_requested_with != "XMLHttpRequest":
            # Log warning but allow request for future client compatibility
            logger.log_line(
                PREFIX_API,
                "SECATOR_SELECTION",
                "GetSecatorSelection accessed without X-Requested-With header from %s"
                % (request.META.get("REMOTE_ADDR", "unknown"),),
                level="warning",
            )

        return render_secator_selection_json(request)


class GetScanParamsEffectiveHtml(APIView):
    """
    Returns the effective scan parameters display HTML for a given target.

    Used by the subscan modal to inject the shared effective-params block
    (single source of truth: shared/_scan_params_effective_display.html).
    GET with target_id (required). Returns 404 if target not found.
    """

    http_method_names = ["get"]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        target_id = request.GET.get("target_id")
        if not target_id or not str(target_id).strip().isdigit():
            return HttpResponse(
                '<p class="text-muted small">Effective parameters depend on the scan target.</p>',
                content_type="text/html",
            )
        target = Target.objects.filter(id=int(target_id)).select_related("project").first()
        if not target:
            return HttpResponse(
                '<p class="text-muted small">Target not found.</p>',
                content_type="text/html",
            )
        from targetApp.services.scope_params import build_effective_params_display, get_scope_for_target

        scope = get_scope_for_target(target)
        organization = scope.organization if scope else target.organizations.first()

        scan_params_effective = build_effective_params_display(target=target, scope=scope, organization=organization)
        html = render_to_string(
            "shared/_scan_params_effective_display.html",
            {
                "scan_params_effective": scan_params_effective,
                "scan_params_level": "target",
            },
            request=request,
        )
        return HttpResponse(html, content_type="text/html")


class PostScanParamsEffectivePreview(APIView):
    """
    Returns the effective scan parameters display HTML for a draft form state.

    POST body (JSON): level, project_slug, organization_id?, scope_id?, target_id?, draft.
    Used for real-time effective block updates when the user edits scan params on
    Organization, Scope, Target, or Scan forms.
    """

    http_method_names = ["post"]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        from api.scan_params_preview import (
            ScanParamsPreviewError,
            _preview_config_organization,
            _preview_config_scan,
            _preview_config_scope,
            _preview_config_target,
        )
        from targetApp.services.scan_param_definitions import ORDERED_PARAM_KEYS_FOR_FORM, PARAM_KEYS
        from targetApp.services.scope_params import (
            _normalize_scan_config,
            build_effective_params_display_from_configs,
        )

        try:
            data = request.data if getattr(request, "data", None) else {}
            if not isinstance(data, dict):
                return HttpResponse(
                    '<p class="text-muted small">Invalid request.</p>',
                    content_type="text/html",
                    status=400,
                )
        except Exception:
            return HttpResponse(
                '<p class="text-muted small">Invalid request.</p>',
                content_type="text/html",
                status=400,
            )

        level = (data.get("level") or "").strip().lower()
        if level not in ("organization", "scope", "target", "scan"):
            return HttpResponse(
                '<p class="text-muted small">Invalid level.</p>',
                content_type="text/html",
                status=400,
            )

        draft_raw = data.get("draft")
        draft = _normalize_scan_config(draft_raw) if draft_raw is not None else {}
        allowed_keys = set(PARAM_KEYS) | {"profiles", "extra_config", "worker_id"}
        draft = {k: v for k, v in draft.items() if k in allowed_keys}
        scan_params_level = level

        scope_for_worker = None
        if level in ("scan", "target") and data.get("target_id") and (data.get("project_slug") or "").strip():
            from targetApp.models import Target
            from targetApp.services.scope_params import get_scope_for_target

            try:
                target = Target.objects.get(
                    id=int(data["target_id"]),
                    project__slug=(data.get("project_slug") or "").strip(),
                )
                scope_for_worker = get_scope_for_target(target)
            except (Target.DoesNotExist, TypeError, ValueError):
                pass

        try:
            if level == "organization":
                org_config, scope_config, target_config, user_override = _preview_config_organization(draft)
            elif level == "scope":
                org_config, scope_config, target_config, user_override = _preview_config_scope(
                    data, draft, _normalize_scan_config
                )
            elif level == "target":
                org_config, scope_config, target_config, user_override = _preview_config_target(
                    data, draft, _normalize_scan_config
                )
            else:
                org_config, scope_config, target_config, user_override = _preview_config_scan(
                    data, draft, _normalize_scan_config
                )
        except ScanParamsPreviewError as e:
            msg = str(e).strip() or "Invalid request."
            html = render_to_string(
                "shared/_scan_params_effective_display_error.html",
                {"error_message": msg},
                request=request,
            )
            return HttpResponse(html, content_type="text/html", status=400)
        except ValueError as e:
            logger.log_line(
                PREFIX_API,
                "SCAN_PARAMS_PREVIEW",
                "Unexpected ValueError in PostScanParamsEffectivePreview: %s" % (e,),
                level="exception",
            )
            html = render_to_string(
                "shared/_scan_params_effective_display_error.html",
                {"error_message": "Unable to preview scan parameters due to an internal error."},
                request=request,
            )
            return HttpResponse(html, content_type="text/html", status=500)
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "SCAN_PARAMS_PREVIEW",
                "PostScanParamsEffectivePreview failed: %s" % (e,),
                level="exception",
            )
            html = render_to_string(
                "shared/_scan_params_effective_display_error.html",
                {"error_message": "Unable to preview scan parameters due to an internal error."},
                request=request,
            )
            return HttpResponse(html, content_type="text/html", status=500)

        scan_params_effective = build_effective_params_display_from_configs(
            org_config=org_config,
            scope_config=scope_config,
            target_config=target_config,
            user_override=user_override,
            scope=scope_for_worker,
        )
        scan_params_effective_ordered = [
            (p, scan_params_effective[p]) for p in ORDERED_PARAM_KEYS_FOR_FORM if p in scan_params_effective
        ]

        html = render_to_string(
            "shared/_scan_params_effective_display.html",
            {
                "scan_params_effective": scan_params_effective,
                "scan_params_effective_ordered": scan_params_effective_ordered,
                "scan_params_level": scan_params_level,
            },
            request=request,
        )
        return HttpResponse(html, content_type="text/html")


class DeleteSubdomain(APIView):
    def post(self, request):
        subdomain_ids = get_data_from_post_request(request, "subdomain_ids")
        try:
            subdomain_ids = [int(id) for id in subdomain_ids]
            Subdomain.objects.filter(id__in=subdomain_ids).delete()
            return Response({"status": True})
        except ValueError:
            return Response({"status": False, "message": "Invalid subdomain ID provided"}, status=400)
        except Exception as e:
            return Response(
                {"status": False, "message": get_safe_user_message(e, None) or GENERIC_USER_ERROR_MESSAGE},
                status=500,
            )


class DeleteVulnerability(APIView):
    def post(self, request):
        vulnerability_ids = get_data_from_post_request(request, "vulnerability_ids")

        # Check if vulnerability_ids is iterable
        if not isinstance(vulnerability_ids, (list, tuple)):
            return Response({"status": False, "message": "vulnerability_ids must be a list or tuple"}, status=400)

        try:
            # Convert to integers
            vulnerability_ids = [int(id) for id in vulnerability_ids]
            # Delete vulnerabilities
            Vulnerability.objects.filter(id__in=vulnerability_ids).delete()
            return Response({"status": True})
        except ValueError:
            return Response({"status": False, "message": "Invalid vulnerability ID provided"}, status=400)


class ListInterestingKeywords(APIView):
    def get(self, request, format=None):
        keywords = get_lookup_keywords()
        return Response(keywords)


class RengineUpdateCheck(APIView):
    def get(self, request):
        from reNgine.utilities.update_check import get_update_info

        info = get_update_info()
        if not info.get("status"):
            error_type_str = str(info.get("error_type", "")).lower()
            transient_error_types = {
                "ratelimited",
                "rate_limited",
                "rate-limit",
                "upstream_unavailable",
                "github_downtime",
            }
            internal_error_types = {
                "invalid_version",
                "invalid_response",
                "parse_error",
                "no_releases",
                "unexpected_response",
                "internal_error",
            }
            if error_type_str in transient_error_types:
                status_code = 503
            elif error_type_str in internal_error_types or error_type_str:
                status_code = 500
            else:
                status_code = 500
            return Response(
                {
                    "status": False,
                    "message": info.get("message", "Update check failed"),
                    "description": info.get(
                        "description",
                        "Unable to determine update status due to an internal error.",
                    ),
                    "error_type": error_type_str or None,
                },
                status=status_code,
            )
        return_response = {
            "status": True,
            "latest_version": info["latest_version"],
            "current_version": info["current_version"],
            "update_available": info["update_available"],
        }
        if info.get("changelog") is not None:
            return_response["changelog"] = info["changelog"]
        return Response(return_response)


class ScanStatus(APIView):
    """Return pending/running/completed scans and tasks for the project dashboard."""

    MAX_RUNNING_TASKS = 30

    def get(self, request):
        slug = self.request.GET.get("project", None)
        qs = get_scan_status_querysets(slug, max_running_tasks=self.MAX_RUNNING_TASKS)
        response = {
            "scans": {
                "pending": ScanHistorySerializer(qs["pending_scans"], many=True).data,
                "scanning": ScanHistorySerializer(qs["current_scans"], many=True).data,
                "completed": ScanHistorySerializer(qs["recently_completed_scans"], many=True).data,
            },
            "tasks": {
                "pending": SubScanSerializer(qs["pending_tasks"], many=True).data,
                "running": ScanActivitySerializer(qs["current_tasks"], many=True).data,
                "completed": ScanActivitySerializer(qs["recently_completed_tasks"], many=True).data,
            },
        }
        return Response(response)


class Whois(APIView):
    def get(self, request):
        req = self.request
        ip_domain = req.query_params.get("ip_domain")
        if not (validators.domain(ip_domain) or validators.ipv4(ip_domain) or validators.ipv6(ip_domain)):
            print(f'Ip address or domain "{ip_domain}" did not pass validator.')
            return Response({"status": False, "message": "Invalid domain or IP"})
        is_force_update = req.query_params.get("is_reload")
        is_force_update = True if is_force_update and "true" == is_force_update.lower() else False
        # NOTE: WHOIS functionality moved to Secator
        return Response({"status": False, "message": "WHOIS functionality moved to Secator"})


class ReverseWhois(APIView):
    def get(self, request):
        # NOTE: Reverse WHOIS functionality moved to Secator
        return Response({"status": False, "message": "Reverse WHOIS functionality moved to Secator"})


class DomainIPHistory(APIView):
    def get(self, request):
        # NOTE: IP history functionality moved to Secator
        return Response({"status": False, "message": "IP history functionality moved to Secator"})


class CMSDetector(APIView):
    def get(self, request):
        url = request.query_params.get("url")
        if not url:
            return Response({"status": False, "message": "URL parameter is missing"})

        try:
            # NOTE: CMS detection functionality moved to Secator
            return Response({"status": False, "message": "CMS detection functionality moved to Secator"})
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "CMS_DETECTOR",
                "Error in CMSDetector: %s" % (e,),
                level="error",
            )
            return Response({"status": False, "message": "An unexpected error occurred."}, status=500)


class VulnerabilityReport(APIView):
    def get(self, request):
        req = self.request
        vulnerability_id = safe_int_cast(req.query_params.get("vulnerability_id"))
        return Response({"status": send_hackerone_report(vulnerability_id)})


def _read_asset_preview(base_dir: str, name: str, extension: str) -> tuple[bool, str, str]:
    """Read asset file for preview with size limit and UTF-8 validation.

    Reads up to MAX_ASSET_PREVIEW_BYTES + 1; large files get a truncated preview
    instead of a hard failure. Returns (success, content, message): content is ""
    on failure; message is set on failure or when preview was truncated.
    Rejects absolute paths and ".." to enforce sandboxing.
    """
    if not name:
        return False, "", "Invalid path!"

    try:
        name_path = Path(name)
    except TypeError:
        return False, "", "Invalid path!"
    if name_path.is_absolute():
        return False, "", "Invalid path!"
    if any(part == ".." for part in name_path.parts):
        return False, "", "Invalid path!"

    try:
        base_path = Path(base_dir).resolve()
        target_path = base_path / name_path
        if not name_path.suffix:
            ext = extension.lstrip(".")
            target_path = target_path.with_suffix(f".{ext}")
        target_path = target_path.resolve()
        target_path.relative_to(base_path)
    except (OSError, ValueError):
        return False, "", "Refusing to read asset outside of base directory."

    if not target_path.exists():
        return False, "", "Asset not found."
    if not target_path.is_file():
        return False, "", "Asset path is not a file."

    try:
        with target_path.open("rb") as f:
            data = f.read(MAX_ASSET_PREVIEW_BYTES + 1)
    except OSError as exc:
        logger.log_line(
            PREFIX_API,
            "ASSET_PREVIEW",
            "Failed to read asset preview from path %s: %s" % (target_path, exc),
            level="warning",
            exc_info=True,
        )
        return False, "", "Error reading asset: %s" % (exc,)

    truncated = len(data) > MAX_ASSET_PREVIEW_BYTES
    if truncated:
        data = data[:MAX_ASSET_PREVIEW_BYTES]

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False, "", "Asset is not UTF-8 text and cannot be previewed as text."

    message = "Preview truncated due to size limit." if truncated else ""
    return True, text, message


class GetFileContents(APIView):
    """Preview custom scan assets (GF patterns, Nuclei templates) only.

    Supported query params: gf_pattern, nuclei_template (with name=).
    Other config types (e.g. tool config files) are no longer supported and
    return 410 Gone with a migration_note so clients can detect the behavior change.
    """

    ASSET_PARAMS = {
        "gf_pattern": (RENGINE_GF_PATTERNS_DIR, "json"),
        "nuclei_template": (RENGINE_NUCLEI_TEMPLATES_DIR, "yaml"),
    }

    def get(self, request, format=None):
        req = self.request
        name = req.query_params.get("name", "")
        response = {"status": False}

        for param, (base_dir, extension) in self.ASSET_PARAMS.items():
            if param in req.query_params:
                success, content, message = _read_asset_preview(base_dir, name, extension)
                if success:
                    response["status"] = True
                    response["content"] = content
                    if message:
                        response["message"] = message
                else:
                    response["message"] = message or "Invalid path!"
                return Response(response)

        response["message"] = (
            "This API only supports gf_pattern and nuclei_template. Other config types are no longer supported."
        )
        response["migration_note"] = (
            "Previously this endpoint could serve other tool config files; "
            "it now only serves custom GF patterns and Nuclei templates. "
            "Use only query params gf_pattern or nuclei_template with name=."
        )
        logger.log_line(
            PREFIX_API,
            "GET_FILE_CONTENTS",
            "GetFileContents returned 410 Gone (unsupported params); query_params=%s" % (dict(req.query_params),),
            level="warning",
        )
        return Response(response, status=HTTP_410_GONE)


class GfList(APIView):
    def get(self, request):
        try:
            # NOTE: GF patterns functionality moved to Secator
            return Response({"status": False, "message": "GF patterns functionality moved to Secator"})
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "GF_LIST",
                "Error in GfList: %s" % (e,),
                level="error",
            )
            return Response({"error": "An unexpected error occurred. Please try again later."}, status=500)


class ListTodoNotes(APIView):
    def get(self, request, format=None):
        req = self.request
        notes = TodoNote.objects.all().order_by("-id")
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        project = req.query_params.get("project")
        if project:
            notes = notes.filter(project__slug=project)
        target_id = safe_int_cast(req.query_params.get("target_id"))
        todo_id = req.query_params.get("todo_id")
        subdomain_id = safe_int_cast(req.query_params.get("subdomain_id"))
        if target_id:
            notes = notes.filter(scan_history__in=ScanHistory.objects.filter(target_id=target_id))
        elif scan_id:
            notes = notes.filter(scan_history__id=scan_id)
        if todo_id:
            notes = notes.filter(id=todo_id)
        if subdomain_id:
            notes = notes.filter(subdomain__id=subdomain_id)

        notes = notes.select_related(
            "scan_history", "scan_history__target", "subdomain", "subdomain__domain", "project"
        )
        limit = parse_limit_from_request(request)
        total_count = notes.count()
        notes_slice = list(notes[:limit])
        serialized = ReconNoteSerializer(notes_slice, many=True)
        return Response(
            {
                "notes": serialized.data,
                "total_count": total_count,
                "limit": limit,
            }
        )


class ScanHistoryFilterChoices(APIView):
    """
    GET ?project=<slug> - Return filter dropdown choices for scan-history and subscan-history pages.

    Response: organizations (list of org names), scan_status_labels (for scan history),
    task_status_labels (for subscan history), targets, scan_engines.
    Used by history.html and subscan_history.html to populate all four filter selects
    (filterByOrganization, filterByScanStatus, filterByTarget, filterByScanType) from a single
    API call. Requires project query param. See wiki datatables-api-filters.md.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        project_slug = request.query_params.get("project")
        if not project_slug:
            return Response(
                {"detail": "Query param 'project' (project slug) is required."},
                status=HTTP_400_BAD_REQUEST,
            )
        qs = (
            ScanHistory.objects.filter(target__project__slug=project_slug)
            .filter(target__isnull=False)
            .values_list("target__value", "scan_type__engine_name")
            .distinct()
        )
        targets = sorted({v[0] for v in qs if v[0]}, key=str.lower)
        engines = sorted({v[1] for v in qs if v[1]}, key=str.lower)
        orgs = list(
            Organization.objects.for_project(project_slug).order_by("name").values_list("name", flat=True).distinct()
        )
        return Response(
            {
                "organizations": orgs,
                "scan_status_labels": get_scan_status_filter_labels(),
                "task_status_labels": get_task_status_filter_labels(),
                "targets": targets,
                "scan_engines": engines,
            }
        )


class ListScanHistory(APIView):
    """
    List scan history. Response format depends on presence of pagination params.

    - With pagination (start + length, or page + page_size): returns DataTables
      server-side format via build_datatables_serverside_response, with optional
      search, order, and filters (organization, status, target, scan_engine).
      Used by the Scan History DataTable (startScan/history.html).

    - Without pagination: returns full list as JSON array using ScanHistorySerializer
      (id, domain.name, start_scan_date, etc.). Used by the Recon note "Add Task"
      modal dropdown (recon_note/note/index.html) to populate "Select Scan History".

    Filter query params: filter_organization, filter_status, filter_target, filter_scan_engine.
    See wiki datatables-api-filters.md and api.helpers.datatables FILTER_PARAM_*.
    """

    def get(self, request, format=None):
        req = self.request
        qs = ScanHistory.objects.all().select_related("target", "initiated_by").prefetch_related("target__scopes")
        project = req.query_params.get("project")
        if project:
            qs = qs.filter(target__project__slug=project)

        pagination = parse_pagination_params(
            start=req.query_params.get("start"),
            length=req.query_params.get("length"),
            page=req.query_params.get("page"),
            page_size=req.query_params.get("page_size"),
        )
        if pagination:
            search_value = req.GET.get("search[value]", None)
            if search_value:
                qs = qs.filter(
                    Q(target__value__icontains=search_value) | Q(initiated_by__username__icontains=search_value)
                ).distinct()

            # Per-column search values from DataTables (individual column filters).
            target_search = get_datatables_column_search_value(req, DATATABLE_COLUMN_MAP_SCAN_HISTORY, "target__value")
            if target_search:
                qs = qs.filter(target__value__icontains=target_search)
            engine_search = get_datatables_column_search_value(
                req, DATATABLE_COLUMN_MAP_SCAN_HISTORY, "scan_type__engine_name"
            )
            if engine_search:
                qs = qs.filter(scan_type__engine_name__icontains=engine_search)
            initiated_by_search = get_datatables_column_search_value(
                req, DATATABLE_COLUMN_MAP_SCAN_HISTORY, "initiated_by__username"
            )
            if initiated_by_search:
                qs = qs.filter(initiated_by__username__icontains=initiated_by_search)

            qs = apply_filter_list_in_by_param(
                qs, req, FILTER_PARAM_ORGANIZATION, "target__organizations__name__in", distinct=True
            )
            qs = apply_filter_scan_status(qs, req)
            qs = apply_filter_list_in_by_param(qs, req, FILTER_PARAM_TARGET, "target__value__in")
            qs = apply_filter_list_in_by_param(qs, req, FILTER_PARAM_SCAN_ENGINE, "scan_type__engine_name__in")
            qs = apply_datatables_order(
                qs,
                req,
                DATATABLE_COLUMN_MAP_SCAN_HISTORY,
                default_order="-start_scan_date",
                nulls_last_fields=DATATABLE_NULLS_LAST_FIELDS,
            )
            qs = qs.distinct()
            total_count = qs.count()
            page_qs = qs[pagination["start"] : pagination["start"] + pagination["length"]]
            serializer = ScanHistoryDatatableSerializer(page_qs, many=True)
            return Response(build_datatables_serverside_response(req, total_count, total_count, serializer.data))

        qs = qs.order_by("-start_scan_date")
        serializer = ScanHistorySerializer(qs, many=True)
        return Response(serializer.data)


class ListEngines(APIView):
    def get(self, request):
        engine_id = request.GET.get("engine_id")
        if engine_id:
            # Validate engine_id is a valid integer
            engine_id_int = safe_int_cast(engine_id)
            if engine_id_int is None:
                logger.log_line(
                    PREFIX_API,
                    "LIST_ENGINES",
                    "Invalid engine_id query parameter received: %s" % (engine_id,),
                    level="warning",
                )
                return Response(
                    {"detail": "Invalid engine_id parameter."},
                    status=HTTP_400_BAD_REQUEST,
                )
            engines = EngineType.objects.filter(id=engine_id_int)
        else:
            engines = EngineType.objects.all()

        serializer = EngineSerializer(engines.order_by("engine_name"), many=True)
        return Response({"engines": serializer.data})


class ListOrganizations(APIView):
    """List organizations. When project (slug) is provided, returns only organizations for that project."""

    def get(self, request, format=None):
        project_slug = request.query_params.get("project")
        if project_slug:
            organizations = Organization.objects.for_project(project_slug).order_by("name")
        else:
            organizations = Organization.objects.all().order_by("name")
        organization_serializer = OrganizationSerializer(organizations, many=True)
        return Response({"organizations": organization_serializer.data})


class ListScopes(APIView):
    """List scope names for filter dropdowns. When project (slug) is provided, returns only scopes for that project."""

    def get(self, request, format=None):
        project_slug = request.query_params.get("project")
        if project_slug:
            scopes = Scope.objects.filter(organization__project__slug=project_slug).order_by("name").values("name")
        else:
            scopes = Scope.objects.all().order_by("name").values("name")
        scopes_list = [{"name": s["name"]} for s in scopes]
        return Response({"scopes": scopes_list})


class ListTargetsInOrganization(APIView):
    def get(self, request, format=None):
        req = self.request
        organization_id = safe_int_cast(req.query_params.get("organization_id"))
        try:
            organization = Organization.objects.get(id=organization_id)
            targets = Domain.objects.filter(scan_history__target__organizations=organization)
            organization_serializer = OrganizationSerializer(organization)
            targets_serializer = OrganizationTargetsSerializer(targets, many=True)
            return Response({"organization": organization_serializer.data, "domains": targets_serializer.data})
        except Organization.DoesNotExist:
            return Response({"error": "Organization not found"}, status=404)


class ListTargetsWithoutOrganization(APIView):
    def get(self, request, format=None):
        targets = Domain.objects.exclude(scan_history__target__organizations__in=Organization.objects.all())
        targets_serializer = OrganizationTargetsSerializer(targets, many=True)
        return Response({"domains": targets_serializer.data})


class VisualiseData(APIView):
    def get(self, request, format=None):
        req = self.request
        if scan_id := safe_int_cast(req.query_params.get("scan_id")):
            mitch_data = ScanHistory.objects.filter(id=scan_id)
            serializer = VisualiseDataSerializer(mitch_data, many=True)

            # Data processing to remove duplicates
            processed_data = self.process_visualisation_data(serializer.data)

            return Response(processed_data)
        else:
            return Response()

    def process_visualisation_data(self, data):
        if not data:
            return []

        processed_data = data[0]  # Assuming there's only one element in data
        subdomains = processed_data.get("subdomains", [])

        # Use a dictionary to group vulnerabilities by subdomain
        vuln_by_subdomain = defaultdict(list)

        for subdomain in subdomains:
            subdomain_name = subdomain["name"]
            vulnerabilities = subdomain.get("vulnerabilities", [])

            # Group unique vulnerabilities
            unique_vulns = {}
            for vuln in vulnerabilities:
                vuln_key = (vuln["name"], vuln["severity"])
                if vuln_key not in unique_vulns:
                    unique_vulns[vuln_key] = vuln

            vuln_by_subdomain[subdomain_name].extend(unique_vulns.values())

        # Update subdomains with unique vulnerabilities
        for subdomain in subdomains:
            subdomain["vulnerabilities"] = vuln_by_subdomain[subdomain["name"]]

        return processed_data


class ListTechnology(APIView):
    def get(self, request, format=None):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))

        # Single subdomain filter reused for both count subquery and Technology filter to avoid drift.
        if target_id := safe_int_cast(req.query_params.get("target_id")):
            subdomain_filter = Subdomain.objects.filter(domain__scan_history__target_id=target_id)
        elif scan_id:
            subdomain_filter = Subdomain.objects.filter(scan_history__id=scan_id)
        else:
            subdomain_filter = Subdomain.objects.all()

        through = Subdomain.technologies.through
        subdomain_id_subquery = Subquery(subdomain_filter.values("id"))
        # Scalar count subquery avoids cartesian products when counting tech usage per subdomain set.
        tech_count_annot = count_subquery(
            through,
            "technology_id",
            filter_kwargs={"subdomain_id__in": subdomain_id_subquery},
        )
        tech_qs = (
            Technology.objects.filter(technologies__in=subdomain_filter)
            .annotate(count=tech_count_annot)
            .order_by("-count")
        )
        limit = parse_limit_from_request(request)
        total_count = tech_qs.count()
        tech = list(tech_qs[:limit])
        serializer = TechnologyCountSerializer(tech, many=True)
        return Response(
            {
                "technologies": serializer.data,
                "total_count": total_count,
                "limit": limit,
            }
        )


class ListDorkTypes(APIView):
    def get(self, request, format=None):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        if scan_id:
            dork = (
                Dork.objects.filter(dorks__in=ScanHistory.objects.filter(id=scan_id))
                .values("type")
                .annotate(count=Count("type"))
                .order_by("-count")
            )
            serializer = DorkCountSerializer(dork, many=True)
            return Response({"dorks": serializer.data})
        else:
            dork = (
                Dork.objects.filter(dorks__in=ScanHistory.objects.all())
                .values("type")
                .annotate(count=Count("type"))
                .order_by("-count")
            )
            serializer = DorkCountSerializer(dork, many=True)
            return Response({"dorks": serializer.data})


class ListEmails(APIView):
    def get(self, request, format=None):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        if scan_id:
            email = Email.objects.filter(emails__in=ScanHistory.objects.filter(id=scan_id)).order_by("password")
            serializer = EmailSerializer(email, many=True)
            return Response({"emails": serializer.data})


class ListDorks(APIView):
    def get(self, request, format=None):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        type = req.query_params.get("type")
        if scan_id:
            dork = Dork.objects.filter(dorks__in=ScanHistory.objects.filter(id=scan_id))
        else:
            dork = Dork.objects.filter(dorks__in=ScanHistory.objects.all())
        if scan_id and type:
            dork = dork.filter(type=type)
        serializer = DorkSerializer(dork, many=True)
        grouped_res = {}
        for item in serializer.data:
            item_type = item["type"]
            if item_type not in grouped_res:
                grouped_res[item_type] = []
            grouped_res[item_type].append(item)
        return Response({"dorks": grouped_res})


class ListEmployees(APIView):
    def get(self, request, format=None):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        if scan_id:
            employee = Employee.objects.filter(employees__in=ScanHistory.objects.filter(id=scan_id))
            serializer = EmployeeSerializer(employee, many=True)
            return Response({"employees": serializer.data})


class ListPorts(APIView):
    def get(self, request, format=None):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        target_id = safe_int_cast(req.query_params.get("target_id"))
        ip_address = req.query_params.get("ip_address")

        # Build the base query
        port_query = Port.objects.all()

        # Filter based on parameters
        if target_id:
            port_query = port_query.filter(
                ip_address__ip_addresses__domain__scan_history__target_id=target_id
            ).distinct()
        elif scan_id:
            port_query = port_query.filter(ip_address__ip_addresses__scan_history__id=scan_id).distinct()

        if ip_address:
            port_query = port_query.filter(ip_address__address=ip_address)

        # Grouping information
        ports_data = []
        ports_data.extend(
            {
                "number": port.number,
                "service_name": port.service_name,
                "description": port.description,
                "is_uncommon": port.is_uncommon,
            }
            for port in port_query.distinct()
        )
        return Response({"ports": ports_data})


class ListSubdomains(AdvancedSearchMixin, APIView):
    search_config = {
        "general_fields": [
            lambda sv: Q(name__icontains=sv),
            lambda sv: Q(cname__icontains=sv),
            lambda sv: Q(http_status__icontains=sv),
            lambda sv: Q(page_title__icontains=sv),
            lambda sv: Q(http_url__icontains=sv),
            lambda sv: Q(technologies__name__icontains=sv),
            lambda sv: Q(webserver__icontains=sv),
            lambda sv: Q(ip_addresses__address__icontains=sv),
        ],
        "special_fields": {
            "name": "name__icontains",
            "page_title": "page_title__icontains",
            "technology": "technologies__name__icontains",
            "webserver": "webserver__icontains",
        },
        "numeric_fields": {
            "http_status": "http_status",
        },
        "boolean_fields": {
            "is_important": ("is_important", "true", "false"),
        },
    }

    def get(self, request, format=None):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        project = req.query_params.get("project")
        target_id = safe_int_cast(req.query_params.get("target_id"))
        ip_address = req.query_params.get("ip_address")
        port = req.query_params.get("port")
        tech = req.query_params.get("tech")

        subdomains = (
            Subdomain.objects.filter(domain__scan_history__target__project__slug=project)
            if project
            else Subdomain.objects.all()
        )

        if scan_id:
            subdomain_query = subdomains.filter(scan_history__id=scan_id).distinct("name")
        elif target_id:
            subdomain_query = subdomains.filter(domain__scan_history__target_id=target_id).distinct("name")
        else:
            subdomain_query = subdomains.all().distinct("name")

        if ip_address:
            subdomain_query = subdomain_query.filter(ip_addresses__address=ip_address)

        if tech:
            subdomain_query = subdomain_query.filter(technologies__name=tech)

        if port:
            subdomain_query = subdomain_query.filter(ip_addresses__ports__number=port).distinct("name")

        if "only_important" in req.query_params:
            subdomain_query = subdomain_query.filter(is_important=True)

        # Advanced search functionality (similar to EndPointViewSet)
        search_value = req.GET.get("search[value]", None)
        if search_value:
            subdomain_query = self.apply_advanced_search(subdomain_query, search_value)

        # Optimize queries with select_related and prefetch_related to avoid N+1 queries
        subdomain_query = subdomain_query.select_related("scan_history", "domain").prefetch_related(
            "ip_addresses",
            "ip_addresses__ports",
            "technologies",
            "waf",
            "directories",
            Prefetch(
                "endpoint_set",
                queryset=EndPoint.objects.filter(is_default=True),
                to_attr="default_endpoint_list",
            ),
        )

        # Handle pagination
        pagination = parse_pagination_params(
            start=req.query_params.get("start"),
            length=req.query_params.get("length"),
            page=req.query_params.get("page"),
            page_size=req.query_params.get("page_size"),
        )

        serializer_context = {}
        if scan_id and "no_lookup_interesting" not in req.query_params:
            interesting = get_interesting_subdomains(scan_history=scan_id)
            serializer_context["datatable_interesting_names"] = set(interesting.values_list("name", flat=True))

        if pagination:
            total_count = subdomain_query.count()
            paginated_queryset = subdomain_query[pagination["start"] : pagination["start"] + pagination["length"]]

            if "no_lookup_interesting" in req.query_params:
                serializer = OnlySubdomainNameSerializer(paginated_queryset, many=True)
            else:
                serializer = SubdomainSerializer(paginated_queryset, many=True, context=serializer_context)

            return Response(build_datatables_serverside_response(req, total_count, total_count, serializer.data))

        # Default response (no pagination) - use shared limit parsing and return total_count/limit
        limit = parse_limit_from_request(req)
        total_count = subdomain_query.count()
        subdomain_slice = list(subdomain_query[:limit])
        if "no_lookup_interesting" in req.query_params:
            serializer = OnlySubdomainNameSerializer(subdomain_slice, many=True)
        else:
            serializer = SubdomainSerializer(subdomain_slice, many=True, context=serializer_context)
        return Response({"subdomains": serializer.data, "total_count": total_count, "limit": limit})

    def post(self, req):
        req = self.request
        data = req.data

        subdomain_ids = data.get("subdomain_ids")

        subdomain_names = []

        for id in subdomain_ids:
            subdomain_names.append(Subdomain.objects.get(id=id).name)

        if subdomain_names:
            return Response({"status": True, "results": subdomain_names})

        return Response({"status": False})


class ListOsintUsers(APIView):
    def get(self, request, format=None):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        if scan_id:
            documents = (
                MetaFinderDocument.objects.filter(scan_history__id=scan_id)
                .exclude(author__isnull=True)
                .values("author")
                .distinct()
            )
            serializer = MetafinderUserSerializer(documents, many=True)
            return Response({"users": serializer.data})


class ListMetadata(APIView):
    def get(self, request, format=None):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        if scan_id:
            documents = MetaFinderDocument.objects.filter(scan_history__id=scan_id).distinct()
            serializer = MetafinderDocumentSerializer(documents, many=True)
            return Response({"metadata": serializer.data})


class ListIPs(APIView):
    def get(self, request, format=None):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        target_id = safe_int_cast(req.query_params.get("target_id"))
        port = req.query_params.get("port")

        if target_id:
            ips = IpAddress.objects.filter(
                ip_addresses__in=Subdomain.objects.filter(domain__scan_history__target_id=target_id)
            ).distinct()
        elif scan_id:
            ips = IpAddress.objects.filter(
                ip_addresses__in=Subdomain.objects.filter(scan_history__id=scan_id)
            ).distinct()
        else:
            ips = IpAddress.objects.filter(ip_addresses__in=Subdomain.objects.all()).distinct()

        if port:
            ips = ips.filter(ports__in=Port.objects.filter(number=port)).distinct()

        pagination = parse_pagination_params(
            start=req.query_params.get("start"),
            length=req.query_params.get("length"),
            page=req.query_params.get("page"),
            page_size=req.query_params.get("page_size"),
        )
        if pagination:
            search_value = (req.GET.get("search[value]") or "").strip()
            if search_value:
                ips = ips.filter(address__icontains=search_value)
            order_str = get_datatables_order_column(req, DATATABLE_COLUMN_MAP_IPS, default_order="address")
            ips = ips.order_by(order_str)
            total_count = ips.count()
            paginated = list(ips[pagination["start"] : pagination["start"] + pagination["length"]])
            ip_subdomain_data = get_ip_subdomain_data(paginated)
            serializer = IpSerializer(
                paginated,
                many=True,
                context={
                    "ip_subdomain_data": ip_subdomain_data,
                    "scan_id": scan_id,
                    "target_id": target_id,
                },
            )
            return Response(build_datatables_serverside_response(req, total_count, total_count, serializer.data))

        ip_subdomain_data = get_ip_subdomain_data(ips)
        serializer = IpSerializer(
            ips,
            many=True,
            context={
                "ip_subdomain_data": ip_subdomain_data,
                "scan_id": scan_id,
                "target_id": target_id,
            },
        )
        return Response({"ips": serializer.data})


class IpAddressViewSet(DatatablePaginationMixin, viewsets.ModelViewSet):
    queryset = Subdomain.objects.none()
    serializer_class = IpSubdomainSerializer
    ordering = ("name",)
    datatable_default_ordering = ("name",)

    def get_queryset(self):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))

        if scan_id:
            self.queryset = (
                Subdomain.objects.filter(scan_history__id=scan_id).exclude(ip_addresses__isnull=True).distinct()
            )
        else:
            self.serializer_class = IpSerializer
            self.queryset = IpAddress.objects.all()
        return self.queryset

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        objs = page if page is not None else queryset

        context = self.get_serializer_context()
        if self.get_serializer_class() == IpSerializer:
            context["ip_subdomain_data"] = get_ip_subdomain_data(objs)

        serializer = self.get_serializer(objs, many=True, context=context)

        if page is not None:
            return self.get_paginated_response(serializer.data)
        return Response(serializer.data)


class SubdomainsViewSet(DatatablePaginationMixin, viewsets.ModelViewSet):
    queryset = Subdomain.objects.none()
    serializer_class = SubdomainSerializer
    ordering = ("name",)
    datatable_default_ordering = ("name",)

    def get_queryset(self):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        if scan_id:
            if "only_screenshot" in self.request.query_params:
                # Get subdomains that have endpoints with screenshots
                endpoint_subdomains = (
                    EndPoint.objects.filter(scan_history__id=scan_id, screenshot_path__isnull=False)
                    .values_list("subdomain", flat=True)
                    .distinct()
                )
                queryset = Subdomain.objects.filter(scan_history__id=scan_id).filter(id__in=endpoint_subdomains)
            else:
                queryset = Subdomain.objects.filter(scan_history=scan_id)

            # Optimize queries with prefetch_related to avoid N+1 queries
            queryset = queryset.prefetch_related(
                "ip_addresses",
                "ip_addresses__ports",
                "technologies",
                "waf",
                "directories",
                "scan_history",
                "domain",
                Prefetch(
                    "endpoint_set",
                    queryset=EndPoint.objects.filter(is_default=True),
                    to_attr="default_endpoint_list",
                ),
            )
            return queryset
        return Subdomain.objects.none()


class SubdomainChangesViewSet(DatatableListMixin, DatatablePaginationMixin, viewsets.ModelViewSet):
    """
    This viewset will return the Subdomain changes
    To get the new subdomains, we will look for ScanHistory with
    subdomain_discovery = True and the status of the last scan has to be
    successful and calculate difference
    """

    queryset = Subdomain.objects.none()
    serializer_class = SubdomainChangesSerializer
    ordering = ("name",)
    filter_backends = []

    datatable_column_map = DATATABLE_COLUMN_MAP_SUBDOMAIN_CHANGES

    def filter_queryset(self, qs):
        if not hasattr(qs, "filter"):
            return qs
        search_value = self.request.GET.get("search[value]", None)
        if search_value:
            qs = qs.filter(
                Q(name__icontains=search_value)
                | Q(page_title__icontains=search_value)
                | Q(http_status__icontains=search_value)
            )
        return apply_datatables_order(qs, self.request, self.datatable_column_map, default_order="content_length")

    datatable_default_ordering = None

    def get_queryset(self):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        target_id = safe_int_cast(req.query_params.get("target_id"))
        project = req.query_params.get("project")

        if scan_id:
            current_scan = ScanHistory.objects.filter(id=scan_id).select_related("target").first()
            if not current_scan or not current_scan.target_id:
                return Subdomain.objects.none()
            scans_with_subdomain_discovery = (
                ScanHistory.objects.filter(target_id=current_scan.target_id)
                .filter(tasks__overlap=["subdomain_discovery"])
                .filter(scan_status=2)  # SUCCESS
                .order_by("-start_scan_date")[:2]
            )
            scans_list = list(scans_with_subdomain_discovery)
            if len(scans_list) >= 2:
                previous_scan = scans_list[1]

                # Get subdomains from current scan
                current_subdomains = (
                    Subdomain.objects.filter(scan_history=current_scan).values_list("name", flat=True).distinct()
                )

                # Get subdomains from previous scan
                previous_subdomains = (
                    Subdomain.objects.filter(scan_history=previous_scan).values_list("name", flat=True).distinct()
                )

                # Calculate new subdomains
                new_subdomains = set(current_subdomains) - set(previous_subdomains)

                # Get the actual subdomain objects for new subdomains
                queryset = (
                    Subdomain.objects.filter(scan_history=current_scan)
                    .filter(name__in=new_subdomains)
                    .annotate(change=Value("added", output_field=CharField()))
                    .select_related("scan_history", "domain")
                )
            else:
                queryset = Subdomain.objects.none()
        elif target_id:
            queryset = (
                Subdomain.objects.filter(domain__scan_history__target_id=target_id)
                .select_related("domain")
                .annotate(change=Value("unknown", output_field=CharField()))
            )
        elif project:
            queryset = (
                Subdomain.objects.filter(domain__scan_history__target__project__slug=project)
                .select_related("domain")
                .annotate(change=Value("unknown", output_field=CharField()))
            )
        else:
            queryset = (
                Subdomain.objects.all()
                .select_related("domain")
                .annotate(change=Value("unknown", output_field=CharField()))
            )

        # domain is a FK: use select_related only (already applied above). Prefetch M2M and reverse relations.
        queryset = queryset.prefetch_related(
            "ip_addresses", "ip_addresses__ports", "technologies", "waf", "directories", "scan_history"
        )

        return queryset


class EndPointChangesViewSet(DatatableListMixin, DatatablePaginationMixin, viewsets.ModelViewSet):
    """
    This viewset will return the EndPoint changes
    """

    queryset = EndPoint.objects.none()
    serializer_class = EndPointChangesSerializer
    ordering = ("http_url",)
    filter_backends = []
    datatable_default_ordering = None

    datatable_column_map = DATATABLE_COLUMN_MAP_ENDPOINT_CHANGES

    def filter_queryset(self, qs):
        if not hasattr(qs, "filter"):
            return qs
        search_value = self.request.GET.get("search[value]", None)
        if search_value:
            qs = qs.filter(
                Q(http_url__icontains=search_value)
                | Q(page_title__icontains=search_value)
                | Q(http_status__icontains=search_value)
            )
        return apply_datatables_order(qs, self.request, self.datatable_column_map, default_order="content_length")

    def get_queryset(self):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        if not scan_id:
            return EndPoint.objects.none()
        changes = req.query_params.get("changes")
        scan = ScanHistory.objects.filter(id=scan_id).select_related("target").first()
        if not scan or not scan.target_id:
            return EndPoint.objects.none()
        scan_history = (
            ScanHistory.objects.filter(target_id=scan.target_id)
            .filter(tasks__overlap=["subdomain_discovery"])
            .filter(id__lte=scan_id)
            .exclude(Q(scan_status=-1) | Q(scan_status=1))
            .order_by("-start_scan_date")
        )
        scans_list = list(scan_history[:2])
        if len(scans_list) < 2:
            return EndPoint.objects.none()
        last_scan = scans_list[1]
        scanned_host_q1 = EndPoint.objects.filter(scan_history__id=scan_id).values("http_url")
        scanned_host_q2 = EndPoint.objects.filter(scan_history__id=last_scan.id).values("http_url")
        added_endpoint = scanned_host_q1.difference(scanned_host_q2)
        removed_endpoints = scanned_host_q2.difference(scanned_host_q1)
        endpoint_base = EndPoint.objects.select_related("subdomain", "domain", "scan_history").prefetch_related("techs")
        if changes == "added":
            return (
                endpoint_base.filter(scan_history__id=scan_id)
                .filter(http_url__in=added_endpoint)
                .annotate(change=Value("added", output_field=CharField()))
            )
        elif changes == "removed":
            return (
                endpoint_base.filter(scan_history__id=last_scan.id)
                .filter(http_url__in=removed_endpoints)
                .annotate(change=Value("removed", output_field=CharField()))
            )
        else:
            added_qs = (
                endpoint_base.filter(scan_history__id=scan_id)
                .filter(http_url__in=added_endpoint)
                .annotate(change=Value("added", output_field=CharField()))
            )
            removed_qs = (
                endpoint_base.filter(scan_history__id=last_scan.id)
                .filter(http_url__in=removed_endpoints)
                .annotate(change=Value("removed", output_field=CharField()))
            )
            added_ids = list(added_qs.values_list("pk", flat=True))
            removed_ids = list(removed_qs.values_list("pk", flat=True))
            union_ids = added_ids + removed_ids
            if not union_ids:
                return EndPoint.objects.none()
            ordering = getattr(self, "ordering", None) or ("http_url",)
            return (
                endpoint_base.filter(pk__in=union_ids)
                .annotate(
                    change=Case(
                        When(pk__in=added_ids, then=Value("added", output_field=CharField())),
                        When(pk__in=removed_ids, then=Value("removed", output_field=CharField())),
                        default=Value("", output_field=CharField()),
                        output_field=CharField(),
                    )
                )
                .order_by(*ordering)
            )


class InterestingSubdomainViewSet(DatatableListMixin, DatatablePaginationMixin, viewsets.ModelViewSet):
    queryset = Subdomain.objects.none()
    serializer_class = SubdomainSerializer
    ordering = ("name",)
    filter_backends = []
    datatable_default_ordering = None

    datatable_column_map = DATATABLE_COLUMN_MAP_INTERESTING_SUBDOMAIN

    def get_queryset(self):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        target_id = safe_int_cast(req.query_params.get("target_id"))

        if "only_subdomains" in self.request.query_params:
            self.serializer_class = InterestingSubdomainSerializer

        if scan_id:
            queryset = get_interesting_subdomains(scan_history=scan_id)
        elif target_id:
            queryset = get_interesting_subdomains(target_id=target_id)
        else:
            queryset = get_interesting_subdomains()

        # Cache interesting names for serializer context to avoid running get_interesting_subdomains twice
        if scan_id or target_id:
            self._datatable_interesting_names = set(queryset.values_list("name", flat=True))
        else:
            self._datatable_interesting_names = None

        # domain is FK: use select_related. Then prefetch M2M/reverse relations.
        if hasattr(queryset, "select_related"):
            queryset = queryset.select_related("domain")
        if hasattr(queryset, "prefetch_related"):
            queryset = queryset.prefetch_related(
                "ip_addresses",
                "ip_addresses__ports",
                "technologies",
                "waf",
                "directories",
                "scan_history",
            )

        self.queryset = queryset

        return self.queryset

    def get_serializer_context(self):
        context = super().get_serializer_context()
        if getattr(self, "_datatable_interesting_names", None) is not None:
            context["datatable_interesting_names"] = self._datatable_interesting_names
        return context

    def filter_queryset(self, qs):
        if not hasattr(qs, "filter"):
            return qs
        search_value = self.request.GET.get("search[value]", None)
        if search_value:
            qs = qs.filter(
                Q(name__icontains=search_value)
                | Q(page_title__icontains=search_value)
                | Q(http_status__icontains=search_value)
            )
        return apply_datatables_order(qs, self.request, self.datatable_column_map, default_order="content_length")


class InterestingEndpointViewSet(DatatableListMixin, DatatablePaginationMixin, viewsets.ModelViewSet):
    queryset = EndPoint.objects.none()
    serializer_class = EndpointSerializer
    ordering = ("http_url",)
    filter_backends = []
    datatable_default_ordering = None

    datatable_column_map = DATATABLE_COLUMN_MAP_INTERESTING_ENDPOINT

    def filter_queryset(self, qs):
        if not hasattr(qs, "filter"):
            return qs
        search_value = self.request.GET.get("search[value]", None)
        if search_value:
            qs = qs.filter(
                Q(http_url__icontains=search_value)
                | Q(page_title__icontains=search_value)
                | Q(http_status__icontains=search_value)
            )
        return apply_datatables_order(qs, self.request, self.datatable_column_map, default_order="http_url")

    def get_queryset(self):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        target_id = safe_int_cast(req.query_params.get("target_id"))

        if "only_endpoints" in self.request.query_params:
            self.serializer_class = InterestingEndPointSerializer
        if scan_id:
            queryset = get_interesting_endpoints(scan_history=scan_id)
        elif target_id:
            queryset = get_interesting_endpoints(target_id=target_id)
        else:
            queryset = EndPoint.objects.none()

        # FKs: select_related. M2M: prefetch_related (techs, endpoint_subscan_ids).
        if hasattr(queryset, "select_related"):
            queryset = queryset.select_related("subdomain", "subdomain__domain", "domain", "scan_history")
        if hasattr(queryset, "prefetch_related"):
            queryset = queryset.prefetch_related("techs", "endpoint_subscan_ids")

        return queryset


class SubdomainDatatableViewSet(
    DatatableListMixin, DatatablePaginationMixin, AdvancedSearchMixin, viewsets.ModelViewSet
):
    queryset = Subdomain.objects.none()
    serializer_class = SubdomainSerializer
    filter_backends = []
    datatable_default_ordering = ("id",)

    def _port_search_handler(self, queryset, operator, value):
        """Custom handler for port searches across multiple port fields."""
        if operator == "=":
            return (
                queryset.filter(ip_addresses__ports__number__icontains=value)
                | queryset.filter(ip_addresses__ports__service_name__icontains=value)
                | queryset.filter(ip_addresses__ports__description__icontains=value)
            )
        elif operator == "!":
            return (
                queryset.exclude(ip_addresses__ports__number__icontains=value)
                | queryset.exclude(ip_addresses__ports__service_name__icontains=value)
                | queryset.exclude(ip_addresses__ports__description__icontains=value)
            )
        return queryset

    search_config = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.search_config = {
            "general_fields": [
                lambda sv: Q(name__icontains=sv),
                lambda sv: Q(cname__icontains=sv),
                lambda sv: Q(http_status__icontains=sv),
                lambda sv: Q(page_title__icontains=sv),
                lambda sv: Q(http_url__icontains=sv),
                lambda sv: Q(technologies__name__icontains=sv),
                lambda sv: Q(webserver__icontains=sv),
                lambda sv: Q(ip_addresses__address__icontains=sv),
                lambda sv: Q(ip_addresses__ports__number__icontains=sv),
                lambda sv: Q(ip_addresses__ports__service_name__icontains=sv),
                lambda sv: Q(ip_addresses__ports__description__icontains=sv),
            ],
            "special_fields": {
                "name": "name__icontains",
                "page_title": "page_title__icontains",
                "http_url": "http_url__icontains",
                "content_type": "content_type__icontains",
                "cname": "cname__icontains",
                "webserver": "webserver__icontains",
                "ip_addresses": "ip_addresses__address__icontains",
                "technology": "technologies__name__icontains",
            },
            "numeric_fields": {
                "http_status": "http_status",
                "content_length": "content_length",
            },
            "boolean_fields": {
                "is_important": ("is_important", "true", "false"),
            },
            "custom_handlers": {
                "port": self._port_search_handler,
            },
        }

    def get_queryset(self):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        target_id = safe_int_cast(req.query_params.get("target_id"))
        self._datatable_scan_id = scan_id
        queryset, self._datatable_interesting_names = build_subdomain_datatable_queryset(
            project_slug=req.query_params.get("project", ""),
            scan_id=scan_id,
            target_id=target_id,
            url_query=req.query_params.get("query_param"),
            ip_address=req.query_params.get("ip_address"),
            name=req.query_params.get("name"),
            is_important="is_important" in req.query_params,
            only_directory="only_directory" in req.query_params,
        )
        self.queryset = queryset
        return self.queryset

    def general_lookup(self, queryset, search_value):
        """Override to add only_directory support."""
        qs = super().general_lookup(queryset, search_value)
        if "only_directory" in self.request.query_params:
            qs = qs | queryset.filter(Q(directories__directory_files__name__icontains=search_value))
        return qs

    datatable_column_map = DATATABLE_COLUMN_MAP_SUBDOMAIN

    def filter_queryset(self, qs):
        qs = self.queryset.filter()
        search_value = self.request.GET.get("search[value]", None)
        if search_value:
            qs = self.apply_advanced_search(qs, search_value)
        qs = apply_filter_list_in(
            qs, "http_status__in", get_request_filter_list(self.request, FILTER_PARAM_HTTP_STATUS)
        )
        qs = apply_filter_list_in(qs, "page_title__in", get_request_filter_list(self.request, FILTER_PARAM_PAGE_TITLE))
        qs = apply_filter_list_in(qs, "name__in", get_request_filter_list(self.request, FILTER_PARAM_SUBDOMAIN))
        order_str = get_datatables_order_column(self.request, self.datatable_column_map, default_order="content_length")
        return qs.order_by(order_str)

    def get_serializer_context(self):
        context = super().get_serializer_context()
        if getattr(self, "_datatable_interesting_names", None) is not None:
            context["datatable_interesting_names"] = self._datatable_interesting_names
        return context


class ListActivityLogsViewSet(viewsets.ModelViewSet):
    serializer_class = CommandSerializer
    queryset = Command.objects.none()

    def get_queryset(self):
        req = self.request
        activity_id = safe_int_cast(req.query_params.get("activity_id"))
        self.queryset = Command.objects.filter(activity__id=activity_id).order_by("id")
        return self.queryset


class ListScanLogsViewSet(viewsets.ModelViewSet):
    serializer_class = CommandSerializer
    queryset = Command.objects.none()

    def get_queryset(self):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        include_pending = req.query_params.get("include_pending", "false").lower() == "true"

        queryset = Command.objects.filter(scan_history__id=scan_id)

        # Exclude PENDING status by default unless include_pending is true
        if not include_pending:
            queryset = queryset.filter(~Q(status="PENDING") | Q(status__isnull=True))

        # Push ordering into the database so we don't have to materialize and sort
        # a large queryset in Python. Order first by hierarchy type, then by
        # grouping key (ancestor_id/workflow_name), and finally by a stable timestamp/id.
        type_order_case = Case(
            When(runner_type="scan", then=Value(0)),
            When(runner_type="workflow", then=Value(1)),
            When(runner_type="task", then=Value(2)),
            default=Value(3),
            output_field=IntegerField(),
        )

        queryset = queryset.annotate(
            type_order=type_order_case,
            # Use ancestor_id for tasks, workflow_name for workflows, None for scans
            group_key=Coalesce(
                F("ancestor_id"),
                F("workflow_name"),
                F("name"),
                Value(""),
            ),
        ).order_by(
            "type_order",
            "group_key",
            "time",
            "id",
        )

        # Store sorted list for serializer context (used for indent calculation)
        # but return queryset to maintain DRF compatibility
        self.sorted_commands = list(queryset)
        return queryset

    def get_serializer_context(self):
        """Add all commands to context for indent_level calculation."""
        context = super().get_serializer_context()
        # Use the pre-computed sorted list instead of calling get_queryset again
        context["all_commands"] = getattr(self, "sorted_commands", [])
        return context


class ListEndpoints(APIView):
    def get(self, request, format=None):
        req = self.request

        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        target_id = safe_int_cast(req.query_params.get("target_id"))
        subdomain_name = req.query_params.get("subdomain_name")
        pattern = req.query_params.get("pattern")

        if scan_id:
            endpoints = EndPoint.objects.filter(scan_history__id=scan_id)
        elif target_id:
            endpoints = EndPoint.objects.filter(domain__scan_history__target_id=target_id).distinct()
        else:
            endpoints = EndPoint.objects.all()

        if subdomain_name:
            endpoints = endpoints.filter(subdomain__name=subdomain_name)

        if pattern:
            endpoints = endpoints.filter(matched_gf_patterns__icontains=pattern)

        if "only_urls" in req.query_params:
            endpoints_serializer = EndpointOnlyURLsSerializer(endpoints, many=True)

        else:
            endpoints_serializer = EndpointSerializer(endpoints, many=True)

        return Response({"endpoints": endpoints_serializer.data})


class ListCertificates(APIView):
    """List certificates for a subdomain (for certificate modal)."""

    def get(self, request, format=None):
        req = self.request
        subdomain_id = safe_int_cast(req.query_params.get("subdomain_id"))
        scan_id = safe_int_cast(req.query_params.get("scan_id"))

        if not subdomain_id:
            return Response(
                {"detail": "subdomain_id is required"},
                status=HTTP_400_BAD_REQUEST,
            )

        certificates = Certificate.objects.filter(subdomain_id=subdomain_id)
        if scan_id is not None:
            certificates = certificates.filter(scan_history_id=scan_id)
        certificates = certificates.order_by("-discovered_date")

        serializer = CertificateSerializer(certificates, many=True)
        return Response({"certificates": serializer.data})


class EndPointViewSet(DatatableListMixin, DatatablePaginationMixin, AdvancedSearchMixin, viewsets.ModelViewSet):
    queryset = EndPoint.objects.none()
    serializer_class = EndpointSerializer
    datatable_default_ordering = ("id",)
    search_config = {
        "general_fields": [
            lambda sv: Q(http_url__icontains=sv),
            lambda sv: Q(page_title__icontains=sv),
            lambda sv: Q(http_status__icontains=sv),
            lambda sv: Q(content_type__icontains=sv),
            lambda sv: Q(webserver__icontains=sv),
            lambda sv: Q(techs__name__icontains=sv),
            lambda sv: Q(matched_gf_patterns__icontains=sv),
        ],
        "special_fields": {
            "http_url": "http_url__icontains",
            "page_title": "page_title__icontains",
            "content_type": "content_type__icontains",
            "webserver": "webserver__icontains",
            "technology": "techs__name__icontains",
            "gf_pattern": "matched_gf_patterns__icontains",
        },
        "numeric_fields": {
            "http_status": "http_status",
            "content_length": "content_length",
        },
        "boolean_fields": {},
        "custom_handlers": {},
    }

    def get_queryset(self):
        req = self.request

        scan_id = safe_int_cast(req.query_params.get("scan_history")) or safe_int_cast(req.query_params.get("scan_id"))
        target_id = safe_int_cast(req.query_params.get("target_id"))
        url_query = req.query_params.get("query_param")
        subdomain_id = safe_int_cast(req.query_params.get("subdomain_id"))
        project = req.query_params.get("project")

        endpoints_obj = EndPoint.objects.filter(scan_history__target__project__slug=project)

        gf_tag = req.query_params.get("gf_tag") if "gf_tag" in req.query_params else None

        # Start with base query without ordering
        endpoints = endpoints_obj

        if scan_id:
            endpoints = endpoints.filter(scan_history__id=scan_id)

        if url_query:
            endpoints = endpoints.filter(Q(domain__name=url_query))

        if gf_tag:
            endpoints = endpoints.filter(matched_gf_patterns__icontains=gf_tag)

        if target_id:
            endpoints = endpoints.filter(domain__scan_history__target_id=target_id)

        if subdomain_id:
            endpoints = endpoints.filter(subdomain__id=subdomain_id)

        # Get unique endpoints by http_url, keeping the latest (highest ID) for each URL
        # Use a subquery to get the latest ID for each unique http_url
        from django.db.models import Max

        latest_endpoint_ids = endpoints.values("http_url").annotate(max_id=Max("id")).values_list("max_id", flat=True)
        endpoints = EndPoint.objects.filter(id__in=latest_endpoint_ids)

        if "only_urls" in req.query_params:
            self.serializer_class = EndpointOnlyURLsSerializer

        # Filter status code 404 and 0
        # endpoints = (
        #     endpoints
        #     .exclude(http_status=0)
        #     .exclude(http_status=None)
        #     .exclude(http_status=404)
        # )

        self.queryset = endpoints

        return self.queryset

    datatable_column_map = DATATABLE_COLUMN_MAP_ENDPOINT

    def filter_queryset(self, qs):
        qs = self.queryset.filter()
        search_value = self.request.GET.get("search[value]", None)
        if search_value:
            qs = self.apply_advanced_search(qs, search_value)
        order_str = get_datatables_order_column(self.request, self.datatable_column_map, default_order="content_length")
        if not (order_str and order_str.strip()):
            order_str = "content_length"
        return qs.order_by(order_str)


class DirectoryViewSet(DatatableListMixin, DatatablePaginationMixin, viewsets.ModelViewSet):
    """List directory files by scan_history or subdomain_id. Supports DataTables server-side (start, length, order, search)."""

    queryset = DirectoryFile.objects.none()
    serializer_class = DirectoryFileSerializer
    datatable_default_ordering = ("id",)
    datatable_column_map = DATATABLE_COLUMN_MAP_DIRECTORY

    def list(self, request, *args, **kwargs):
        scan_id = safe_int_cast(request.query_params.get("scan_history")) or safe_int_cast(
            request.query_params.get("scan_id")
        )
        subdomain_id = safe_int_cast(request.query_params.get("subdomain_id"))
        if not (scan_id or subdomain_id):
            return Response(
                {"status": False, "message": "Scan id or subdomain id must be provided."},
                status=HTTP_400_BAD_REQUEST,
            )
        return super().list(request, *args, **kwargs)

    def get_queryset(self):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_history")) or safe_int_cast(req.query_params.get("scan_id"))
        subdomain_id = safe_int_cast(req.query_params.get("subdomain_id"))

        if not (scan_id or subdomain_id):
            return DirectoryFile.objects.none()

        subdomains = (
            Subdomain.objects.filter(scan_history__id=scan_id) if scan_id else Subdomain.objects.filter(id=subdomain_id)
        )
        dirs_scans = DirectoryScan.objects.filter(directories__in=subdomains)

        return DirectoryFile.objects.filter(directory_files__in=dirs_scans).distinct().order_by("id")

    def filter_queryset(self, qs):
        search_value = self.request.GET.get("search[value]", None)
        if search_value:
            qs = qs.filter(Q(url__icontains=search_value) | Q(name__icontains=search_value)).distinct()
        order_str = get_datatables_order_column(self.request, self.datatable_column_map, default_order="name")
        if order_str and order_str.strip():
            return qs.order_by(order_str)
        return qs.order_by("id")


class ProjectViewSet(viewsets.ModelViewSet):
    serializer_class = ProjectSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Project.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def perform_update(self, serializer):
        if serializer.instance.user != self.request.user:
            raise PermissionDenied("You don't have permission to modify this project.")
        serializer.save()


class VulnerabilityViewSet(DatatableListMixin, DatatablePaginationMixin, AdvancedSearchMixin, viewsets.ModelViewSet):
    queryset = Vulnerability.objects.none()
    serializer_class = VulnerabilitySerializer
    datatable_default_ordering = ("-severity",)

    def _handle_severity(self, queryset, operator, value):
        """Custom handler for severity field using NUCLEI_SEVERITY_MAP."""
        severity_value = NUCLEI_SEVERITY_MAP.get(value.lower(), -1)
        if operator == "=":
            return queryset.filter(severity=severity_value)
        elif operator == "!":
            return queryset.exclude(severity=severity_value)
        return queryset

    def _handle_status(self, queryset, operator, value):
        """Custom handler for status field."""
        open_status = value.lower() == "open"
        if operator == "=":
            return queryset.filter(open_status=open_status)
        elif operator == "!":
            return queryset.exclude(open_status=open_status)
        return queryset

    def _handle_description(self, queryset, operator, value):
        """Custom handler for description field - searches across multiple fields."""
        description_q = (
            Q(description__icontains=value) | Q(template__icontains=value) | Q(extracted_results__icontains=value)
        )
        if operator == "=":
            return queryset.filter(description_q)
        elif operator == "!":
            return queryset.exclude(description_q)
        return queryset

    def _handle_cvss_score(self, queryset, operator, value):
        """Custom handler for cvss_score field - supports numeric comparisons."""
        try:
            float_value = float(value)
            if operator == "=":
                return queryset.filter(cvss_score__exact=float_value)
            elif operator == ">":
                return queryset.filter(cvss_score__gt=float_value)
            elif operator == "<":
                return queryset.filter(cvss_score__lt=float_value)
            elif operator == "!":
                return queryset.exclude(cvss_score__exact=float_value)
        except (ValueError, TypeError):
            logger.log_line(
                PREFIX_API,
                "VULNERABILITY_SEARCH",
                "Invalid numeric value for cvss_score: %s" % (value,),
                level="warning",
            )
        return queryset

    @property
    def search_config(self):
        return {
            "general_fields": [
                lambda sv: Q(http_url__icontains=sv),
                lambda sv: Q(domain__name__icontains=sv),
                lambda sv: Q(template__icontains=sv),
                lambda sv: Q(template_id__icontains=sv),
                lambda sv: Q(name__icontains=sv),
                lambda sv: Q(severity__icontains=sv),
                lambda sv: Q(description__icontains=sv),
                lambda sv: Q(extracted_results__icontains=sv),
                lambda sv: Q(references__icontains=sv),
                lambda sv: Q(cve_ids__name__icontains=sv),
                lambda sv: Q(cwe_ids__name__icontains=sv),
                lambda sv: Q(cvss_metrics__icontains=sv),
                lambda sv: Q(cvss_score__icontains=sv),
                lambda sv: Q(type__icontains=sv),
                lambda sv: Q(open_status__icontains=sv),
                lambda sv: Q(hackerone_report_id__icontains=sv),
                lambda sv: Q(tags__name__icontains=sv),
            ],
            "special_fields": {
                "name": "name__icontains",
                "http_url": "http_url__icontains",
                "template": "template__icontains",
                "template_id": "template_id__icontains",
                "cve_id": "cve_ids__name__icontains",
                "cve": "cve_ids__name__icontains",
                "cwe_id": "cwe_ids__name__icontains",
                "cwe": "cwe_ids__name__icontains",
                "cvss_metrics": "cvss_metrics__icontains",
                "type": "type__icontains",
                "tag": "tags__name__icontains",
            },
            "numeric_fields": {},
            "boolean_fields": {},
            "custom_handlers": {
                "severity": self._handle_severity,
                "status": self._handle_status,
                "description": self._handle_description,
                "cvss_score": self._handle_cvss_score,
            },
        }

    def get_queryset(self):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_history"))
        target_id = safe_int_cast(req.query_params.get("target_id"))
        domain = req.query_params.get("domain")
        severity = req.query_params.get("severity")
        subdomain_id = safe_int_cast(req.query_params.get("subdomain_id"))
        subdomain_name = req.query_params.get("subdomain")
        vulnerability_name = req.query_params.get("vulnerability_name")
        slug = self.request.GET.get("project", None)

        if slug:
            vulnerabilities = Vulnerability.objects.filter(scan_history__target__project__slug=slug)
        else:
            vulnerabilities = Vulnerability.objects.all()

        if scan_id:
            qs = vulnerabilities.filter(scan_history__id=scan_id).distinct()
        elif target_id:
            qs = vulnerabilities.filter(domain__scan_history__target_id=target_id).distinct()
        elif subdomain_name:
            subdomains = Subdomain.objects.filter(name=subdomain_name)
            qs = vulnerabilities.filter(subdomain__in=subdomains).distinct()
        else:
            qs = vulnerabilities.distinct()

        if domain:
            qs = qs.filter(Q(domain__name=domain)).distinct()
        if vulnerability_name:
            qs = qs.filter(Q(name=vulnerability_name)).distinct()
        if severity:
            qs = qs.filter(severity=severity)
        if subdomain_id:
            qs = qs.filter(subdomain__id=subdomain_id)

        # Optimize queries with select_related and prefetch_related to avoid N+1 queries
        qs = qs.select_related(
            "subdomain",
            "endpoint",
            "domain",
            "scan_history",
            "subdomain__scan_history",
            "subdomain__domain",
        ).prefetch_related(
            "cve_ids",
            "cwe_ids",
            "tags",
            "subdomain__technologies",
            "subdomain__ip_addresses",
            "subdomain__ip_addresses__ports",
            "subdomain__directories",
            "subdomain__waf",
            "scan_history__emails",
            "scan_history__employees",
            "scan_history__buckets",
            "scan_history__dorks",
            "vuln_subscan_ids",
        )

        self.queryset = qs
        return self.queryset

    datatable_column_map = DATATABLE_COLUMN_MAP_VULNERABILITY

    def filter_queryset(self, qs):
        qs = self.queryset.filter()
        search_value = self.request.GET.get("search[value]", None)
        if search_value:
            qs = self.apply_advanced_search(qs, search_value)
        filter_severity = get_request_filter_list(self.request, FILTER_PARAM_SEVERITY)
        codes = get_nuclei_severity_codes_for_labels(filter_severity)
        if codes:
            qs = qs.filter(severity__in=codes)
        filter_status = get_request_filter_list(self.request, FILTER_PARAM_STATUS)
        if filter_status:
            status_bool = []
            for s in filter_status:
                sl = (s or "").lower()
                if sl in ("open", "true", "1"):
                    status_bool.append(True)
                elif sl in ("resolved", "closed", "false", "0"):
                    status_bool.append(False)
            if status_bool:
                qs = qs.filter(open_status__in=status_bool)
        qs = apply_filter_list_in(qs, "source__in", get_request_filter_list(self.request, FILTER_PARAM_SOURCE))
        order_str = get_datatables_order_column(self.request, self.datatable_column_map, default_order="-severity")
        return qs.order_by(order_str)


class SecretViewSet(DatatableListMixin, DatatablePaginationMixin, viewsets.ReadOnlyModelViewSet):
    queryset = Secret.objects.none()
    serializer_class = SecretSerializer
    datatable_default_ordering = ("-discovered_date",)
    datatable_column_map = DATATABLE_COLUMN_MAP_SECRET

    def get_queryset(self):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_history"))
        slug = req.query_params.get("project")

        if slug:
            qs = Secret.objects.filter(scan_history__target__project__slug=slug)
            if scan_id:
                qs = qs.filter(scan_history_id=scan_id)
        elif scan_id:
            qs = Secret.objects.filter(scan_history_id=scan_id)
        else:
            qs = Secret.objects.none()

        qs = qs.select_related("scan_history")
        self.queryset = qs
        return self.queryset


class ExploitViewSet(DatatableListMixin, DatatablePaginationMixin, viewsets.ReadOnlyModelViewSet):
    queryset = Exploit.objects.none()
    serializer_class = ExploitSerializer
    datatable_default_ordering = ("-discovered_date",)
    datatable_column_map = DATATABLE_COLUMN_MAP_EXPLOIT

    def get_queryset(self):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_history"))
        target_id = safe_int_cast(req.query_params.get("target_id"))
        slug = req.query_params.get("project")

        if slug:
            qs = Exploit.objects.filter(scan_history__target__project__slug=slug)
            if scan_id:
                qs = qs.filter(scan_history_id=scan_id)
            elif target_id:
                qs = qs.filter(scan_history__target_id=target_id)
        elif scan_id:
            qs = Exploit.objects.filter(scan_history_id=scan_id)
        elif target_id:
            qs = Exploit.objects.filter(scan_history__target_id=target_id)
        else:
            qs = Exploit.objects.none()

        qs = qs.select_related("scan_history", "ip_address", "endpoint", "domain").prefetch_related("cve_ids", "tags")
        self.queryset = qs
        return self.queryset

    def filter_queryset(self, qs):
        search_value = self.request.GET.get("search[value]", "") or ""
        search_value = search_value.strip()
        if search_value:
            qs = qs.filter(
                Q(name__icontains=search_value)
                | Q(exploit_id__icontains=search_value)
                | Q(provider__icontains=search_value)
                | Q(matched_at__icontains=search_value)
                | Q(reference__icontains=search_value)
                | Q(domain__name__icontains=search_value)
            ).distinct()
        for field_name in ("name", "exploit_id", "provider", "matched_at", "reference", "domain__name"):
            value = get_datatables_column_search_value(self.request, self.datatable_column_map, field_name)
            if value:
                qs = qs.filter(**{f"{field_name}__icontains": value})
        return apply_datatables_order(qs, self.request, self.datatable_column_map, default_order="-discovered_date")


class GetIpDetails(APIView):
    def get(self, request, format=None):
        req = self.request
        ip_address = req.query_params.get("ip_address")
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        target_id = safe_int_cast(req.query_params.get("target_id"))

        if not ip_address:
            return Response({"error": "IP address is required"}, status=400)

        # Build the base query
        ip_query = IpAddress.objects.filter(address=ip_address)

        if scan_id:
            ip_query = ip_query.filter(ip_addresses__scan_history__id=scan_id)
        elif target_id:
            ip_query = ip_query.filter(ip_addresses__domain__scan_history__target_id=target_id)

        # Preloading relations to optimize performance
        ip_query = ip_query.prefetch_related(
            "ports",
            "ip_addresses",
        ).distinct()

        if not ip_query.exists():
            return Response({"error": "IP not found"}, status=404)

        serializer = IpSerializer(ip_query.first(), context={"scan_id": scan_id})
        return Response(serializer.data)


class UncommonWebPortsView(APIView):
    def get(self, request):
        from reNgine.definitions import COMMON_WEB_PORTS, UNCOMMON_WEB_PORTS

        return Response({"uncommon_web_ports": UNCOMMON_WEB_PORTS, "common_web_ports": COMMON_WEB_PORTS})


class LLMModelsManager(APIView):
    def get(self, request):
        """Get all available LLM models (GPT and Ollama) and currently selected model"""
        try:
            # Get default GPT models
            all_models = DEFAULT_GPT_MODELS.copy()

            # Get Ollama models
            try:
                response = requests.get(f"{OLLAMA_INSTANCE}/api/tags")
                if response.status_code == 200:
                    ollama_models = response.json().get("models", [])

                    def parse_date(date_str):
                        # First try to handle nanoseconds by truncating to microseconds
                        if "." in date_str:
                            parts = date_str.split(".")
                            # Truncate nanoseconds to microseconds (6 digits)
                            micros = parts[1].rstrip("Z")[:6]
                            date_str = f"{parts[0]}.{micros}"
                            if "Z" in parts[1]:
                                date_str += "Z"

                        formats = [
                            "%Y-%m-%dT%H:%M:%S.%fZ",  # Format with microseconds and Z
                            "%Y-%m-%dT%H:%M:%S.%f",  # Format with microseconds only
                            "%Y-%m-%dT%H:%M:%SZ",  # Format with Z
                            "%Y-%m-%dT%H:%M:%S",  # Basic format
                        ]

                        for date_format in formats:
                            try:
                                return datetime.strptime(date_str, date_format)
                            except ValueError:
                                continue

                        # If no format matches, log error and return current time
                        logger.log_line(
                            PREFIX_API,
                            "LLM_MODELS",
                            "Could not parse timestamp: %s" % (date_str,),
                            level="error",
                        )
                        return timezone.now()

                    all_models.extend(
                        [
                            {
                                **model,
                                "modified_at": parse_date(model["modified_at"]),
                                "is_local": True,
                            }
                            for model in ollama_models
                        ]
                    )
            except Exception as e:
                logger.log_line(
                    PREFIX_API,
                    "LLM_MODELS",
                    "Error fetching Ollama models: %s" % (e,),
                    level="error",
                )

            # Get currently selected model
            selected_model = OllamaSettings.objects.first()
            selected_model_name = selected_model.selected_model if selected_model else "gpt-3.5-turbo"

            # Mark selected model
            for model in all_models:
                if model["name"] == selected_model_name:
                    model["selected"] = True

            # Add model capabilities
            for model in all_models:
                # Strip tags from model name (e.g., "llama2:latest" -> "llama2")
                base_model_name = model["name"].split(":")[0]
                if base_model_name in MODEL_REQUIREMENTS:
                    model["capabilities"] = MODEL_REQUIREMENTS[base_model_name]

            return Response(
                {
                    "status": True,
                    "models": all_models,
                    "selected_model": selected_model_name,
                    "openai_key_error": not get_open_ai_key() and "gpt" in selected_model_name,
                }
            )

        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "LLM_MODELS",
                "Error in LLMModelsManager GET: %s" % (e,),
                level="error",
            )
            return Response(
                {"status": False, "error": "Failed to fetch LLM models", "message": get_safe_user_message(e, None)},
                status=500,
            )


@api_view(["GET"])
def websocket_status(request):
    """Check if WebSocket server is available"""
    try:
        channel_layer = get_channel_layer()
        return Response(
            {
                "status": True,
                "websocket_enabled": bool(channel_layer),
                "websocket_endpoints": {
                    "ollama_download": "/ws/ollama/download/{model_name}/",
                    "scan_status": "/ws/scan-status/{scan_id}/",
                    "scan_status_project": "/ws/scan-status/project/{project_slug}/",
                },
            }
        )
    except Exception as e:
        return Response({"status": False, "error": get_safe_user_message(e, logger)}, status=500)


class FetchScreenshots(APIView):
    def get(self, request):
        """Get screenshots from endpoints for a specific scan or target"""
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        target_id = safe_int_cast(req.query_params.get("target_id"))
        subdomain_id = safe_int_cast(req.query_params.get("subdomain_id"))
        port = req.query_params.get("port")

        if not scan_id and not target_id:
            return Response({"status": False, "error": "Missing scan_id or target_id parameter"})

        def extract_port_from_url(url):
            """Extract port from URL, return default ports for HTTP/HTTPS"""
            from urllib.parse import urlparse

            parsed = urlparse(url)
            if parsed.port:
                return parsed.port
            elif parsed.scheme == "https":
                return 443
            elif parsed.scheme == "http":
                return 80
            return None

        from reNgine.definitions import UNCOMMON_WEB_PORTS

        # Get endpoints with screenshots
        endpoints_with_screenshots = (
            EndPoint.objects.filter(screenshot_path__isnull=False)
            .select_related("subdomain")
            .prefetch_related("subdomain__ip_addresses", "subdomain__technologies")
        )

        # Filter by scan_id or target_id
        if scan_id:
            endpoints_with_screenshots = endpoints_with_screenshots.filter(scan_history__id=scan_id)
        elif target_id:
            endpoints_with_screenshots = endpoints_with_screenshots.filter(scan_history__target_id=target_id)

        # Filter by subdomain if provided
        if subdomain_id:
            endpoints_with_screenshots = endpoints_with_screenshots.filter(subdomain__id=subdomain_id)

        # Filter by port if provided - handle default ports correctly
        if port:
            port_int = safe_int_cast(port)
            filtered_endpoints = []
            for endpoint in endpoints_with_screenshots:
                endpoint_port = extract_port_from_url(endpoint.http_url)
                if endpoint_port == port_int:
                    filtered_endpoints.append(endpoint)
            endpoints_with_screenshots = filtered_endpoints

        if not endpoints_with_screenshots:
            return Response({"status": False, "message": "No screenshots found"})

        # Group by subdomain to maintain UI compatibility
        screenshots_data = {}
        for endpoint in endpoints_with_screenshots:
            subdomain = endpoint.subdomain
            if not subdomain:
                continue

            subdomain_key = f"{subdomain.name}_{endpoint.id}"
            endpoint_port = extract_port_from_url(endpoint.http_url)

            # URLs served with project-scoped access via api.scan_file.ServeScanFile
            screenshot_urls = get_scan_file_urls(endpoint.screenshot_path, req)
            stored_response_urls = get_scan_file_urls(endpoint.stored_response_path, req)
            screenshot_url = screenshot_urls.absolute
            stored_response_url = stored_response_urls.absolute
            port_is_uncommon = endpoint_port is not None and endpoint_port in UNCOMMON_WEB_PORTS
            # Frontend uses screenshot_url (and stored_response_url) for display; screenshot_path
            # is included for API consumers that need the stored path (e.g. export/debug).
            screenshots_data[subdomain_key] = {
                "name": subdomain.name,
                "http_url": endpoint.http_url,
                "page_title": endpoint.page_title or subdomain.page_title,
                "http_status": endpoint.http_status or subdomain.http_status,
                "screenshot_path": endpoint.screenshot_path,
                "screenshot_url": screenshot_url,
                "stored_response_path": endpoint.stored_response_path,
                "stored_response_url": stored_response_url,
                "is_interesting": subdomain.is_important,
                "endpoint_id": endpoint.id,
                "port": endpoint_port,
                "port_is_uncommon": port_is_uncommon,
                "ip_addresses": [{"address": ip.address, "is_cdn": ip.is_cdn} for ip in subdomain.ip_addresses.all()],
                "technologies": [{"name": tech.name} for tech in subdomain.technologies.all()],
            }

        return Response(screenshots_data)


class GetCSRFToken(APIView):
    def get(self, request):
        """
        Get CSRF token for API requests when CSRF_USE_SESSIONS=True
        According to Django documentation: https://docs.djangoproject.com/en/5.2/howto/csrf/
        """
        from django.middleware.csrf import get_token

        # This will create the token and store it in the session
        csrf_token = get_token(request)

        return Response(
            {
                "status": True,
                "csrf_token": csrf_token,
                "usage": "Include this token in X-CSRFToken header for POST requests",
            }
        )


# =============================================================================
# Workflow API Views
# =============================================================================


class CreateSecatorWorkflow(APIView):
    """Create a new workflow."""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            data = request.data

            workflow = SecatorWorkflow.objects.create(
                name=data["name"],
                description=data.get("description", ""),
                workflow_type=data.get("workflow_type", "custom"),
                yaml_configuration=data["yaml_configuration"],
                scan_type=data.get("scan_type", "internet"),
                is_active=data.get("is_active", True),
            )

            return Response(
                {"status": "success", "workflow_id": workflow.id, "message": "Workflow created successfully"}
            )

        except Exception as e:
            return Response({"status": "error", "message": get_safe_user_message(e, logger)}, status=400)


class CreateSecatorTask(APIView):
    """Create a new task."""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            data = request.data

            task = SecatorTask.objects.create(
                name=data["name"],
                task_type=data["task_type"],
                description=data.get("description", ""),
                is_builtin=data.get("is_builtin", False),
                yaml_configuration=data.get("yaml_configuration", ""),
            )

            return Response({"status": "success", "task_id": task.id, "message": "Task created successfully"})

        except Exception as e:
            return Response({"status": "error", "message": get_safe_user_message(e, logger)}, status=400)


class CreateSecatorScan(APIView):
    """Create a new scan configuration."""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            data = request.data

            scan = SecatorScan.objects.create(
                name=data["name"],
                description=data.get("description", ""),
                scan_type=data.get("scan_type", "internet"),
                scan_config_type=data.get("scan_config_type", "custom"),
                is_default=data.get("is_default", False),
                yaml_configuration=data.get("yaml_configuration", ""),
            )

            # Note: execution_mode, workflow, and tasks are no longer used
            # Scans now use YAML configuration instead

            scan.save()

            return Response(
                {"status": "success", "scan_id": scan.id, "message": "Scan configuration created successfully"}
            )

        except Exception as e:
            return Response({"status": "error", "message": get_safe_user_message(e, logger)}, status=400)


class LoadBuiltinWorkflows(APIView):
    """Load built-in workflows."""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            from io import StringIO

            from django.core.management import call_command

            # Capture output
            out = StringIO()
            call_command("load_workflows", "--builtin-only", "--force", stdout=out)

            return Response(
                {"status": "success", "message": "Built-in workflows loaded successfully", "output": out.getvalue()}
            )
        except Exception as e:
            return Response({"status": "error", "message": get_safe_user_message(e, logger)}, status=400)


class LoadBuiltinTasks(APIView):
    """Load built-in tasks."""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            from io import StringIO

            from django.core.management import call_command

            out = StringIO()
            call_command("load_tasks", stdout=out)

            return Response(
                {"status": "success", "message": "Built-in tasks loaded successfully", "output": out.getvalue()}
            )
        except Exception as e:
            return Response({"status": "error", "message": get_safe_user_message(e, logger)}, status=400)


class LoadBuiltinProfiles(APIView):
    """Load built-in profiles."""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            from io import StringIO

            from django.core.management import call_command

            # Capture output
            out = StringIO()
            call_command("load_profiles", "--builtin-only", stdout=out)

            return Response(
                {"status": "success", "message": "Built-in profiles loaded successfully", "output": out.getvalue()}
            )
        except Exception as e:
            return Response({"status": "error", "message": get_safe_user_message(e, logger)}, status=400)


class GetDefaultProfileOpts(APIView):
    """Get default profile opts template."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            from scanEngine.management.commands.load_profiles import Command

            command = Command()
            opts_yaml = command._extract_all_opts()

            return Response({"status": "success", "opts": opts_yaml})
        except Exception as e:
            return Response({"status": "error", "message": get_safe_user_message(e, logger)}, status=400)


class LoadBuiltinScans(APIView):
    """Load built-in scans."""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            from io import StringIO

            from django.core.management import call_command

            # Capture output
            out = StringIO()
            call_command("load_scans", "--builtin-only", stdout=out)

            return Response(
                {"status": "success", "message": "Built-in scans loaded successfully", "output": out.getvalue()}
            )
        except Exception as e:
            return Response({"status": "error", "message": get_safe_user_message(e, logger)}, status=400)


class GetWorkflowTasks(APIView):
    """Get tasks for a specific workflow."""

    permission_classes = [IsAuthenticated]

    def get(self, request, workflow_id):
        try:
            workflow = get_object_or_404(SecatorWorkflow, id=workflow_id)
            tasks = workflow.get_tasks()

            return Response({"status": "success", "tasks": tasks})

        except Exception as e:
            return Response({"status": "error", "message": get_safe_user_message(e, logger)}, status=400)


class GetAvailableTasks(APIView):
    """Get all available tasks for selection."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            tasks = SecatorTask.objects.all().values("id", "name", "task_type", "description")

            return Response({"status": "success", "tasks": list(tasks)})

        except Exception as e:
            return Response({"status": "error", "message": get_safe_user_message(e, logger)}, status=400)


class GetAvailableWorkflows(APIView):
    """Get all available workflows for selection."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            workflows = SecatorWorkflow.objects.filter(is_active=True).values(
                "id", "name", "description", "workflow_type", "scan_type"
            )

            return Response({"status": "success", "workflows": list(workflows)})

        except Exception as e:
            return Response({"status": "error", "message": get_safe_user_message(e, logger)}, status=400)


class GetWorkflowDetail(APIView):
    """Get workflow detail by ID."""

    def get(self, request, workflow_id):
        try:
            workflow = SecatorWorkflow.objects.get(id=workflow_id)

            workflow_data = {
                "id": workflow.id,
                "name": workflow.name,
                "description": workflow.description,
                "workflow_type": workflow.workflow_type,
                "yaml_configuration": workflow.yaml_configuration,
                "is_active": workflow.is_active,
                "scan_type": workflow.scan_type,
                "created_at": workflow.created_at.isoformat(),
                "updated_at": workflow.updated_at.isoformat(),
            }

            return Response({"status": "success", "workflow": workflow_data})

        except SecatorWorkflow.DoesNotExist:
            return Response({"status": "error", "message": "Workflow not found"}, status=404)
        except Exception as e:
            return Response({"status": "error", "message": get_safe_user_message(e, logger)}, status=400)


class UpdateSecatorWorkflow(APIView):
    """Update an existing workflow."""

    def put(self, request, workflow_id):
        try:
            workflow = SecatorWorkflow.objects.get(id=workflow_id)

            # Update fields
            workflow.name = request.data.get("name", workflow.name)
            workflow.description = request.data.get("description", workflow.description)
            workflow.workflow_type = request.data.get("workflow_type", workflow.workflow_type)
            workflow.yaml_configuration = request.data.get("yaml_configuration", workflow.yaml_configuration)
            workflow.is_active = request.data.get("is_active", workflow.is_active)
            workflow.scan_type = request.data.get("scan_type", workflow.scan_type)

            workflow.save()

            return Response({"status": "success", "message": "Workflow updated successfully"})

        except SecatorWorkflow.DoesNotExist:
            return Response({"status": "error", "message": "Workflow not found"}, status=404)
        except Exception as e:
            return Response({"status": "error", "message": get_safe_user_message(e, logger)}, status=400)


class DeleteSecatorWorkflow(APIView):
    """Delete a workflow."""

    def delete(self, request, workflow_id):
        try:
            workflow = SecatorWorkflow.objects.get(id=workflow_id)
            workflow_name = workflow.name
            workflow.delete()

            return Response({"status": "success", "message": f'Workflow "{workflow_name}" deleted successfully'})

        except SecatorWorkflow.DoesNotExist:
            return Response({"status": "error", "message": "Workflow not found"}, status=404)
        except Exception as e:
            return Response({"status": "error", "message": get_safe_user_message(e, logger)}, status=400)


class GetTaskDetail(APIView):
    """Get task detail by ID."""

    def get(self, request, task_id):
        try:
            task = SecatorTask.objects.get(id=task_id)

            task_data = {
                "id": task.id,
                "name": task.name,
                "task_type": task.task_type,
                "description": task.description,
                "is_builtin": task.is_builtin,
                "yaml_configuration": task.yaml_configuration,
                "created_at": task.created_at.isoformat(),
                "updated_at": task.updated_at.isoformat(),
            }

            return Response({"status": "success", "task": task_data})

        except SecatorTask.DoesNotExist:
            return Response({"status": "error", "message": "Task not found"}, status=404)
        except Exception as e:
            return Response({"status": "error", "message": get_safe_user_message(e, logger)}, status=400)


class UpdateSecatorTask(APIView):
    """Update an existing task."""

    def put(self, request, task_id):
        try:
            task = SecatorTask.objects.get(id=task_id)

            # Update fields
            task.name = request.data.get("name", task.name)
            task.task_type = request.data.get("task_type", task.task_type)
            task.description = request.data.get("description", task.description)
            task.yaml_configuration = request.data.get("yaml_configuration", task.yaml_configuration)

            task.save()

            return Response({"status": "success", "message": "Task updated successfully"})

        except SecatorTask.DoesNotExist:
            return Response({"status": "error", "message": "Task not found"}, status=404)
        except Exception as e:
            return Response({"status": "error", "message": get_safe_user_message(e, logger)}, status=400)


class DeleteSecatorTask(APIView):
    """Delete a task."""

    def delete(self, request, task_id):
        try:
            task = SecatorTask.objects.get(id=task_id)
            task_name = task.name
            task.delete()

            return Response({"status": "success", "message": f'Task "{task_name}" deleted successfully'})

        except SecatorTask.DoesNotExist:
            return Response({"status": "error", "message": "Task not found"}, status=404)
        except Exception as e:
            return Response({"status": "error", "message": get_safe_user_message(e, logger)}, status=400)


class GetScanDetail(APIView):
    """Get scan configuration detail by ID."""

    def get(self, request, scan_id):
        try:
            scan = SecatorScan.objects.get(id=scan_id)

            scan_data = {
                "id": scan.id,
                "name": scan.name,
                "description": scan.description,
                "scan_type": scan.scan_type,
                "execution_mode": "scan",
                "scan_config_type": scan.scan_config_type,
                "is_default": scan.is_default,
                "workflow_id": None,
                "workflow_name": None,
                "task_ids": [],
                "task_names": [],
                "created_at": scan.created_at.isoformat(),
                "updated_at": scan.updated_at.isoformat(),
            }

            return Response({"status": "success", "scan": scan_data})

        except SecatorScan.DoesNotExist:
            return Response({"status": "error", "message": "Scan configuration not found"}, status=404)
        except Exception as e:
            return Response({"status": "error", "message": get_safe_user_message(e, logger)}, status=400)


class UpdateSecatorScan(APIView):
    """Update an existing scan configuration."""

    def put(self, request, scan_id):
        try:
            scan = SecatorScan.objects.get(id=scan_id)

            # Update fields
            scan.name = request.data.get("name", scan.name)
            scan.description = request.data.get("description", scan.description)
            scan.scan_type = request.data.get("scan_type", scan.scan_type)
            scan.is_default = request.data.get("is_default", scan.is_default)

            # Note: execution_mode, workflow, and tasks are no longer used
            # Scans now use YAML configuration instead

            scan.save()

            return Response({"status": "success", "message": "Scan configuration updated successfully"})

        except SecatorScan.DoesNotExist:
            return Response({"status": "error", "message": "Scan configuration not found"}, status=404)
        except Exception as e:
            return Response({"status": "error", "message": get_safe_user_message(e, logger)}, status=400)


class DeleteSecatorScan(APIView):
    """Delete a scan configuration."""

    def delete(self, request, scan_id):
        try:
            scan = SecatorScan.objects.get(id=scan_id)
            scan_name = scan.name
            scan.delete()

            return Response({"status": "success", "message": f'Scan configuration "{scan_name}" deleted successfully'})

        except SecatorScan.DoesNotExist:
            return Response({"status": "error", "message": "Scan configuration not found"}, status=404)
        except Exception as e:
            return Response({"status": "error", "message": get_safe_user_message(e, logger)}, status=400)


class SecatorRunnerCreate(SecatorAPIBase):
    """
    API endpoint to create a runner from Secator hooks.
    This endpoint is called by Secator workers to register new runners.
    """

    permission_classes = [HasAPIKeyOrIsAuthenticated]

    def post(self, request):
        try:
            from rest_framework.exceptions import ParseError

            from startScan.models import ScanHistory, SecatorRunner, SubScan

            try:
                runner_data = request.data
            except ParseError:
                return Response(
                    {"status": False, "error": "Invalid request data format"},
                    status=HTTP_400_BAD_REQUEST,
                )
            if not isinstance(runner_data, dict):
                return Response(
                    {"status": False, "error": "Invalid request data format"},
                    status=HTTP_400_BAD_REQUEST,
                )

            # Validate request data
            is_valid, error_response = self.validate_request_data(runner_data)
            if not is_valid:
                return error_response

            # Log API call
            self.logger.log_runner_api_call("CREATE", runner_data)

            # Extract context
            context = self.extract_runner_context(runner_data)
            runner_type = context.get("runner_type") or "unknown"
            runner_name = context.get("runner_name")
            scan_history_id = context.get("scan_history_id")

            # Create runner object in database
            secator_runner = SecatorRunner(
                runner_type=runner_type,
                runner_name=runner_name,
                workspace_name=context.get("workspace_name"),
                runner_data=runner_data,
            )

            # Link to scan history if available
            if scan_history_id:
                try:
                    scan_history = ScanHistory.objects.get(id=scan_history_id)
                    secator_runner.scan_history = scan_history
                except ScanHistory.DoesNotExist:
                    self.logger.log_warning(
                        "ScanHistory %s not found, skipping link" % (scan_history_id,),
                        {"prefix": self.logger.PREFIX_SYNC, "action": "CREATE", "scan_id": scan_history_id},
                    )

            worker_id = get_request_worker_id(request, context=context)
            if worker_id is not None:
                try:
                    secator_runner.worker_id = worker_id
                except (ValueError, TypeError):
                    self.logger.log_warning(
                        f"Invalid worker_id '{worker_id}' provided; ignoring assignment",
                        {
                            "prefix": self.logger.PREFIX_SYNC,
                            "action": "CREATE",
                            "worker_id": worker_id,
                        },
                    )
                except Exception as e:
                    self.logger.log_error(
                        e,
                        {"prefix": self.logger.PREFIX_SYNC, "action": "CREATE", "worker_id": worker_id},
                        exc_info=True,
                    )

            # Save runner and get its ID
            secator_runner.save()
            runner_id = str(secator_runner.id)

            # Link SubScan to this runner when subscan_id is in context (per-task subscans)
            subscan_id = safe_int_cast(context.get("subscan_id"))
            if subscan_id is not None:
                if SubScan.objects.filter(id=subscan_id).update(secator_runner_id=secator_runner.id):
                    self.logger.log_runner_sync(
                        "CREATE",
                        runner_name or "unknown",
                        runner_type,
                        "LINKED_SUBSCAN",
                        scan_history_id,
                        {"runner_id": runner_id, "subscan_id": subscan_id},
                    )
                else:
                    self.logger.log_warning(
                        f"SubScan {subscan_id} not found, skipping runner link",
                        {"prefix": self.logger.PREFIX_SYNC, "action": "CREATE", "subscan_id": subscan_id},
                    )

            # Log success
            self.logger.log_runner_sync(
                "CREATE",
                runner_name or "unknown",
                runner_type,
                "CREATED",
                scan_history_id,
                {"id": runner_id},
            )

            return Response({"status": True, "id": runner_id})
        except Exception as e:
            self.logger.log_error(
                e,
                {"prefix": self.logger.PREFIX_SYNC, "action": "CREATE", "error": get_safe_user_message(e, logger)},
                exc_info=True,
            )
            return Response({"status": False, "error": get_safe_user_message(e, logger)}, status=500)


class SecatorRunnerUpdate(SecatorAPIBase):
    """
    API endpoint to update a runner from Secator hooks.
    This endpoint is called by Secator workers to update runner state.
    """

    permission_classes = [HasAPIKeyOrIsAuthenticated]

    def put(self, request, runner_id):
        try:
            from startScan.models import SecatorRunner

            # Parse request data - handle potential parsing errors
            try:
                runner_data = request.data
            except Exception as parse_error:
                self.logger.log_error(
                    parse_error,
                    {"prefix": self.logger.PREFIX_SYNC, "action": "UPDATE", "id": runner_id},
                    exc_info=True,
                )
                return Response(
                    {"status": False, "error": f"Error parsing request data: {str(parse_error)}"}, status=400
                )

            # Validate request data
            is_valid, error_response = self.validate_request_data(runner_data, runner_id)
            if not is_valid:
                return error_response

            # Log API call
            self.logger.log_runner_api_call("UPDATE", runner_data, runner_id)

            # Update runner data in database
            try:
                secator_runner = SecatorRunner.objects.get(id=runner_id)
                secator_runner.runner_data = runner_data

                # Update runner name if provided
                runner_name = runner_data.get("config", {}).get("name") or runner_data.get("name")
                if runner_name:
                    secator_runner.runner_name = runner_name

                # Extract and store celery_id from context
                context = runner_data.get("context", {})
                celery_id = context.get("celery_id")
                if celery_id:
                    secator_runner.celery_id = celery_id
                    self.logger.log_runner_field_extraction("celery_id", celery_id, runner_id)

                # Extract and store status from runner_data
                runner_status = runner_data.get("status")
                if runner_status:
                    secator_runner.status = runner_status.upper()
                    self.logger.log_runner_field_extraction("status", runner_status, runner_id)

                worker_id = get_request_worker_id(request, context=context)
                if worker_id is not None:
                    try:
                        secator_runner.worker_id = worker_id
                    except (ValueError, TypeError):
                        self.logger.log_warning(
                            "Invalid worker_id '%s' provided; ignoring assignment" % (worker_id,),
                            {
                                "prefix": self.logger.PREFIX_SYNC,
                                "action": "UPDATE",
                                "id": runner_id,
                                "worker_id": worker_id,
                            },
                        )
                    except Exception as e:
                        self.logger.log_error(
                            e,
                            {
                                "prefix": self.logger.PREFIX_SYNC,
                                "action": "UPDATE",
                                "id": runner_id,
                                "worker_id": worker_id,
                            },
                            exc_info=True,
                        )

                secator_runner.save()

                # Log success
                context_info = self.extract_runner_context(runner_data)
                self.logger.log_runner_sync(
                    "UPDATE",
                    runner_name or context_info.get("runner_name") or "unknown",
                    context_info.get("runner_type") or "unknown",
                    runner_status or "UNKNOWN",
                    context_info.get("scan_history_id"),
                    {"id": runner_id},
                )

                # Sync with ScanHistory: inline when SECATOR_RUNNER_UPDATE_SYNC_BACKGROUND is False (e.g. tests);
                # otherwise run in bounded pool. Pool limits concurrent syncs (SECATOR_RUNNER_UPDATE_SYNC_MAX_WORKERS).
                if secator_runner.scan_history_id:
                    if not django_settings.SECATOR_RUNNER_UPDATE_SYNC_BACKGROUND:
                        self._sync_runner_with_scan_history(secator_runner, runner_data)
                    else:
                        secator_submit_sync(secator_runner.id)

            except SecatorRunner.DoesNotExist:
                self.logger.log_warning(
                    f"Runner {runner_id} not found, cannot update",
                    {"prefix": self.logger.PREFIX_SYNC, "action": "UPDATE", "id": runner_id},
                )
                return Response({"status": False, "error": f"Runner {runner_id} not found"}, status=404)

            return Response({"status": True, "id": runner_id})
        except Exception as e:
            self.logger.log_error(
                e,
                {"prefix": self.logger.PREFIX_SYNC, "action": "UPDATE", "id": runner_id},
                exc_info=True,
            )
            # Check if it's a validation error that should return 400
            error_str = str(e).lower()
            if "validation" in error_str or "invalid" in error_str or "required" in error_str:
                return Response({"status": False, "error": get_safe_user_message(e, logger)}, status=400)
            return Response({"status": False, "error": get_safe_user_message(e, logger)}, status=500)

    def _is_all_runners_completed(self, scan_history_id: int) -> bool:
        """Delegate to standalone helper (view passes self.logger)."""
        return is_all_runners_completed(scan_history_id, self.logger)

    def _sync_runner_with_scan_history(self, secator_runner, runner_data):
        """Delegate to standalone helper (view passes self.logger)."""
        sync_runner_with_scan_history(secator_runner, runner_data, self.logger)


class SecatorFindingCreate(SecatorAPIBase):
    """
    API endpoint to create a finding from Secator hooks.
    This endpoint is called by Secator workers to save new findings.
    """

    permission_classes = [HasAPIKeyOrIsAuthenticated]

    def post(self, request):
        try:
            finding_data = request.data

            # Validate request data
            is_valid, error_response = self.validate_request_data(finding_data, prefix=self.logger.PREFIX_FINDING)
            if not is_valid:
                return error_response

            # Log API call
            self.logger.log_finding_api_call("CREATE", finding_data)

            # Extract context
            context_info = self.extract_finding_context(finding_data)
            finding_type = context_info["finding_type"]
            scan_history_id = context_info["scan_history_id"]
            target_id = context_info["target_id"]
            context = dict(finding_data.get("_context", {}))
            runner_id = context_info.get("runner_id")
            if runner_id is not None:
                try:
                    runner_id = int(runner_id)
                except (TypeError, ValueError):
                    runner_id = None
                if runner_id:
                    from startScan.models import SecatorRunner

                    try:
                        runner = SecatorRunner.objects.get(id=runner_id)
                        if getattr(runner, "subscan_id", None):
                            context["subscan_id"] = runner.subscan_id
                            subscan = SubScan.objects.filter(id=runner.subscan_id).select_related("subdomain").first()
                            if subscan and subscan.subdomain_id:
                                context["subdomain_id"] = subscan.subdomain_id
                    except SecatorRunner.DoesNotExist:
                        pass

            if not finding_type:
                return Response({"status": False, "error": "Missing _type in finding data"}, status=400)

            # Centralized tag routing (whois, url_pattern, asn, ignored, fallback to Technology)
            if finding_type == "tag":
                from reNgine.secator.tag_routing import dispatch_secator_tag

                def _validate_tag_context(sh_id, t_id):
                    return self.validate_scan_context(sh_id, t_id, "tag")

                result = dispatch_secator_tag(
                    finding_data,
                    scan_history_id,
                    target_id,
                    _validate_tag_context,
                    is_update=False,
                )
                if result[0] == "ignored":
                    return Response({"status": True, "id": result[1]})
                if result[0] == "skipped":
                    return Response(
                        {"status": True, "skipped": True, "id": result[1]},
                    )
                if result[0] == "success":
                    saved_obj = result[1]
                    self.logger.log_finding_save(
                        "CREATE", finding_type, saved_obj, scan_history_id, target_id, success=True
                    )
                    return Response({"status": True, "id": str(saved_obj.id)})
                if result[0] == "error":
                    status_code, err_msg = result[1], result[2]
                    self.logger.log_finding_save(
                        "CREATE",
                        finding_type,
                        None,
                        scan_history_id,
                        target_id,
                        success=False,
                        error_message=err_msg,
                    )
                    return Response({"status": False, "error": err_msg}, status=status_code)
                # fallback: continue to TechnologyRepository below

            # Get repository for finding type
            repository_class = self.get_repository_for_finding_type(finding_type)
            if not repository_class:
                self.logger.log_unknown_type("finding", finding_type)
                import time

                finding_id = f"{finding_type}_{int(time.time() * 1000)}"
                return Response({"status": True, "id": finding_id})

            # Validate scan context (target_id required)
            is_valid, error_response, scan_history, target = self.validate_scan_context(
                scan_history_id, target_id, finding_type
            )
            if not is_valid:
                return error_response
            target_id = target.id
            from targetApp.services.scope_params import get_finding_scope_filters_for_target

            context["finding_scope_filters"] = get_finding_scope_filters_for_target(target_id)

            # Instantiate repository and save finding
            repository = repository_class()
            self.logger.log_debug(
                self.logger.PREFIX_FINDING, "CREATE", "Using repository: %s" % (repository_class.__name__,)
            )
            self.logger.log_debug(
                self.logger.PREFIX_FINDING,
                "CREATE",
                "Calling save_from_secator with finding_data (keys: %s)" % (list(finding_data.keys()),),
            )

            try:
                if finding_type == "subdomain":
                    self.logger.log_debug(
                        self.logger.PREFIX_FINDING, "CREATE", "Saving subdomain with context: %s" % (context,)
                    )
                saved_object = repository.save_from_secator(
                    finding_data, scan_history_id, target_id, rengine_context=context
                )

                # Check if save was successful
                if saved_object is None:
                    error_detail = (
                        "Invalid or rejected hostname for subdomain finding."
                        if finding_type == "subdomain"
                        else "Validation error or missing required fields."
                    )
                    try:
                        self.logger.log_finding_save(
                            "CREATE",
                            finding_type,
                            None,
                            scan_history_id,
                            target_id,
                            success=False,
                            error_message="Repository returned None - %s" % (error_detail,),
                        )
                    except Exception:
                        pass
                    return Response(
                        {
                            "status": False,
                            "error": "Failed to save %s finding. %s" % (finding_type, error_detail),
                        },
                        status=422,
                    )

                # Generate finding ID from saved object
                if hasattr(saved_object, "id"):
                    finding_id = str(saved_object.id)
                    self.logger.log_finding_save(
                        "CREATE",
                        finding_type,
                        saved_object,
                        scan_history_id,
                        target_id,
                        success=True,
                    )
                    return Response({"status": True, "id": finding_id})
                else:
                    self.logger.log_finding_save(
                        "CREATE",
                        finding_type,
                        saved_object,
                        scan_history_id,
                        target_id,
                        success=False,
                        error_message="Saved object has no 'id' attribute",
                    )
                    return Response({"status": False, "error": "Saved object has no ID attribute"}, status=500)

            except FindingOutOfScopeError:
                synthetic_id = synthetic_id_skipped_scope(finding_type)
                self.logger.log_debug(
                    self.logger.PREFIX_FINDING,
                    "CREATE",
                    "Finding skipped (out of scope) for type=%s scan_id=%s target_id=%s"
                    % (finding_type, scan_history_id, target_id),
                )
                return Response(
                    {"status": True, "skipped": True, "id": synthetic_id},
                )
            except Exception as e:
                return self.handle_repository_error(e, finding_type, scan_history_id, target_id)

        except Exception as e:
            self.logger.log_error(
                e,
                {"prefix": self.logger.PREFIX_FINDING, "action": "CREATE", "error": get_safe_user_message(e, logger)},
                exc_info=True,
            )
            return Response({"status": False, "error": get_safe_user_message(e, logger)}, status=500)


class SecatorFindingUpdate(SecatorAPIBase):
    """
    API endpoint to update a finding from Secator hooks.
    This endpoint is called by Secator workers to update finding state.
    """

    permission_classes = [HasAPIKeyOrIsAuthenticated]

    def put(self, request, finding_id):
        try:
            # Parse request data - handle potential parsing errors
            try:
                finding_data = request.data
            except Exception as parse_error:
                self.logger.log_error(
                    parse_error,
                    {"prefix": self.logger.PREFIX_FINDING, "action": "UPDATE", "id": finding_id},
                    exc_info=True,
                )
                return Response(
                    {"status": False, "error": f"Error parsing request data: {str(parse_error)}"}, status=400
                )

            # Validate request data
            is_valid, error_response = self.validate_request_data(
                finding_data, finding_id, prefix=self.logger.PREFIX_FINDING
            )
            if not is_valid:
                return error_response

            # Validate context is a dict
            context = finding_data.get("_context", {})
            if not isinstance(context, dict):
                self.logger.log_error(
                    ValueError(f"_context is not a dict: {type(context)}"),
                    {"prefix": self.logger.PREFIX_FINDING, "action": "UPDATE", "id": finding_id},
                    exc_info=False,
                )
                return Response({"status": False, "error": "Invalid _context format"}, status=400)

            # Log API call
            self.logger.log_finding_api_call("UPDATE", finding_data, finding_id)

            # Extract context
            context_info = self.extract_finding_context(finding_data)
            finding_type = context_info["finding_type"]
            scan_history_id = context_info["scan_history_id"]
            target_id = context_info["target_id"]
            context = dict(finding_data.get("_context", {}))
            runner_id = context_info.get("runner_id")
            if runner_id is not None:
                try:
                    runner_id = int(runner_id)
                except (TypeError, ValueError):
                    runner_id = None
                if runner_id:
                    from startScan.models import SecatorRunner

                    try:
                        runner = SecatorRunner.objects.get(id=runner_id)
                        if getattr(runner, "subscan_id", None):
                            context["subscan_id"] = runner.subscan_id
                            subscan = SubScan.objects.filter(id=runner.subscan_id).select_related("subdomain").first()
                            if subscan and subscan.subdomain_id:
                                context["subdomain_id"] = subscan.subdomain_id
                    except SecatorRunner.DoesNotExist:
                        pass

            if not finding_type:
                self.logger.log_warning(
                    "Missing _type in finding data for finding_id=%s" % (finding_id,),
                    {"prefix": self.logger.PREFIX_FINDING, "action": "UPDATE", "id": finding_id},
                )
                return Response({"status": False, "error": "Missing _type in finding data"}, status=400)

            # Centralized tag routing (whois, url_pattern, asn, ignored, fallback to Technology)
            if finding_type == "tag":
                from reNgine.secator.tag_routing import dispatch_secator_tag

                def _validate_tag_context_update(sh_id, t_id):
                    return self.validate_scan_context(sh_id, t_id, "tag", prefix=self.logger.PREFIX_FINDING)

                result = dispatch_secator_tag(
                    finding_data,
                    scan_history_id,
                    target_id,
                    _validate_tag_context_update,
                    is_update=True,
                )
                if result[0] == "ignored":
                    return Response({"status": True, "id": result[1]})
                if result[0] == "skipped":
                    return Response(
                        {"status": True, "skipped": True, "id": result[1]},
                    )
                if result[0] == "success":
                    saved_obj = result[1]
                    self.logger.log_finding_save(
                        "UPDATE", finding_type, saved_obj, scan_history_id, target_id, success=True
                    )
                    return Response({"status": True, "id": str(saved_obj.id)})
                if result[0] == "error":
                    status_code, err_msg = result[1], result[2]
                    self.logger.log_finding_save(
                        "UPDATE",
                        finding_type,
                        None,
                        scan_history_id,
                        target_id,
                        success=False,
                        error_message=err_msg,
                    )
                    return Response({"status": False, "error": err_msg}, status=status_code)
                # fallback: continue to TechnologyRepository below

            # Get repository for finding type
            repository_class = self.get_repository_for_finding_type(finding_type)
            if not repository_class:
                # Check if it's a metadata type that should be ignored
                if self.is_metadata_type(finding_type):
                    self.logger.log_metadata_ignored(finding_type, finding_id)
                    return Response(
                        {"status": True, "message": "Ignored metadata type: %s" % (finding_type,)}, status=200
                    )

                self.logger.log_unknown_type("finding", finding_type, finding_id)
                return Response({"status": False, "error": "Unknown finding type: %s" % (finding_type,)}, status=400)

            # Validate scan context (target_id required)
            is_valid, error_response, scan_history, target = self.validate_scan_context(
                scan_history_id, target_id, finding_type, prefix=self.logger.PREFIX_FINDING
            )
            if not is_valid:
                return error_response
            target_id = target.id
            from targetApp.services.scope_params import get_finding_scope_filters_for_target

            context["finding_scope_filters"] = get_finding_scope_filters_for_target(target_id)

            # Instantiate repository and save finding (upsert: create or update)
            repository = repository_class()
            logger.log_line(
                PREFIX_API,
                "FINDING_UPDATE",
                "Using repository: %s for finding type: %s, finding_id: %s"
                % (repository_class.__name__, finding_type, finding_id),
                level="debug",
            )

            try:
                if finding_type == "subdomain":
                    logger.log_line(
                        PREFIX_API,
                        "FINDING_UPDATE",
                        "Saving subdomain with context: %s, finding_id: %s" % (context, finding_id),
                        level="debug",
                    )
                saved_object = repository.save_from_secator(
                    finding_data, scan_history_id, target_id, rengine_context=context
                )

                # Check if save was successful
                if saved_object is None:
                    self.logger.log_finding_save(
                        "UPDATE",
                        finding_type,
                        None,
                        scan_history_id,
                        target_id,
                        success=False,
                        error_message="Repository returned None - validation error or missing required fields",
                    )
                    return Response(
                        {
                            "status": False,
                            "error": f"Failed to save {finding_type} finding. Validation error or missing required fields. Check logs for details.",
                        },
                        status=400,
                    )

                # Generate finding ID from saved object
                if hasattr(saved_object, "id"):
                    saved_finding_id = str(saved_object.id)
                    self.logger.log_finding_save(
                        "UPDATE",
                        finding_type,
                        saved_object,
                        scan_history_id,
                        target_id,
                        success=True,
                    )
                    return Response({"status": True, "id": saved_finding_id})
                else:
                    self.logger.log_finding_save(
                        "UPDATE",
                        finding_type,
                        saved_object,
                        scan_history_id,
                        target_id,
                        success=False,
                        error_message="Saved object has no 'id' attribute",
                    )
                    return Response({"status": False, "error": "Saved object has no ID attribute"}, status=500)

            except FindingOutOfScopeError:
                synthetic_id = synthetic_id_skipped_scope(finding_type)
                self.logger.log_debug(
                    self.logger.PREFIX_FINDING,
                    "UPDATE",
                    "Finding skipped (out of scope) for type=%s finding_id=%s scan_id=%s target_id=%s"
                    % (finding_type, finding_id, scan_history_id, target_id),
                )
                return Response(
                    {"status": True, "skipped": True, "id": synthetic_id},
                )
            except Exception as e:
                return self.handle_repository_error(e, finding_type, scan_history_id, target_id, finding_id)

        except Exception as e:
            self.logger.log_error(
                e,
                {"prefix": self.logger.PREFIX_FINDING, "action": "UPDATE", "id": finding_id},
                exc_info=True,
            )
            # Check if it's a validation error that should return 400
            error_str = str(e).lower()
            if "validation" in error_str or "invalid" in error_str or "required" in error_str:
                return Response({"status": False, "error": get_safe_user_message(e, logger)}, status=400)
            return Response({"status": False, "error": get_safe_user_message(e, logger)}, status=500)


class SecatorHealth(APIView):
    """GET /health/ - Health check for Secator API (auth: API key or session)."""

    permission_classes = [HasAPIKeyOrIsAuthenticated]

    def get(self, request):
        return Response({"status": "ok"})


class DatatableFilterHealth(APIView):
    """
    GET /health/datatables-filters/ - Returns DataTables filter warnings (malformed inputs, drift).

    Only available when DEBUG is True. Warnings are collected when apply_filter_list_in or
    apply_filter_list_in_by_param log; call with ?clear=1 to clear after reading.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not django_settings.DEBUG:
            return Response({"detail": "Not available when DEBUG is False"}, status=HTTP_404_NOT_FOUND)
        clear = request.GET.get("clear", "").lower() in ("1", "true", "yes")
        warnings = get_datatable_filter_warnings(clear=clear)
        return Response({"warnings": warnings})


class SecatorWorkerCheckIn(APIView):
    """
    POST /worker/<worker_id>/check - Worker check-in to report status.
    Body: api_reachable (bool), last_error (str or null).
    Auth: Secator API key or session.
    """

    permission_classes = [HasAPIKeyOrIsAuthenticated]

    def post(self, request, worker_id):
        worker = get_object_or_404(SecatorWorker, pk=worker_id)
        try:
            data = request.data or {}
            if "api_reachable" in data:
                worker.api_reachable = bool(data["api_reachable"])
            if "last_error" in data:
                worker.last_error = data["last_error"] or None
            worker.last_status_at = timezone.now()
            worker.save(update_fields=["api_reachable", "last_error", "last_status_at"])
            from reNgine.utilities.websocket import send_worker_status_update

            send_worker_status_update(worker.id)
            return Response({"status": "ok"})
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "WORKER_CHECKIN",
                "Worker check-in failed for worker_id=%s: %s" % (worker_id, e),
                level="error",
                exc_info=True,
            )
            return Response(
                {"status": "error", "message": get_safe_user_message(e, logger)},
                status=400,
            )


class SecatorWorkerViewSet(viewsets.ModelViewSet):
    """
    CRUD + deploy/refresh/disable/delete for Secator workers.
    Requires IsAuthenticated (session or user API key).
    """

    permission_classes = [IsAuthenticated]
    queryset = SecatorWorker.objects.all().order_by("name")

    def get_serializer_class(self):
        if self.action == "list":
            return SecatorWorkerListSerializer
        if self.action in (
            "retrieve",
            "deploy",
            "refresh",
            "restart",
            "disable",
            "enable",
            "delete_worker",
            "sync_configs",
            "check_connection",
            "install_public_key",
        ):
            return SecatorWorkerDetailSerializer
        return SecatorWorkerCreateUpdateSerializer

    def get_queryset(self):
        return SecatorWorker.objects.all().order_by("name").prefetch_related("secatorrunner_set")

    @action(detail=True, methods=["post"], url_path="check-connection")
    def check_connection(self, request, pk=None):
        """Test SSH connection (password or key). Returns {ok: true/false, error?: string}."""
        worker = self.get_object()
        client = None
        try:
            client = get_ssh_client(worker)
            exit_code, _, _ = run_remote_command(client, "echo ok", timeout=10)
            if exit_code != 0:
                return Response(
                    {"ok": False, "error": "Connection failed."},
                    status=HTTP_400_BAD_REQUEST,
                )
            return Response({"ok": True})
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "WORKER_CHECK_CONNECTION",
                "Check connection failed for worker %s: %s" % (worker.name, e),
                level="warning",
            )
            return Response(
                {"ok": False, "error": "Connection failed."},
                status=HTTP_400_BAD_REQUEST,
            )
        finally:
            if client:
                try:
                    client.close()
                except Exception:
                    pass

    @action(detail=True, methods=["post"])
    def deploy(self, request, pk=None):
        """Start worker deploy in background; progress is streamed via WebSocket (worker-deploy-{id})."""
        worker = self.get_object()
        try:
            validate_deploy_path(worker.deploy_path)
        except ValueError as e:
            return Response(
                {"status": "error", "message": get_safe_user_message(e, logger)},
                status=HTTP_400_BAD_REQUEST,
            )

        from reNgine.utilities.websocket import send_worker_deploy_log, send_worker_status_update

        def progress_callback(step: str, message: str) -> None:
            send_worker_deploy_log(worker.id, step, message, done=False)

        def run_deploy() -> None:
            try:
                deploy_worker(worker, progress_callback=progress_callback)
                send_worker_deploy_log(worker.id, None, None, done=True)
                send_worker_status_update(worker.id)
            except Exception as e:
                logger.log_line(
                    PREFIX_API,
                    "WORKER_DEPLOY",
                    "Deploy failed for worker %s: %s" % (worker.name, e),
                    level="error",
                    exc_info=True,
                )
                safe_msg = get_safe_user_message(e, logger)
                send_worker_deploy_log(worker.id, "error", None, done=True, error=safe_msg)

        thread = threading.Thread(target=run_deploy, daemon=True)
        thread.start()
        return Response(
            {"status": "accepted", "worker_id": worker.id},
            status=HTTP_202_ACCEPTED,
        )

    @action(detail=True, methods=["post"])
    def refresh(self, request, pk=None):
        """Start worker status refresh in background; progress is streamed via WebSocket (worker-refresh-{id})."""
        worker = self.get_object()
        from reNgine.utilities.websocket import send_worker_refresh_log, send_worker_status_update

        def progress_callback(step: str, message: str) -> None:
            send_worker_refresh_log(worker.id, step, message, done=False)

        def run_refresh() -> None:
            tunnel_handle = None
            try:
                if worker.api_access_type == SecatorWorker.API_ACCESS_TUNNEL:
                    from scanEngine.services.worker_tunnel import start_worker_tunnel, stop_worker_tunnel

                    try:
                        tunnel_handle = start_worker_tunnel(worker)
                        if tunnel_handle:
                            progress_callback("tunnel", "SSH tunnel started.")
                    except ValueError as e:
                        send_worker_refresh_log(
                            worker.id, "error", None, done=True, error=get_safe_user_message(e, logger)
                        )
                        return
                status = refresh_worker_status(worker, progress_callback=progress_callback)
                worker.last_status_at = timezone.now()
                worker.last_error = status.get("last_error") or worker.last_error
                worker.ssh_ok = status.get("ssh_ok", False)
                worker.container_running = status.get("container_running", False)
                worker.api_reachable = status.get("api_reachable", False)
                worker.save(
                    update_fields=[
                        "last_status_at",
                        "last_error",
                        "ssh_ok",
                        "container_running",
                        "api_reachable",
                    ]
                )
                summary = (
                    f"SSH: ok, Container: {'running' if status.get('container_running') else 'not running'}, "
                    f"API: {'reachable' if status.get('api_reachable') else 'not reachable'}."
                )
                send_worker_refresh_log(
                    worker.id,
                    "done",
                    summary,
                    done=True,
                    ssh_ok=status.get("ssh_ok"),
                    container_running=status.get("container_running"),
                    api_reachable=status.get("api_reachable"),
                )
                send_worker_status_update(worker.id)
            except Exception as e:
                logger.log_line(
                    PREFIX_API,
                    "WORKER_REFRESH",
                    "Refresh failed for worker %s: %s" % (worker.name, e),
                    level="error",
                    exc_info=True,
                )
                send_worker_refresh_log(worker.id, "error", None, done=True, error=get_safe_user_message(e, logger))
            finally:
                if tunnel_handle is not None:
                    from scanEngine.services.worker_tunnel import stop_worker_tunnel

                    stop_worker_tunnel(tunnel_handle)

        thread = threading.Thread(target=run_refresh, daemon=True)
        thread.start()
        return Response(
            {"status": "accepted", "worker_id": worker.id},
            status=HTTP_202_ACCEPTED,
        )

    @action(detail=True, methods=["post"])
    def restart(self, request, pk=None):
        """Restart the worker container on the remote host. Returns {ok, log} for display in a modal."""
        worker = self.get_object()
        try:
            success, log = restart_worker_container(worker)
            if success:
                return Response({"ok": True, "log": log})
            return Response(
                {"ok": False, "log": log, "error": "Restart failed."},
                status=HTTP_400_BAD_REQUEST,
            )
        except ValueError as e:
            return Response(
                {"ok": False, "log": "", "error": str(e)},
                status=HTTP_400_BAD_REQUEST,
            )

    @action(detail=True, methods=["post"], url_path="install-public-key")
    def install_public_key(self, request, pk=None):
        """Connect with password, install default public key on host, verify key auth, then switch worker to key auth."""
        worker = self.get_object()
        if worker.ssh_auth_type != SecatorWorker.AUTH_PASSWORD:
            return Response(
                {"ok": False, "error": "Worker is not using password authentication."},
                status=HTTP_400_BAD_REQUEST,
            )
        if not (worker.ssh_password_encrypted or "").strip():
            return Response(
                {"ok": False, "error": "No password set for this worker."},
                status=HTTP_400_BAD_REQUEST,
            )
        pubkey_content = get_public_key_content()
        if not pubkey_content:
            return Response(
                {"ok": False, "error": "Public key not available."},
                status=HTTP_400_BAD_REQUEST,
            )
        client = None
        try:
            client = get_ssh_client(worker)
            install_public_key_on_host(client, pubkey_content)
            client.close()
            client = None
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "WORKER_INSTALL_KEY",
                "Install public key failed for worker %s: %s" % (worker.name, e),
                level="warning",
            )
            return Response(
                {"ok": False, "error": "Connection or install failed."},
                status=HTTP_400_BAD_REQUEST,
            )
        finally:
            if client:
                try:
                    client.close()
                except Exception:
                    pass

        key_test_client = None
        try:
            key_test_worker = type(
                "_KeyTest",
                (),
                {
                    "ssh_host": worker.ssh_host,
                    "ssh_port": worker.ssh_port,
                    "ssh_user": worker.ssh_user,
                    "ssh_auth_type": SecatorWorker.AUTH_KEY,
                    "ssh_key_path": "",
                    "ssh_password_encrypted": "",
                    "AUTH_KEY": SecatorWorker.AUTH_KEY,
                    "AUTH_PASSWORD": SecatorWorker.AUTH_PASSWORD,
                },
            )()
            key_test_client = get_ssh_client(key_test_worker)
            exit_code, _, _ = run_remote_command(key_test_client, "echo ok", timeout=10)
            key_test_client.close()
            key_test_client = None
            if exit_code != 0:
                return Response(
                    {"ok": False, "error": "Key installed but connection test failed."},
                    status=HTTP_400_BAD_REQUEST,
                )
        except Exception as e:
            logger.log_line(
                PREFIX_API,
                "WORKER_KEY_AUTH",
                "Key auth test failed for worker %s: %s" % (worker.name, e),
                level="warning",
            )
            return Response(
                {"ok": False, "error": "Key installed but connection test failed."},
                status=HTTP_400_BAD_REQUEST,
            )
        finally:
            if key_test_client:
                try:
                    key_test_client.close()
                except Exception:
                    pass

        worker.ssh_auth_type = SecatorWorker.AUTH_KEY
        worker.ssh_key_path = ""
        worker.ssh_password_encrypted = ""
        worker.save(update_fields=["ssh_auth_type", "ssh_key_path", "ssh_password_encrypted"])
        return Response({"ok": True})

    @action(detail=True, methods=["post"], url_path="sync-configs")
    def sync_configs(self, request, pk=None):
        """Sync all custom workflows, scans, tasks, and profiles to the worker."""
        worker = self.get_object()
        try:
            sync_all_custom_configs_to_worker(worker)
            return Response({"status": "ok", "message": "Configs synced successfully."})
        except (ValueError, RuntimeError) as e:
            return Response(
                {"status": "error", "message": get_safe_user_message(e, logger)},
                status=HTTP_400_BAD_REQUEST,
            )

    @action(detail=True, methods=["post"])
    def disable(self, request, pk=None):
        """Set worker is_active=False."""
        worker = self.get_object()
        worker.is_active = False
        worker.save(update_fields=["is_active"])
        from reNgine.utilities.websocket import send_worker_status_update

        send_worker_status_update(worker.id)
        return Response({"status": "ok", "message": "Worker disabled."})

    @action(detail=True, methods=["post"])
    def enable(self, request, pk=None):
        """Set worker is_active=True."""
        worker = self.get_object()
        worker.is_active = True
        worker.save(update_fields=["is_active"])
        from reNgine.utilities.websocket import send_worker_status_update

        send_worker_status_update(worker.id)
        return Response({"status": "ok", "message": "Worker enabled."})

    @action(detail=True, methods=["post"], url_path="delete")
    def delete_worker(self, request, pk=None):
        """Teardown on remote host (stop container, remove files) then delete worker from DB."""
        worker = self.get_object()
        worker_id = worker.id
        ok, err = teardown_worker_remote(worker)
        if not ok:
            return Response(
                {"status": "error", "message": err or "Teardown failed."},
                status=HTTP_400_BAD_REQUEST,
            )
        worker.delete()
        from reNgine.utilities.websocket import send_worker_status_update

        send_worker_status_update(worker_id)
        return Response({"status": "ok", "message": "Worker removed."})
