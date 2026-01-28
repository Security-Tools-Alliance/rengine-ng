from collections import defaultdict
from datetime import datetime
import json
import logging
import os.path
from pathlib import Path
import re
import threading

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.core.cache import cache
from django.db.models import Case, CharField, Count, F, IntegerField, Prefetch, Q, Value, When
from django.db.models.functions import Coalesce
from django.shortcuts import get_object_or_404
from django.template.defaultfilters import slugify
from django.urls import reverse
from django.utils import timezone
from packaging import version
import requests
from rest_framework import viewsets
from rest_framework.decorators import api_view
from rest_framework.exceptions import PermissionDenied
from rest_framework.parsers import JSONParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.status import HTTP_400_BAD_REQUEST
from rest_framework.views import APIView
import validators

from api.permissions import HasAPIKeyOrIsAuthenticated
from api.secator_api_base import SecatorAPIBase
from dashboard.models import OllamaSettings, OpenAiAPIKey, Project, SearchHistory
from recon_note.models import TodoNote

# NOTE: Legacy tasks removed (query_ip_history, query_reverse_whois, query_whois,
# run_cmseek, run_command, run_gf_list, run_wafw00f) - functionality now in Secator
from reNgine.core.data import get_data_from_post_request, safe_int_cast
from reNgine.core.path import is_safe_path
from reNgine.definitions import (
    ABORTED_TASK,
    FAILED_TASK,
    INITIATED_TASK,
    NUCLEI_SEVERITY_MAP,
    RUNNING_TASK,
    SUCCESS_TASK,
)
from reNgine.llm.config import DEFAULT_GPT_MODELS, MODEL_REQUIREMENTS, OLLAMA_INSTANCE, RECOMMENDED_MODELS
from reNgine.llm.llm import LLMAttackSuggestionGenerator
from reNgine.llm.utils import convert_markdown_to_html, get_default_llm_model, is_empty_attack_surface

# NOTE: Legacy task functions removed - functionality now in Secator
from reNgine.secator.service import start_secator_scan
from reNgine.services.repositories.scan_repository import ScanRepository
from reNgine.settings import RENGINE_CURRENT_VERSION
from reNgine.tasks import (
    llm_vulnerability_report,
    send_hackerone_report,
)
from reNgine.utilities.command import run_command
from reNgine.utilities.endpoint import get_interesting_endpoints
from reNgine.utilities.external import get_open_ai_key
from reNgine.utilities.lookup import get_lookup_keywords
from reNgine.utilities.subdomain import get_interesting_subdomains
from scanEngine.models import EngineType, SecatorScan, SecatorTask, SecatorWorkflow
from startScan.models import (
    Command,
    DirectoryFile,
    DirectoryScan,
    Dork,
    Email,
    Employee,
    EndPoint,
    IpAddress,
    LLMVulnerabilityReport,
    MetaFinderDocument,
    Port,
    ScanActivity,
    ScanHistory,
    Subdomain,
    SubScan,
    Technology,
    Vulnerability,
)
from targetApp.models import Domain, Organization

from .serializers import (
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
    InterestingEndPointSerializer,
    InterestingSubdomainSerializer,
    IpSerializer,
    IpSubdomainSerializer,
    MetafinderDocumentSerializer,
    MetafinderUserSerializer,
    OnlySubdomainNameSerializer,
    OrganizationSerializer,
    OrganizationTargetsSerializer,
    ProjectSerializer,
    ReconNoteSerializer,
    ScanActivitySerializer,
    ScanHistorySerializer,
    SearchHistorySerializer,
    SubdomainChangesSerializer,
    SubdomainSerializer,
    SubScanResultSerializer,
    SubScanSerializer,
    TechnologyCountSerializer,
    VisualiseDataSerializer,
    VulnerabilitySerializer,
)


logger = logging.getLogger(__name__)


def parse_pagination_params(start=None, length=None, page=None, page_size=None):
    """
    Validate and parse pagination parameters from query string.

    Supports two pagination modes:
    - DataTables style: start (offset) and length (page size)
    - REST style: page (page number, 1-indexed) and page_size

    Args:
        start: Starting offset for DataTables pagination
        length: Number of items per page for DataTables pagination
        page: Page number (1-indexed) for REST pagination
        page_size: Number of items per page for REST pagination

    Returns:
        dict: Parsed pagination parameters with 'type', 'start', and 'length' keys

    Raises:
        rest_framework.exceptions.ValidationError: If parameters are invalid
    """
    from rest_framework.exceptions import ValidationError

    try:
        if start is not None and length is not None:
            start_val = int(start)
            length_val = int(length)

            if start_val < 0:
                raise ValueError("Start offset must be non-negative")
            if length_val <= 0:
                raise ValueError("Length must be positive")
            if length_val > 10000:
                raise ValueError("Length exceeds maximum allowed value (10000)")

            return {"type": "datatables", "start": start_val, "length": length_val}

        elif page is not None and page_size is not None:
            page_val = int(page)
            page_size_val = int(page_size)

            if page_val < 1:
                raise ValueError("Page number must be at least 1")
            if page_size_val <= 0:
                raise ValueError("Page size must be positive")
            if page_size_val > 10000:
                raise ValueError("Page size exceeds maximum allowed value (10000)")

            start_val = (page_val - 1) * page_size_val
            return {"type": "rest", "start": start_val, "length": page_size_val, "page": page_val}

        return None

    except ValueError as e:
        logger.warning("Pagination parameter validation error: %s", str(e))
        raise ValidationError("Invalid pagination parameters.")


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
                                logger.debug(f"Ollama response: {data}")

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
                                logger.error(f"JSON decode error: {e}")
                                async_to_sync(channel_layer.group_send)(
                                    channel_name,
                                    {
                                        "type": "download_progress",
                                        "message": {"status": "error", "error": "Invalid response format"},
                                    },
                                )
                                break

                except Exception as e:
                    logger.error(f"Download error: {e}")
                    try:
                        async_to_sync(channel_layer.group_send)(
                            channel_name, {"type": "download_progress", "message": {"status": "error", "error": str(e)}}
                        )
                    except Exception as e2:
                        logger.error(f"Error sending error message: {e2}")
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
            logger.error(f"Error in OllamaManager: {e}")
            return Response({"status": False, "error": str(e)}, status=500)


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
            logger.error(f"Error in OllamaDetailManager DELETE: {str(e)}")
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
            logger.error(f"Error in OllamaDetailManager PUT: {str(e)}")
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
                    logger.warning(f"Ollama API returned status {response.status_code}")
                    for model in recommended_models:
                        model["installed"] = False
                        model["installed_versions"] = []
            except requests.exceptions.RequestException as e:
                logger.error(f"Error connecting to Ollama API: {str(e)}")
                for model in recommended_models:
                    model["installed"] = False
                    model["installed_versions"] = []

            response_data = {"status": True, "models": recommended_models}

            cache.set(cache_key, response_data, 300)
            return Response(response_data)

        except Exception as e:
            logger.error(f"Error in AvailableOllamaModels: {str(e)}")
            return Response({"status": False, "error": str(e)}, status=500)


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
            logger.error(f"Error deleting attack surface analysis: {str(e)}")
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
            logger.error(f"Error fetching default LLM model: {e}")
            selected_model = None

        try:
            is_gpt = False
            if selected_model:
                gpt_model_names = [model["name"] for model in DEFAULT_GPT_MODELS]
                is_gpt = selected_model in gpt_model_names
        except (KeyError, AttributeError) as e:
            logger.error(f"Error determining if selected model is GPT: {e}")
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
        task = llm_vulnerability_report.apply_async(args=(vulnerability_id, None, force_regenerate))
        response = task.wait()
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
            logger.error(f"Error deleting LLM vulnerability report: {str(e)}")
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
            logger.error(f"Error in CreateProjectApi: {str(e)}")
            return Response({"status": False, "message": "Failed to create project."}, status=HTTP_400_BAD_REQUEST)


class QueryInterestingSubdomains(APIView):
    def get(self, request):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        domain_id = safe_int_cast(req.query_params.get("target_id"))

        if scan_id:
            queryset = get_interesting_subdomains(scan_history=scan_id)
        elif domain_id:
            queryset = get_interesting_subdomains(domain_id=domain_id)
        else:
            queryset = get_interesting_subdomains()

        queryset = queryset.distinct("name")

        return Response(InterestingSubdomainSerializer(queryset, many=True).data)


class ListTargetsDatatableViewSet(viewsets.ModelViewSet):
    queryset = Domain.objects.all()
    serializer_class = DomainSerializer

    def get_queryset(self):
        if slug := self.request.GET.get("slug", None):
            self.queryset = self.queryset.filter(project__slug=slug)
        return self.queryset

    def filter_queryset(self, qs):
        qs = self.queryset.filter()
        search_value = self.request.GET.get("search[value]", None)
        _order_col = self.request.GET.get("order[0][column]", None)
        _order_direction = self.request.GET.get("order[0][dir]", None)
        if search_value or _order_col or _order_direction:
            order_col = "id"
            if _order_col == "2":
                order_col = "name"
            elif _order_col == "4":
                order_col = "insert_date"
            elif _order_col == "5":
                order_col = "start_scan_date"
                if _order_direction == "desc":
                    return qs.order_by(F("start_scan_date").desc(nulls_last=True))
                return qs.order_by(F("start_scan_date").asc(nulls_last=True))

            if _order_direction == "desc":
                order_col = f"-{order_col}"

            qs = self.queryset.filter(
                Q(name__icontains=search_value)
                | Q(description__icontains=search_value)
                | Q(domains__name__icontains=search_value)
            )
            return qs.order_by(order_col)

        return qs.order_by("-id")


class WafDetector(APIView):
    def get(self, request):
        req = self.request
        url = req.query_params.get("url")
        response = {"status": False, "message": "", "results": None}

        if not url:
            response["message"] = "URL parameter is missing"
            return Response(response)

        try:
            logger.debug(f"WAF detection for URL: {url} - Legacy function disabled, use Secator instead")
            response["message"] = "WAF detection is now handled by Secator. Please use the Secator scan interface."
            logger.debug(f"WAF detection result: {response}")
        except Exception as e:
            logger.error(f"Error during WAF detection: {str(e)}")
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

            vulnerabilities = (
                Vulnerability.objects.filter(target_domain__project__slug=project_slug)
                if project_slug
                else Vulnerability.objects.all()
            )

            # Optimize queries with prefetch_related to avoid N+1 queries
            vulnerabilities = vulnerabilities.prefetch_related(
                "cve_ids", "cwe_ids", "tags", "subdomain", "endpoint", "target_domain", "scan_history"
            )

            if scan_history_id:
                vuln_query = vulnerabilities.filter(scan_history__id=scan_history_id).values("name", "severity")
            elif target_id:
                vuln_query = vulnerabilities.filter(target_domain__id=target_id).values("name", "severity")
            else:
                vuln_query = vulnerabilities.values("name", "severity")

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
            logger.error(f"Error in FetchMostCommonVulnerability: {str(e)}")
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
            subdomains = Subdomain.objects.filter(target_domain__project=project)
            domains = Domain.objects.filter(project=project)
        else:
            subdomains = Subdomain.objects.all()
            domains = Domain.objects.all()

        if scan_history_id:
            subdomain_query = subdomains.filter(scan_history__id=scan_history_id)
            if is_ignore_info:
                most_vulnerable_subdomains = (
                    subdomain_query.annotate(
                        vuln_count=Count("vulnerability__name", filter=~Q(vulnerability__severity=0))
                    )
                    .order_by("-vuln_count")
                    .exclude(vuln_count=0)
                    .prefetch_related(
                        "ip_addresses",
                        "ip_addresses__ports",
                        "technologies",
                        "waf",
                        "directories",
                        "scan_history",
                        "target_domain",
                    )[:limit]
                )
            else:
                most_vulnerable_subdomains = (
                    subdomain_query.annotate(vuln_count=Count("vulnerability__name"))
                    .order_by("-vuln_count")
                    .exclude(vuln_count=0)[:limit]
                )

            if most_vulnerable_subdomains:
                response["status"] = True
                response["result"] = SubdomainSerializer(most_vulnerable_subdomains, many=True).data

        elif target_id:
            subdomain_query = subdomains.filter(target_domain__id=target_id)
            if is_ignore_info:
                most_vulnerable_subdomains = (
                    subdomain_query.annotate(
                        vuln_count=Count("vulnerability__name", filter=~Q(vulnerability__severity=0))
                    )
                    .order_by("-vuln_count")
                    .exclude(vuln_count=0)
                    .prefetch_related(
                        "ip_addresses",
                        "ip_addresses__ports",
                        "technologies",
                        "waf",
                        "directories",
                        "scan_history",
                        "target_domain",
                    )[:limit]
                )
            else:
                most_vulnerable_subdomains = (
                    subdomain_query.annotate(vuln_count=Count("vulnerability__name"))
                    .order_by("-vuln_count")
                    .exclude(vuln_count=0)
                    .prefetch_related(
                        "ip_addresses",
                        "ip_addresses__ports",
                        "technologies",
                        "waf",
                        "directories",
                        "scan_history",
                        "target_domain",
                    )[:limit]
                )

            if most_vulnerable_subdomains:
                response["status"] = True
                response["result"] = SubdomainSerializer(most_vulnerable_subdomains, many=True).data
        else:
            if is_ignore_info:
                most_vulnerable_targets = (
                    domains.annotate(
                        vuln_count=Count(
                            "subdomain__vulnerability__name", filter=~Q(subdomain__vulnerability__severity=0)
                        )
                    )
                    .order_by("-vuln_count")
                    .exclude(vuln_count=0)[:limit]
                )
            else:
                most_vulnerable_targets = (
                    domains.annotate(vuln_count=Count("subdomain__vulnerability__name"))
                    .order_by("-vuln_count")
                    .exclude(vuln_count=0)[:limit]
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
            logger.error(e)
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

        # Validate domain name
        if not validators.domain(domain_name):
            return Response({"status": False, "message": "Invalid domain or IP"}, status=400)

        project = Project.objects.get(slug=slug)

        # Check if the domain already exists
        if Domain.objects.filter(name=domain_name, project=project).exists():
            return Response({"status": False, "message": "Domain already exists as a target!"}, status=400)

        # Create domain object in DB
        domain, _ = Domain.objects.get_or_create(name=domain_name)
        domain.project = project
        domain.h1_team_handle = h1_team_handle
        domain.description = description
        if not domain.insert_date:
            domain.insert_date = timezone.now()
        domain.save()

        # Create org object in DB
        if organization_name:
            organization_obj, created = Organization.objects.get_or_create(
                name=organization_name, defaults={"project": project, "insert_date": timezone.now()}
            )
            organization_obj.domains.add(domain)

        return Response(
            {
                "status": True,
                "message": "Domain successfully added as target!",
                "domain_name": domain_name,
                "domain_id": domain.id,
                "initiate_scan_url": reverse("start_scan", kwargs={"slug": slug, "domain_id": domain.id}),
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

        if task_name == "port_scan":
            ips_in_subscan = IpAddress.objects.filter(ip_subscan_ids__in=subscan)
            subscan_results = IpSerializer(ips_in_subscan, many=True).data

        elif task_name == "vulnerability_scan":
            vulns_in_subscan = Vulnerability.objects.filter(vuln_subscan_ids__in=subscan)
            subscan_results = VulnerabilitySerializer(vulns_in_subscan, many=True).data

        elif task_name == "fetch_url":
            endpoints_in_subscan = EndPoint.objects.filter(endpoint_subscan_ids__in=subscan)
            subscan_results = EndpointSerializer(endpoints_in_subscan, many=True).data

        elif task_name == "dir_file_fuzz":
            dirs_in_subscan = DirectoryScan.objects.filter(dir_subscan_ids__in=subscan)
            subscan_results = DirectoryScanSerializer(dirs_in_subscan, many=True).data

        elif task_name == "subdomain_discovery":
            subdomains_in_subscan = Subdomain.objects.filter(subdomain_subscan_ids__in=subscan)
            subscan_results = SubdomainSerializer(subdomains_in_subscan, many=True).data

        elif task_name == "screenshot":
            endpoints_in_subscan = EndPoint.objects.filter(
                endpoint_subscan_ids__in=subscan, screenshot_path__isnull=False
            )
            subscan_results = EndpointSerializer(endpoints_in_subscan, many=True).data

        logger.info(subscan_data)
        logger.info(subscan_results)

        return Response(
            {
                "subscan": subscan_data,
                "result": subscan_results,
                "endpoint_url": reverse("api:endpoints-list"),
                "vulnerability_url": reverse("api:vulnerabilities-list"),
            }
        )


class ListSubScans(APIView):
    def post(self, request):
        req = self.request
        data = req.data
        subdomain_id = safe_int_cast(data.get("subdomain_id", None))
        scan_history = safe_int_cast(data.get("scan_history_id", None))
        domain_id = safe_int_cast(data.get("domain_id", None))
        response = {"status": False}

        if subdomain_id:
            subscans = SubScan.objects.filter(subdomain__id=subdomain_id).order_by("-stop_scan_date")
            results = SubScanSerializer(subscans, many=True).data
            if subscans:
                response["status"] = True
                response["results"] = results

        elif scan_history:
            subscans = SubScan.objects.filter(scan_history__id=scan_history).order_by("-stop_scan_date")
            results = SubScanSerializer(subscans, many=True).data
            if subscans:
                response["status"] = True
                response["results"] = results

        elif domain_id:
            scan_history = ScanHistory.objects.filter(domain__id=domain_id)
            subscans = SubScan.objects.filter(scan_history__in=scan_history).order_by("-stop_scan_date")
            results = SubScanSerializer(subscans, many=True).data
            if subscans:
                response["status"] = True
                response["results"] = results

        return Response(response)


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
            return Response({"status": False, "message": logger.debug(e)}, status=500)


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
                logger.error(e)
                response = {"status": False, "message": str(e)}
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
                logger.error(e)
                response = {"status": False, "message": str(e)}

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
            logger.error(e)
            return Response({"status": False, "message": str(e)}, status=HTTP_400_BAD_REQUEST)


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
            - domain_id (int): ID of the target domain
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
            - scan_existing_elements (bool): Whether to scan existing elements

        Returns:
            JSON response with scan details or error message
        """
        data = request.data
        if hasattr(data, "get"):
            domain_id = safe_int_cast(data.get("domain_id"), default=None)
        else:
            # Handle case where data is Empty or not a dict-like object
            domain_id = None

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
            scan_existing_elements = data.get("scan_existing_elements", False)
        else:
            secator_config = {}
            imported_subdomains = []
            out_of_scope_subdomains = []
            url_filter = ""
            scan_existing_elements = False

        # Call shared service to start scan
        result = start_secator_scan(
            domain_id=domain_id,
            user_id=request.user.id,
            execution_mode=execution_mode,
            workflow_id=workflow_id,
            task_ids=task_ids,
            secator_scan_type=secator_scan_type,
            secator_scan_id=secator_scan_id,
            imported_subdomains=imported_subdomains,
            out_of_scope_subdomains=out_of_scope_subdomains,
            url_filter=url_filter,
            scan_existing_elements=scan_existing_elements,
            secator_config=secator_config,
        )

        # Convert result to Response
        # Use explicit http_status from result, with fallback for backward compatibility
        http_status = result.get("http_status")
        if http_status is None:
            # Backward compatibility / safety net: derive a status code if not provided
            http_status = 200 if result.get("status") else 500
        return Response(result, status=http_status)


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

            # Get unique domains from subdomains
            domains = subdomains.values_list("target_domain", flat=True).distinct()
            if len(domains) > 1:
                return Response({"status": False, "error": "All subdomains must belong to the same domain"}, status=400)

            domain_id = domains[0]

        except Exception as e:
            return Response({"status": False, "error": f"Error retrieving subdomains: {str(e)}"}, status=400)

        # Create scan history for each subdomain and start scan
        scan_results = []

        for subdomain in subdomains:
            try:
                # Start scan using start_secator_scan service
                # Pass subdomain.name as imported_subdomains so it's the only target
                result = start_secator_scan(
                    domain_id=domain_id,
                    user_id=request.user.id,
                    execution_mode=execution_mode,
                    workflow_id=workflow_id_for_scan,
                    task_ids=task_ids_for_scan,
                    secator_scan_type=secator_scan_type,
                    imported_subdomains=[subdomain.name],
                    out_of_scope_subdomains=[],
                    url_filter="",
                    scan_existing_elements=False,
                    secator_config=secator_config,
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
                    logger.info(f"Secator subscan initiated for subdomain {subdomain.name} (ID: {subdomain.id})")
                else:
                    scan_results.append(
                        {
                            "subdomain_id": subdomain.id,
                            "subdomain_name": subdomain.name,
                            "status": "error",
                            "error": result.get("error", "Unknown error"),
                        }
                    )
                    logger.error(
                        f"Failed to start subscan for subdomain {subdomain.name}: {result.get('error', 'Unknown error')}"
                    )

            except Exception as e:
                logger.error(f"Error initiating subscan for subdomain {subdomain.name}: {e}")
                scan_results.append(
                    {"subdomain_id": subdomain.id, "subdomain_name": subdomain.name, "status": "error", "error": str(e)}
                )

        return Response(
            {
                "status": True,
                "message": f"Subscans initiated for {len(subdomain_ids)} subdomain(s)",
                "results": scan_results,
            }
        )


class GetSecatorSelection(APIView):
    """
    API endpoint to get Secator selection HTML (workflows, tasks, scans).

    This endpoint is used by the subscan modal to dynamically load selection options.
    Access is restricted to authenticated users and AJAX (XMLHttpRequest) requests.
    """

    http_method_names = ["get"]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from startScan.secator_ajax import render_secator_selection_json

        # Prefer AJAX requests to avoid exposing template HTML broadly
        # Note: This check is advisory - if other clients need access in future,
        # consider moving this enforcement to middleware or making it optional
        # DRF provides request.headers which is case-insensitive
        x_requested_with = request.headers.get("X-Requested-With", "")
        if x_requested_with != "XMLHttpRequest":
            # Log warning but allow request for future client compatibility
            logger = logging.getLogger(__name__)
            logger.warning(
                f"GetSecatorSelection accessed without X-Requested-With header "
                f"from {request.META.get('REMOTE_ADDR', 'unknown')}"
            )

        return render_secator_selection_json(request)


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
            return Response({"status": False, "message": logger.debug(e)}, status=500)


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
        github_api = "https://api.github.com/repos/Security-Tools-Alliance/rengine-ng/releases"
        response = requests.get(github_api).json()
        if "message" in response:
            return Response({"status": False, "message": "RateLimited"})

        return_response = {}

        # get current version_number
        # remove quotes from current_version
        current_version = (
            RENGINE_CURRENT_VERSION[1:] if RENGINE_CURRENT_VERSION[0] == "v" else RENGINE_CURRENT_VERSION
        ).replace("'", "")

        # for consistency remove v from both if exists
        latest_version = re.search(
            r"v(\d+\.)?(\d+\.)?(\*|\d+)",
            ((response[0]["name"])[1:] if response[0]["name"][0] == "v" else response[0]["name"]),
        )

        latest_version = latest_version.group(0) if latest_version else None

        if not latest_version:
            latest_version = re.search(
                r"(\d+\.)?(\d+\.)?(\*|\d+)",
                ((response[0]["name"])[1:] if response[0]["name"][0] == "v" else response[0]["name"]),
            )
            if latest_version:
                latest_version = latest_version.group(0)

        return_response["status"] = True
        return_response["latest_version"] = latest_version
        return_response["current_version"] = current_version
        return_response["update_available"] = version.parse(current_version) < version.parse(latest_version)
        if version.parse(current_version) < version.parse(latest_version):
            return_response["changelog"] = response[0]["body"]

        return Response(return_response)


class ScanStatus(APIView):
    def get(self, request):
        slug = self.request.GET.get("project", None)
        # main tasks
        recently_completed_scans = (
            ScanHistory.objects.filter(domain__project__slug=slug)
            .order_by("-start_scan_date")
            .filter(Q(scan_status=0) | Q(scan_status=2) | Q(scan_status=3))[:10]
        )
        current_scans = (
            ScanHistory.objects.filter(domain__project__slug=slug)
            .order_by("-start_scan_date")
            .filter(Q(scan_status=1) | Q(scan_status=4))
        )
        pending_scans = ScanHistory.objects.filter(domain__project__slug=slug).filter(scan_status=-1)

        # subtasks - use ScanActivity instead of SubScan for better visibility
        recently_completed_tasks = (
            ScanActivity.objects.filter(scan_of__domain__project__slug=slug)
            .order_by("-time")
            .filter(Q(status=FAILED_TASK) | Q(status=SUCCESS_TASK))[:15]
        )
        current_tasks = (
            ScanActivity.objects.filter(scan_of__domain__project__slug=slug)
            .order_by("-time")
            .filter(status=RUNNING_TASK)
        )
        # For pending tasks, we keep SubScan since ScanActivity don't have pending status
        pending_tasks = SubScan.objects.filter(scan_history__domain__project__slug=slug).filter(status=-1)
        response = {
            "scans": {
                "pending": ScanHistorySerializer(pending_scans, many=True).data,
                "scanning": ScanHistorySerializer(current_scans, many=True).data,
                "completed": ScanHistorySerializer(recently_completed_scans, many=True).data,
            },
            "tasks": {
                "pending": SubScanSerializer(pending_tasks, many=True).data,
                "running": ScanActivitySerializer(current_tasks, many=True).data,
                "completed": ScanActivitySerializer(recently_completed_tasks, many=True).data,
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
            logger.error(f"Error in CMSDetector: {str(e)}")
            return Response({"status": False, "message": "An unexpected error occurred."}, status=500)


class VulnerabilityReport(APIView):
    def get(self, request):
        req = self.request
        vulnerability_id = safe_int_cast(req.query_params.get("vulnerability_id"))
        return Response({"status": send_hackerone_report(vulnerability_id)})


class GetFileContents(APIView):
    def get(self, request, format=None):
        req = self.request
        name = req.query_params.get("name")

        response = {"status": False}

        if "nuclei_config" in req.query_params:
            path = str(Path.home() / ".config" / "nuclei" / "config.yaml")
            if not os.path.exists(path):
                run_command(f"touch {path}")
                response["message"] = "File Created!"
            with open(path, "r") as f:
                response["status"] = True
                response["content"] = f.read()
            return Response(response)

        if "subfinder_config" in req.query_params:
            path = str(Path.home() / ".config" / "subfinder" / "config.yaml")
            if not os.path.exists(path):
                run_command(f"touch {path}")
                response["message"] = "File Created!"
            with open(path, "r") as f:
                response["status"] = True
                response["content"] = f.read()
            return Response(response)

        if "naabu_config" in req.query_params:
            path = str(Path.home() / ".config" / "naabu" / "config.yaml")
            if not os.path.exists(path):
                run_command(f"touch {path}")
                response["message"] = "File Created!"
            with open(path, "r") as f:
                response["status"] = True
                response["content"] = f.read()
            return Response(response)

        if "theharvester_config" in req.query_params:
            path = str(Path.home() / ".config" / "theHarvester" / "api-keys.yaml")
            if not os.path.exists(path):
                run_command(f"touch {path}")
                response["message"] = "File Created!"
            with open(path, "r") as f:
                response["status"] = True
                response["content"] = f.read()
            return Response(response)

        if "amass_config" in req.query_params:
            path = str(Path.home() / ".config" / "amass" / "config.ini")
            if not os.path.exists(path):
                run_command(f"touch {path}")
                response["message"] = "File Created!"
            with open(path, "r") as f:
                response["status"] = True
                response["content"] = f.read()
            return Response(response)

        if "gf_pattern" in req.query_params:
            basedir = str(Path.home() / ".gf")
            path = str(Path.home() / ".gf" / f"{name}.json")
            if is_safe_path(basedir, path) and os.path.exists(path):
                with open(path, "r") as f:
                    content = f.read()
                response["status"] = True
                response["content"] = content
            else:
                response["message"] = "Invalid path!"
                response["status"] = False
            return Response(response)

        if "nuclei_template" in req.query_params:
            safe_dir = str(Path.home() / "nuclei-templates")
            path = str(Path.home() / "nuclei-templates" / f"{name}")
            if is_safe_path(safe_dir, path) and os.path.exists(path):
                with open(path.format(name), "r") as f:
                    content = f.read()
                response["status"] = True
                response["content"] = content
            else:
                response["message"] = "Invalid Path!"
                response["status"] = False
            return Response(response)

        if "gau_config" in req.query_params:
            path = str(Path.home() / ".config" / "gau" / "config.toml")
            if not os.path.exists(path):
                run_command(f"touch {path}")
                response["message"] = "File Created!"
            with open(path, "r") as f:
                response["status"] = True
                response["content"] = f.read()
            return Response(response)

        response["message"] = "Invalid Query Params"
        return Response(response)


class GfList(APIView):
    def get(self, request):
        try:
            # NOTE: GF patterns functionality moved to Secator
            return Response({"status": False, "message": "GF patterns functionality moved to Secator"})
        except Exception as e:
            logger.error(f"Error in GfList: {str(e)}")  # Log the exception for internal tracking
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
            notes = notes.filter(scan_history__in=ScanHistory.objects.filter(domain__id=target_id))
        elif scan_id:
            notes = notes.filter(scan_history__id=scan_id)
        if todo_id:
            notes = notes.filter(id=todo_id)
        if subdomain_id:
            notes = notes.filter(subdomain__id=subdomain_id)

        # Optimize queries with select_related to avoid N+1 queries
        notes = notes.select_related(
            "scan_history", "scan_history__domain", "subdomain", "subdomain__target_domain", "project"
        )

        notes = ReconNoteSerializer(notes, many=True)
        return Response({"notes": notes.data})


class ListScanHistory(APIView):
    def get(self, request, format=None):
        req = self.request
        scan_history = ScanHistory.objects.all().order_by("-start_scan_date")
        project = req.query_params.get("project")
        if project:
            scan_history = scan_history.filter(domain__project__slug=project)
        scan_history = ScanHistorySerializer(scan_history, many=True)
        return Response(scan_history.data)


class ListEngines(APIView):
    def get(self, request):
        engine_id = request.GET.get("engine_id")
        if engine_id:
            # Validate engine_id is a valid integer
            engine_id_int = safe_int_cast(engine_id)
            if engine_id_int is None:
                logger.warning(
                    "Invalid engine_id query parameter received",
                    extra={"engine_id": engine_id},
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
    def get(self, request, format=None):
        organizations = Organization.objects.all()
        organization_serializer = OrganizationSerializer(organizations, many=True)
        return Response({"organizations": organization_serializer.data})


class ListTargetsInOrganization(APIView):
    def get(self, request, format=None):
        req = self.request
        organization_id = safe_int_cast(req.query_params.get("organization_id"))
        try:
            organization = Organization.objects.get(id=organization_id)
            targets = Domain.objects.filter(domains=organization)
            organization_serializer = OrganizationSerializer(organization)
            targets_serializer = OrganizationTargetsSerializer(targets, many=True)
            return Response({"organization": organization_serializer.data, "domains": targets_serializer.data})
        except Organization.DoesNotExist:
            return Response({"error": "Organization not found"}, status=404)


class ListTargetsWithoutOrganization(APIView):
    def get(self, request, format=None):
        targets = Domain.objects.exclude(domains__in=Organization.objects.all())
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

        # Determine the queryset based on the presence of target_id or scan_id
        if target_id := safe_int_cast(req.query_params.get("target_id")):
            subdomain_filter = Subdomain.objects.filter(target_domain__id=target_id)
        elif scan_id:
            subdomain_filter = Subdomain.objects.filter(scan_history__id=scan_id)
        else:
            subdomain_filter = Subdomain.objects.all()

        # Fetch technologies and serialize the results with optimization
        tech = (
            Technology.objects.filter(technologies__in=subdomain_filter)
            .annotate(count=Count("name"))
            .order_by("-count")
        )

        # Optimize queries with select_related and prefetch_related to avoid N+1 queries
        tech = tech.select_related().prefetch_related("technologies", "techs")

        serializer = TechnologyCountSerializer(tech, many=True)

        return Response({"technologies": serializer.data})


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
            port_query = port_query.filter(ip_address__ip_addresses__target_domain__id=target_id).distinct()
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
            Subdomain.objects.filter(target_domain__project__slug=project) if project else Subdomain.objects.all()
        )

        if scan_id:
            subdomain_query = subdomains.filter(scan_history__id=scan_id).distinct("name")
        elif target_id:
            subdomain_query = subdomains.filter(target_domain__id=target_id).distinct("name")
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
        subdomain_query = subdomain_query.select_related("scan_history", "target_domain").prefetch_related(
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

        if pagination:
            total_count = subdomain_query.count()
            paginated_queryset = subdomain_query[pagination["start"] : pagination["start"] + pagination["length"]]

            if "no_lookup_interesting" in req.query_params:
                serializer = OnlySubdomainNameSerializer(paginated_queryset, many=True)
            else:
                serializer = SubdomainSerializer(paginated_queryset, many=True)

            return Response({"count": total_count, "results": serializer.data})

        # Default response (no pagination) - maintain backward compatibility
        if "no_lookup_interesting" in req.query_params:
            serializer = OnlySubdomainNameSerializer(subdomain_query, many=True)
        else:
            serializer = SubdomainSerializer(subdomain_query, many=True)
        return Response({"subdomains": serializer.data})

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
                ip_addresses__in=Subdomain.objects.filter(target_domain__id=target_id)
            ).distinct()
        elif scan_id:
            ips = IpAddress.objects.filter(
                ip_addresses__in=Subdomain.objects.filter(scan_history__id=scan_id)
            ).distinct()
        else:
            ips = IpAddress.objects.filter(ip_addresses__in=Subdomain.objects.all()).distinct()

        if port:
            ips = ips.filter(ports__in=Port.objects.filter(number=port)).distinct()

        serializer = IpSerializer(ips, many=True)
        return Response({"ips": serializer.data})


class IpAddressViewSet(viewsets.ModelViewSet):
    queryset = Subdomain.objects.none()
    serializer_class = IpSubdomainSerializer
    ordering = ("name",)

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

    def paginate_queryset(self, queryset, view=None):
        if "no_page" in self.request.query_params:
            return None
        return self.paginator.paginate_queryset(queryset.order_by(*self.ordering), self.request, view=self)


class SubdomainsViewSet(viewsets.ModelViewSet):
    queryset = Subdomain.objects.none()
    serializer_class = SubdomainSerializer
    ordering = ("name",)

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
                "target_domain",
                Prefetch(
                    "endpoint_set",
                    queryset=EndPoint.objects.filter(is_default=True),
                    to_attr="default_endpoint_list",
                ),
            )
            return queryset
        return Subdomain.objects.none()

    def paginate_queryset(self, queryset, view=None):
        if "no_page" in self.request.query_params:
            return None
        return self.paginator.paginate_queryset(queryset.order_by(*self.ordering), self.request, view=self)


class SubdomainChangesViewSet(viewsets.ModelViewSet):
    """
    This viewset will return the Subdomain changes
    To get the new subdomains, we will look for ScanHistory with
    subdomain_discovery = True and the status of the last scan has to be
    successful and calculate difference
    """

    queryset = Subdomain.objects.none()
    serializer_class = SubdomainChangesSerializer
    ordering = ("name",)

    def get_queryset(self):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        target_id = safe_int_cast(req.query_params.get("target_id"))
        project = req.query_params.get("project")

        if scan_id:
            # Get the current scan
            current_scan = ScanHistory.objects.get(id=scan_id)
            domain = current_scan.domain

            # Get all scans for this domain that have subdomain_discovery task
            scans_with_subdomain_discovery = (
                ScanHistory.objects.filter(domain=domain)
                .filter(tasks__overlap=["subdomain_discovery"])
                .filter(scan_status=2)  # SUCCESS
                .order_by("-start_scan_date")
            )

            if scans_with_subdomain_discovery.count() > 1:
                # Get the previous scan
                previous_scan = scans_with_subdomain_discovery[1]

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
                )
            else:
                # If this is the first scan, return empty queryset as changes are only meaningful from 2nd scan
                queryset = Subdomain.objects.none()
        elif target_id:
            queryset = Subdomain.objects.filter(target_domain__id=target_id).annotate(
                change=Value("unknown", output_field=CharField())
            )
        elif project:
            queryset = Subdomain.objects.filter(target_domain__project__slug=project).annotate(
                change=Value("unknown", output_field=CharField())
            )
        else:
            queryset = Subdomain.objects.all().annotate(change=Value("unknown", output_field=CharField()))

        # Optimize queries with prefetch_related to avoid N+1 queries
        queryset = queryset.prefetch_related(
            "ip_addresses", "ip_addresses__ports", "technologies", "waf", "directories", "scan_history", "target_domain"
        )

        return queryset

    def paginate_queryset(self, queryset, view=None):
        if "no_page" in self.request.query_params:
            return None
        return self.paginator.paginate_queryset(queryset.order_by(*self.ordering), self.request, view=self)


class EndPointChangesViewSet(viewsets.ModelViewSet):
    """
    This viewset will return the EndPoint changes
    """

    queryset = EndPoint.objects.none()
    serializer_class = EndPointChangesSerializer
    ordering = ("http_url",)

    def get_queryset(self):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        changes = req.query_params.get("changes")
        domain_id = safe_int_cast(ScanHistory.objects.filter(id=safe_int_cast(scan_id)).first().domain.id)
        scan_history = (
            ScanHistory.objects.filter(domain=domain_id)
            .filter(tasks__overlap=["subdomain_discovery"])
            .filter(id__lte=scan_id)
            .exclude(Q(scan_status=-1) | Q(scan_status=1))
        )
        if scan_history.count() > 1:
            last_scan = scan_history.order_by("-start_scan_date")[1]
            scanned_host_q1 = EndPoint.objects.filter(scan_history__id=scan_id).values("http_url")
            scanned_host_q2 = EndPoint.objects.filter(scan_history__id=last_scan.id).values("http_url")
            added_endpoint = scanned_host_q1.difference(scanned_host_q2)
            removed_endpoints = scanned_host_q2.difference(scanned_host_q1)
            if changes == "added":
                queryset = (
                    EndPoint.objects.filter(scan_history__id=scan_id)
                    .filter(http_url__in=added_endpoint)
                    .annotate(change=Value("added", output_field=CharField()))
                    .prefetch_related("subdomain", "target_domain", "scan_history", "techs")
                )
            elif changes == "removed":
                queryset = (
                    EndPoint.objects.filter(scan_history__id=last_scan.id)
                    .filter(http_url__in=removed_endpoints)
                    .annotate(change=Value("removed", output_field=CharField()))
                    .prefetch_related("subdomain", "target_domain", "scan_history", "techs")
                )
            else:
                added_endpoint = (
                    EndPoint.objects.filter(scan_history__id=scan_id)
                    .filter(http_url__in=added_endpoint)
                    .annotate(change=Value("added", output_field=CharField()))
                    .prefetch_related("subdomain", "target_domain", "scan_history", "techs")
                )
                removed_endpoints = (
                    EndPoint.objects.filter(scan_history__id=last_scan.id)
                    .filter(http_url__in=removed_endpoints)
                    .annotate(change=Value("removed", output_field=CharField()))
                    .prefetch_related("subdomain", "target_domain", "scan_history", "techs")
                )
                queryset = added_endpoint.union(removed_endpoints)
        else:
            # If this is the first scan, return empty queryset as changes are only meaningful from 2nd scan
            queryset = EndPoint.objects.none()

        return queryset

    def paginate_queryset(self, queryset, view=None):
        if "no_page" in self.request.query_params:
            return None
        return self.paginator.paginate_queryset(queryset.order_by(*self.ordering), self.request, view=self)


class InterestingSubdomainViewSet(viewsets.ModelViewSet):
    queryset = Subdomain.objects.none()
    serializer_class = SubdomainSerializer
    ordering = ("name",)

    def get_queryset(self):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        target_id = safe_int_cast(req.query_params.get("target_id"))

        if "only_subdomains" in self.request.query_params:
            self.serializer_class = InterestingSubdomainSerializer

        if scan_id:
            queryset = get_interesting_subdomains(scan_history=scan_id)
        elif target_id:
            queryset = get_interesting_subdomains(domain_id=target_id)
        else:
            queryset = get_interesting_subdomains()

        # Optimize queries with prefetch_related to avoid N+1 queries
        if hasattr(queryset, "prefetch_related"):
            queryset = queryset.prefetch_related(
                "ip_addresses",
                "ip_addresses__ports",
                "technologies",
                "waf",
                "directories",
                "scan_history",
                "target_domain",
            )

        self.queryset = queryset

        return self.queryset

    def filter_queryset(self, qs):
        qs = self.queryset.filter()
        search_value = self.request.GET.get("search[value]", None)
        _order_col = self.request.GET.get("order[0][column]", None)
        _order_direction = self.request.GET.get("order[0][dir]", None)
        order_col = "content_length"
        if _order_col == "0":
            order_col = "name"
        elif _order_col == "1":
            order_col = "page_title"
        elif _order_col == "2":
            order_col = "http_status"
        elif _order_col == "3":
            order_col = "content_length"

        if _order_direction == "desc":
            order_col = f"-{order_col}"

        if search_value:
            qs = self.queryset.filter(
                Q(name__icontains=search_value)
                | Q(page_title__icontains=search_value)
                | Q(http_status__icontains=search_value)
            )
        return qs.order_by(order_col)

    def paginate_queryset(self, queryset, view=None):
        if "no_page" in self.request.query_params:
            return None
        return self.paginator.paginate_queryset(queryset.order_by(*self.ordering), self.request, view=self)


class InterestingEndpointViewSet(viewsets.ModelViewSet):
    queryset = EndPoint.objects.none()
    serializer_class = EndpointSerializer
    ordering = ("http_url",)

    def get_queryset(self):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_id"))
        target_id = safe_int_cast(req.query_params.get("target_id"))

        if "only_endpoints" in self.request.query_params:
            self.serializer_class = InterestingEndPointSerializer
        if scan_id:
            queryset = get_interesting_endpoints(scan_history=scan_id)
        elif target_id:
            queryset = get_interesting_endpoints(target=target_id)
        else:
            queryset = get_interesting_endpoints()

        # Optimize queries with prefetch_related to avoid N+1 queries
        if hasattr(queryset, "prefetch_related"):
            queryset = queryset.prefetch_related("subdomain", "target_domain", "scan_history", "techs")

        return queryset

    def paginate_queryset(self, queryset, view=None):
        if "no_page" in self.request.query_params:
            return None
        return self.paginator.paginate_queryset(queryset.order_by(*self.ordering), self.request, view=self)


class SubdomainDatatableViewSet(AdvancedSearchMixin, viewsets.ModelViewSet):
    queryset = Subdomain.objects.none()
    serializer_class = SubdomainSerializer

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
        url_query = req.query_params.get("query_param")
        ip_address = req.query_params.get("ip_address")
        name = req.query_params.get("name")
        project = req.query_params.get("project")

        # Start with base query without ordering
        subdomains = Subdomain.objects.filter(target_domain__project__slug=project)

        if "is_important" in req.query_params:
            subdomains = subdomains.filter(is_important=True)

        if target_id:
            subdomains = subdomains.filter(target_domain__id=target_id)
        elif url_query:
            subdomains = subdomains.filter(Q(target_domain__name=url_query))
        elif scan_id:
            subdomains = subdomains.filter(scan_history__id=scan_id)

        if "only_directory" in req.query_params:
            subdomains = subdomains.exclude(directories__isnull=True)

        if ip_address:
            subdomains = subdomains.filter(ip_addresses__address__icontains=ip_address)

        if name:
            subdomains = subdomains.filter(name=name)

        # Get unique subdomains by name, keeping the latest (highest ID) for each name
        # Use a subquery to get the latest ID for each unique subdomain name
        from django.db.models import Max

        latest_subdomain_ids = subdomains.values("name").annotate(max_id=Max("id")).values_list("max_id", flat=True)
        self.queryset = Subdomain.objects.filter(id__in=latest_subdomain_ids)

        # Prefetching necessary relations for get_ports_by_ip
        self.queryset = self.queryset.prefetch_related(
            "ip_addresses",
            "ip_addresses__ports",
        )

        return self.queryset

    def general_lookup(self, queryset, search_value):
        """Override to add only_directory support."""
        qs = super().general_lookup(queryset, search_value)
        if "only_directory" in self.request.query_params:
            qs = qs | queryset.filter(Q(directories__directory_files__name__icontains=search_value))
        return qs

    def filter_queryset(self, qs):
        qs = self.queryset.filter()
        search_value = self.request.GET.get("search[value]", None)
        _order_col = self.request.GET.get("order[0][column]", None)
        _order_direction = self.request.GET.get("order[0][dir]", None)
        order_col = "content_length"
        if _order_col == "0":
            order_col = "checked"
        elif _order_col == "1":
            order_col = "name"
        elif _order_col == "4":
            order_col = "http_status"
        elif _order_col == "5":
            order_col = "page_title"
        elif _order_col == "8":
            order_col = "content_length"
        elif _order_col == "10":
            order_col = "response_time"
        if _order_direction == "desc":
            order_col = f"-{order_col}"

        if search_value:
            qs = self.apply_advanced_search(qs, search_value)

        return qs.order_by(order_col)


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
            endpoints = EndPoint.objects.filter(target_domain__id=target_id).distinct()
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


class EndPointViewSet(AdvancedSearchMixin, viewsets.ModelViewSet):
    queryset = EndPoint.objects.none()
    serializer_class = EndpointSerializer
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

        scan_id = safe_int_cast(req.query_params.get("scan_history"))
        target_id = safe_int_cast(req.query_params.get("target_id"))
        url_query = req.query_params.get("query_param")
        subdomain_id = safe_int_cast(req.query_params.get("subdomain_id"))
        project = req.query_params.get("project")

        endpoints_obj = EndPoint.objects.filter(scan_history__domain__project__slug=project)

        gf_tag = req.query_params.get("gf_tag") if "gf_tag" in req.query_params else None

        # Start with base query without ordering
        endpoints = endpoints_obj

        if scan_id:
            endpoints = endpoints.filter(scan_history__id=scan_id)

        if url_query:
            endpoints = endpoints.filter(Q(target_domain__name=url_query))

        if gf_tag:
            endpoints = endpoints.filter(matched_gf_patterns__icontains=gf_tag)

        if target_id:
            endpoints = endpoints.filter(target_domain__id=target_id)

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

    def filter_queryset(self, qs):
        qs = self.queryset.filter()
        search_value = self.request.GET.get("search[value]", None)
        _order_col = self.request.GET.get("order[0][column]", None)
        _order_direction = self.request.GET.get("order[0][dir]", None)
        if search_value or _order_col or _order_direction:
            order_col = "content_length"
            if _order_col == "1":
                order_col = "http_url"
            elif _order_col == "2":
                order_col = "http_status"
            elif _order_col == "3":
                order_col = "page_title"
            elif _order_col == "4":
                order_col = "matched_gf_patterns"
            elif _order_col == "5":
                order_col = "content_type"
            elif _order_col == "6":
                order_col = "content_length"
            elif _order_col == "7":
                order_col = "techs"
            elif _order_col == "8":
                order_col = "webserver"
            elif _order_col == "9":
                order_col = "response_time"
            if _order_direction == "desc":
                order_col = f"-{order_col}"

            # Use AdvancedSearchMixin for search functionality
            if search_value:
                qs = self.apply_advanced_search(qs, search_value)

            return qs.order_by(order_col)
        return qs

    def paginate_queryset(self, queryset, view=None):
        if "no_page" in self.request.query_params:
            return None
        return self.paginator.paginate_queryset(queryset.order_by("id"), self.request, view=self)

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        # Support manual pagination with start/length (DataTables) or page/page_size (REST)
        pagination = parse_pagination_params(
            start=request.query_params.get("start"),
            length=request.query_params.get("length"),
            page=request.query_params.get("page"),
            page_size=request.query_params.get("page_size"),
        )

        if pagination:
            total_count = queryset.count()
            paginated_queryset = queryset[pagination["start"] : pagination["start"] + pagination["length"]]
            serializer = self.get_serializer(paginated_queryset, many=True)
            return Response({"count": total_count, "results": serializer.data})

        # Fallback to normal pagination
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class DirectoryViewSet(viewsets.ModelViewSet):
    queryset = DirectoryFile.objects.none()
    serializer_class = DirectoryFileSerializer

    def get_queryset(self):
        req = self.request
        scan_id = safe_int_cast(req.query_params.get("scan_history"))
        subdomain_id = safe_int_cast(req.query_params.get("subdomain_id"))

        if not (scan_id or subdomain_id):
            return Response({"status": False, "message": "Scan id or subdomain id must be provided."})

        subdomains = (
            Subdomain.objects.filter(scan_history__id=scan_id) if scan_id else Subdomain.objects.filter(id=subdomain_id)
        )
        dirs_scans = DirectoryScan.objects.filter(directories__in=subdomains)

        return DirectoryFile.objects.filter(directory_files__in=dirs_scans).distinct().order_by("id")


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


class VulnerabilityViewSet(AdvancedSearchMixin, viewsets.ModelViewSet):
    queryset = Vulnerability.objects.none()
    serializer_class = VulnerabilitySerializer

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
            logger.warning(f"Invalid numeric value for cvss_score: {value}")
        return queryset

    @property
    def search_config(self):
        return {
            "general_fields": [
                lambda sv: Q(http_url__icontains=sv),
                lambda sv: Q(target_domain__name__icontains=sv),
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
            vulnerabilities = Vulnerability.objects.filter(scan_history__domain__project__slug=slug)
        else:
            vulnerabilities = Vulnerability.objects.all()

        if scan_id:
            qs = vulnerabilities.filter(scan_history__id=scan_id).distinct()
        elif target_id:
            qs = vulnerabilities.filter(target_domain__id=target_id).distinct()
        elif subdomain_name:
            subdomains = Subdomain.objects.filter(name=subdomain_name)
            qs = vulnerabilities.filter(subdomain__in=subdomains).distinct()
        else:
            qs = vulnerabilities.distinct()

        if domain:
            qs = qs.filter(Q(target_domain__name=domain)).distinct()
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
            "target_domain",
            "scan_history",
            "subdomain__scan_history",
            "subdomain__target_domain",
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

    def filter_queryset(self, qs):
        qs = self.queryset.filter()
        search_value = self.request.GET.get("search[value]", None)
        _order_col = self.request.GET.get("order[0][column]", None)
        _order_direction = self.request.GET.get("order[0][dir]", None)
        if search_value or _order_col or _order_direction:
            order_col = "severity"
            if _order_col == "1":
                order_col = "source"
            elif _order_col == "3":
                order_col = "name"
            elif _order_col == "7":
                order_col = "severity"
            elif _order_col == "11":
                order_col = "http_url"
            elif _order_col == "15":
                order_col = "open_status"

            if _order_direction == "desc":
                order_col = f"-{order_col}"

            # Use AdvancedSearchMixin for search functionality
            if search_value:
                qs = self.apply_advanced_search(qs, search_value)

            return qs.order_by(order_col)
        return qs.order_by("-severity")

    def paginate_queryset(self, queryset, view=None):
        if "no_page" in self.request.query_params:
            return None
        return self.paginator.paginate_queryset(queryset.order_by("-severity"), self.request, view=self)

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        # Support manual pagination with start/length (DataTables) or page/page_size (REST)
        pagination = parse_pagination_params(
            start=request.query_params.get("start"),
            length=request.query_params.get("length"),
            page=request.query_params.get("page"),
            page_size=request.query_params.get("page_size"),
        )

        if pagination:
            total_count = queryset.count()
            paginated_queryset = queryset[pagination["start"] : pagination["start"] + pagination["length"]]
            serializer = self.get_serializer(paginated_queryset, many=True)
            return Response({"count": total_count, "results": serializer.data})

        # Fallback to normal pagination
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


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
            ip_query = ip_query.filter(ip_addresses__target_domain__id=target_id)

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
                        logger.error(
                            f"Could not parse timestamp: {date_str}",
                            extra={"timestamp": date_str, "parsing_formats": formats},
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
                logger.error(f"Error fetching Ollama models: {str(e)}")

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
            logger.error(f"Error in LLMModelsManager GET: {str(e)}")
            return Response({"status": False, "error": "Failed to fetch LLM models", "message": str(e)}, status=500)


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
        return Response({"status": False, "error": str(e)}, status=500)


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
            endpoints_with_screenshots = endpoints_with_screenshots.filter(scan_history__domain__id=target_id)

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

            screenshots_data[subdomain_key] = {
                "name": subdomain.name,
                "http_url": endpoint.http_url,
                "page_title": endpoint.page_title or subdomain.page_title,
                "http_status": endpoint.http_status or subdomain.http_status,
                "screenshot_path": endpoint.screenshot_path,
                "is_interesting": subdomain.is_important,
                "endpoint_id": endpoint.id,
                "port": endpoint_port,  # Add port information
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
            return Response({"status": "error", "message": str(e)}, status=400)


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
            return Response({"status": "error", "message": str(e)}, status=400)


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
            return Response({"status": "error", "message": str(e)}, status=400)


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
            return Response({"status": "error", "message": str(e)}, status=400)


class LoadBuiltinTasks(APIView):
    """Load built-in tasks."""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            from io import StringIO

            from django.core.management import call_command

            # Capture output
            out = StringIO()
            call_command("load_secator_defaults", stdout=out)

            return Response(
                {"status": "success", "message": "Built-in tasks loaded successfully", "output": out.getvalue()}
            )
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=400)


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
            return Response({"status": "error", "message": str(e)}, status=400)


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
            return Response({"status": "error", "message": str(e)}, status=400)


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
            return Response({"status": "error", "message": str(e)}, status=400)


class GetWorkflowTasks(APIView):
    """Get tasks for a specific workflow."""

    permission_classes = [IsAuthenticated]

    def get(self, request, workflow_id):
        try:
            workflow = get_object_or_404(SecatorWorkflow, id=workflow_id)
            tasks = workflow.get_tasks()

            return Response({"status": "success", "tasks": tasks})

        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=400)


class GetAvailableTasks(APIView):
    """Get all available tasks for selection."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            tasks = SecatorTask.objects.all().values("id", "name", "task_type", "description")

            return Response({"status": "success", "tasks": list(tasks)})

        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=400)


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
            return Response({"status": "error", "message": str(e)}, status=400)


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
            return Response({"status": "error", "message": str(e)}, status=400)


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
            return Response({"status": "error", "message": str(e)}, status=400)


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
            return Response({"status": "error", "message": str(e)}, status=400)


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
            return Response({"status": "error", "message": str(e)}, status=400)


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
            return Response({"status": "error", "message": str(e)}, status=400)


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
            return Response({"status": "error", "message": str(e)}, status=400)


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
            return Response({"status": "error", "message": str(e)}, status=400)


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
            return Response({"status": "error", "message": str(e)}, status=400)


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
            return Response({"status": "error", "message": str(e)}, status=400)


class SecatorRunnerCreate(SecatorAPIBase):
    """
    API endpoint to create a runner from Secator hooks.
    This endpoint is called by Secator workers to register new runners.
    """

    permission_classes = [HasAPIKeyOrIsAuthenticated]

    def post(self, request):
        try:
            from startScan.models import Domain, ScanHistory, SecatorRunner

            runner_data = request.data

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
            domain_id = context.get("domain_id")

            # Create runner object in database
            secator_runner = SecatorRunner(
                runner_type=runner_type,
                runner_name=runner_name,
                runner_data=runner_data,
            )

            # Link to scan history if available
            if scan_history_id:
                try:
                    scan_history = ScanHistory.objects.get(id=scan_history_id)
                    secator_runner.scan_history = scan_history
                except ScanHistory.DoesNotExist:
                    self.logger.log_warning(
                        f"ScanHistory {scan_history_id} not found, skipping link",
                        {"prefix": self.logger.PREFIX_SYNC, "action": "CREATE", "scan_id": scan_history_id},
                    )

            # Link to domain if available
            if domain_id:
                try:
                    domain = Domain.objects.get(id=domain_id)
                    secator_runner.domain = domain
                except Domain.DoesNotExist:
                    self.logger.log_warning(
                        f"Domain {domain_id} not found, skipping link",
                        {"prefix": self.logger.PREFIX_SYNC, "action": "CREATE", "domain_id": domain_id},
                    )

            # Save runner and get its ID
            secator_runner.save()
            runner_id = str(secator_runner.id)

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
                {"prefix": self.logger.PREFIX_SYNC, "action": "CREATE", "error": str(e)},
                exc_info=True,
            )
            return Response({"status": False, "error": str(e)}, status=500)


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

                # Sync with ScanHistory if scan_history is linked
                if secator_runner.scan_history:
                    self._sync_runner_with_scan_history(secator_runner, runner_data)

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
                return Response({"status": False, "error": str(e)}, status=400)
            return Response({"status": False, "error": str(e)}, status=500)

    def _is_all_runners_completed(self, scan_history_id: int) -> bool:
        """
        Check if all runners for this scan are completed.
        Works for both workflow scans (checks all runners) and task-only scans.

        Args:
            scan_history_id: ID of the scan history

        Returns:
            bool: True if all runners are done, False otherwise
        """
        from startScan.models import SecatorRunner

        # Get all runners for this scan
        runners = SecatorRunner.objects.filter(scan_history_id=scan_history_id)

        if not runners.exists():
            self.logger.log_debug(
                self.logger.PREFIX_SYNC,
                "CHECK",
                f"_is_all_runners_completed: No runners found for scan {scan_history_id}",
            )
            return False

        # Check if all runners are done
        incomplete_runners = []
        for runner in runners:
            if runner.runner_data:
                done = runner.runner_data.get("done", False)
                status = runner.runner_data.get("status", "").upper()
                runner_name = runner.runner_name or runner.runner_data.get("name", "Unknown")
                runner_type = runner.runner_type or runner.runner_data.get("config", {}).get("type", "unknown")
                # If any runner is not done or still running, scan is not completed
                if not done or status == "RUNNING":
                    incomplete_runners.append(f"{runner_name} (type={runner_type}, status={status}, done={done})")

        if incomplete_runners:
            self.logger.log_debug(
                self.logger.PREFIX_SYNC,
                "CHECK",
                f"_is_all_runners_completed: Scan {scan_history_id} NOT completed. "
                f"Incomplete runners: {', '.join(incomplete_runners)}",
            )
            return False

        self.logger.log_debug(
            self.logger.PREFIX_SYNC,
            "CHECK",
            f"_is_all_runners_completed: Scan {scan_history_id} is fully completed. "
            f"Total runners checked: {runners.count()}",
        )
        return True

    def _sync_runner_with_scan_history(self, secator_runner, runner_data):
        """
        Synchronize runner data with ScanHistory and create/update ScanActivity.

        Args:
            secator_runner: SecatorRunner instance
            runner_data: Runner data from Secator
        """
        from django.utils import timezone

        from reNgine.utilities.websocket import send_scan_status_update
        from startScan.models import ScanActivity, SecatorRunner

        scan_history = secator_runner.scan_history
        scan_repo = ScanRepository()

        # Extract runner status and progress
        runner_status = runner_data.get("status", "").upper()
        runner_done = runner_data.get("done", False)
        runner_name = runner_data.get("name") or secator_runner.runner_name or "Unknown"
        runner_type = runner_data.get("config", {}).get("type", "") or secator_runner.runner_type

        # Map Secator status to reNgine status
        status_map = {
            "RUNNING": RUNNING_TASK,
            "SUCCESS": SUCCESS_TASK,
            "FAILURE": FAILED_TASK,
            "FAILED": FAILED_TASK,
            "PENDING": INITIATED_TASK,
        }
        rengine_status = status_map.get(runner_status, INITIATED_TASK)

        # Debug: Log current state
        self.logger.log_debug(
            self.logger.PREFIX_SYNC,
            "SYNC",
            f"Runner update request - "
            f"Runner: {runner_name} (type={runner_type}, id={secator_runner.id}), "
            f"Secator status: {runner_status}, done: {runner_done}, "
            f"ScanHistory current status: {scan_history.scan_status}, "
            f"Proposed reNgine status: {rengine_status}",
        )

        # Determine if this runner can update the global status
        # Case 1: Runner workflow/scan -> always allowed
        # Case 2: Runner task -> allowed only if scan has no workflow/scan runner
        has_workflow_or_scan_runner = SecatorRunner.objects.filter(
            scan_history_id=scan_history.id, runner_type__in=["workflow", "scan"]
        ).exists()

        can_update_status = runner_type in ["workflow", "scan"] or (
            runner_type == "task" and not has_workflow_or_scan_runner
        )

        self.logger.log_debug(
            self.logger.PREFIX_SYNC,
            "SYNC",
            f"Permission check - "
            f"has_workflow_or_scan_runner: {has_workflow_or_scan_runner}, "
            f"can_update_status: {can_update_status}",
        )

        if can_update_status:
            # Do not downgrade status if scan is already in progress
            if runner_status == "PENDING" and scan_history.scan_status in [RUNNING_TASK, SUCCESS_TASK]:
                self.logger.log_debug(
                    self.logger.PREFIX_SYNC,
                    "BLOCKED",
                    f"Ignoring PENDING status for runner {runner_name} "
                    f"(type={runner_type}) - scan already in progress. "
                    f"Current ScanHistory status: {scan_history.scan_status}, "
                    f"Would set to: {rengine_status}",
                )
            # For SUCCESS, verify that all runners are really completed
            elif runner_status == "SUCCESS":
                self.logger.log_debug(
                    self.logger.PREFIX_SYNC,
                    "SUCCESS",
                    f"Processing SUCCESS status - "
                    f"Runner: {runner_name} (type={runner_type}), done: {runner_done}, "
                    f"Current ScanHistory status: {scan_history.scan_status}",
                )
                if runner_done:
                    # Verify that all runners are completed
                    all_completed = self._is_all_runners_completed(scan_history.id)
                    self.logger.log_debug(
                        self.logger.PREFIX_SYNC,
                        "CHECK",
                        f"All runners completed check: {all_completed} for scan {scan_history.id}",
                    )
                    if all_completed:
                        old_status = scan_history.scan_status
                        scan_history.scan_status = rengine_status
                        if not scan_history.stop_scan_date:
                            scan_history.stop_scan_date = timezone.now()
                        scan_history.save(update_fields=["scan_status", "stop_scan_date"])
                        self.logger.log_runner_sync(
                            "SUCCESS",
                            runner_name,
                            runner_type,
                            runner_status,
                            scan_history.id,
                            {
                                "old_status": old_status,
                                "new_status": rengine_status,
                                "stop_scan_date": scan_history.stop_scan_date,
                            },
                        )
                        # Send WebSocket update
                        send_scan_status_update(scan_history.id)
                    else:
                        # Not all runners are completed yet, keep RUNNING
                        old_status = scan_history.scan_status
                        scan_history.scan_status = RUNNING_TASK
                        scan_history.save(update_fields=["scan_status"])
                        self.logger.log_debug(
                            self.logger.PREFIX_SYNC,
                            "KEEP_RUNNING",
                            f"Scan {scan_history.id} not fully completed yet. "
                            f"Status changed from {old_status} to {RUNNING_TASK} by runner {runner_name} "
                            f"(type={runner_type})",
                        )
                        # Send WebSocket update
                        send_scan_status_update(scan_history.id)
                else:
                    # Runner in SUCCESS but not yet done, keep RUNNING
                    old_status = scan_history.scan_status
                    scan_history.scan_status = RUNNING_TASK
                    scan_history.save(update_fields=["scan_status"])
                    self.logger.log_debug(
                        self.logger.PREFIX_SYNC,
                        "KEEP_RUNNING",
                        f"Runner {runner_name} (type={runner_type}) "
                        f"in SUCCESS but not done. Status changed from {old_status} to {RUNNING_TASK}",
                    )
                    # Send WebSocket update
                    send_scan_status_update(scan_history.id)
            # For RUNNING, FAILURE, FAILED
            elif runner_status in ["RUNNING", "FAILURE", "FAILED"]:
                old_status = scan_history.scan_status
                scan_history.scan_status = rengine_status
                if runner_done and runner_status in ["FAILURE", "FAILED"] and not scan_history.stop_scan_date:
                    scan_history.stop_scan_date = timezone.now()
                scan_history.save(update_fields=["scan_status", "stop_scan_date"])
                self.logger.log_runner_sync(
                    "UPDATED",
                    runner_name,
                    runner_type,
                    runner_status,
                    scan_history.id,
                    {
                        "old_status": old_status,
                        "new_status": rengine_status,
                        "done": runner_done,
                        "stop_scan_date": scan_history.stop_scan_date,
                    },
                )
                # Send WebSocket update
                send_scan_status_update(scan_history.id)
        else:
            self.logger.log_debug(
                self.logger.PREFIX_SYNC,
                "SKIPPED",
                f"Runner {runner_name} (type={runner_type}) "
                f"cannot update global status. Current ScanHistory status: {scan_history.scan_status}",
            )

        # Extract reports_folder from run_opts for results_dir
        run_opts = runner_data.get("run_opts", {})
        reports_folder = run_opts.get("reports_folder")

        # Create or update ScanActivity
        activity_title = f"{runner_type.title()}: {runner_name}"

        # Check if activity already exists for this runner
        existing_activity = (
            ScanActivity.objects.filter(scan_of=scan_history, name=runner_name, runner_id=secator_runner)
            .order_by("-time")
            .first()
        )

        if existing_activity:
            # Update existing activity
            existing_activity.status = rengine_status
            existing_activity.time = timezone.now()
            if runner_done and runner_status in ["SUCCESS", "FAILURE", "FAILED"]:
                existing_activity.title = f"{activity_title} - Completed"
            if reports_folder:
                existing_activity.results_dir = reports_folder
            update_fields = ["status", "time", "title"]
            if reports_folder:
                update_fields.append("results_dir")
            existing_activity.save(update_fields=update_fields)
            self.logger.log_debug(
                self.logger.PREFIX_SYNC,
                "ACTIVITY",
                f"Updated ScanActivity {existing_activity.id} for runner {runner_name}",
            )
        else:
            # Create new activity
            activity_id = scan_repo.create_activity(scan_history.id, activity_title, rengine_status)
            # Update the newly created activity with runner_id, name, and results_dir
            try:
                new_activity = ScanActivity.objects.get(id=activity_id)
                new_activity.runner_id = secator_runner
                new_activity.name = runner_name
                if reports_folder:
                    new_activity.results_dir = reports_folder
                update_fields = ["runner_id", "name"]
                if reports_folder:
                    update_fields.append("results_dir")
                new_activity.save(update_fields=update_fields)
                self.logger.log_debug(
                    self.logger.PREFIX_SYNC,
                    "ACTIVITY",
                    f"Created ScanActivity {activity_id} for runner {runner_name}",
                )
            except ScanActivity.DoesNotExist:
                self.logger.log_warning(
                    f"Could not find newly created ScanActivity {activity_id}",
                    {"prefix": self.logger.PREFIX_SYNC, "action": "SYNC", "runner": runner_name},
                )

        self.logger.log_runner_sync(
            "SYNC",
            runner_name,
            runner_type,
            runner_status,
            scan_history.id,
            {},
        )

        # Save command log from runner data
        try:
            from reNgine.services.repositories.command_repository import CommandRepository

            command_repo = CommandRepository()
            activity_id_for_command = existing_activity.id if existing_activity else activity_id
            command_repo.save_from_secator(runner_data, scan_history.id, activity_id_for_command)
        except Exception as e:
            self.logger.log_warning(
                f"Error saving command log for runner {runner_name}: {e}",
                {"prefix": self.logger.PREFIX_SYNC, "action": "SYNC", "runner": runner_name},
            )

        # Send WebSocket update for runner status/progress changes
        # This ensures real-time updates even when status doesn't change
        runner_progress = runner_data.get("progress")
        if isinstance(runner_progress, (int, float)) and runner_progress >= 0:
            self.logger.log_debug(
                self.logger.PREFIX_SYNC,
                "WEBSOCKET",
                f"Sending progress update for scan {scan_history.id} - "
                f"Runner: {runner_name}, Progress: {runner_progress}%, Status: {runner_status}",
            )
        else:
            self.logger.log_debug(
                self.logger.PREFIX_SYNC,
                "WEBSOCKET",
                f"Sending runner update for scan {scan_history.id} - "
                f"Runner: {runner_name}, Status: {runner_status} (no progress data)",
            )
        send_scan_status_update(scan_history.id)


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
            domain_id = context_info["domain_id"]
            context = finding_data.get("_context", {})

            if not finding_type:
                return Response({"status": False, "error": "Missing _type in finding data"}, status=400)

            # Get repository for finding type
            repository_class = self.get_repository_for_finding_type(finding_type)
            if not repository_class:
                self.logger.log_unknown_type("finding", finding_type)
                import time

                finding_id = f"{finding_type}_{int(time.time() * 1000)}"
                return Response({"status": True, "id": finding_id})

            # Validate scan context
            is_valid, error_response, scan_history, domain = self.validate_scan_context(
                scan_history_id, domain_id, finding_type
            )
            if not is_valid:
                return error_response

            # Instantiate repository and save finding
            repository = repository_class()
            self.logger.log_debug(
                self.logger.PREFIX_FINDING, "CREATE", f"Using repository: {repository_class.__name__}"
            )
            self.logger.log_debug(
                self.logger.PREFIX_FINDING,
                "CREATE",
                f"Calling save_from_secator with finding_data (keys: {list(finding_data.keys())})",
            )

            try:
                if finding_type == "subdomain":
                    self.logger.log_debug(
                        self.logger.PREFIX_FINDING, "CREATE", f"Saving subdomain with context: {context}"
                    )
                    saved_object = repository.save_from_secator(
                        finding_data, scan_history_id, domain_id, rengine_context=context
                    )
                else:
                    saved_object = repository.save_from_secator(finding_data, scan_history_id, domain_id)

                # Check if save was successful
                if saved_object is None:
                    self.logger.log_finding_save(
                        "CREATE",
                        finding_type,
                        None,
                        scan_history_id,
                        domain_id,
                        success=False,
                        error_message="Repository returned None - validation error or missing required fields",
                    )
                    return Response(
                        {
                            "status": False,
                            "error": f"Failed to save {finding_type} finding. Validation error or missing required fields.",
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
                        domain_id,
                        success=True,
                    )
                    return Response({"status": True, "id": finding_id})
                else:
                    self.logger.log_finding_save(
                        "CREATE",
                        finding_type,
                        saved_object,
                        scan_history_id,
                        domain_id,
                        success=False,
                        error_message="Saved object has no 'id' attribute",
                    )
                    return Response({"status": False, "error": "Saved object has no ID attribute"}, status=500)

            except Exception as e:
                return self.handle_repository_error(e, finding_type, scan_history_id, domain_id)

        except Exception as e:
            self.logger.log_error(
                e,
                {"prefix": self.logger.PREFIX_FINDING, "action": "CREATE", "error": str(e)},
                exc_info=True,
            )
            return Response({"status": False, "error": str(e)}, status=500)


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
            domain_id = context_info["domain_id"]

            if not finding_type:
                self.logger.log_warning(
                    f"Missing _type in finding data for finding_id={finding_id}",
                    {"prefix": self.logger.PREFIX_FINDING, "action": "UPDATE", "id": finding_id},
                )
                return Response({"status": False, "error": "Missing _type in finding data"}, status=400)

            # Get repository for finding type
            repository_class = self.get_repository_for_finding_type(finding_type)
            if not repository_class:
                # Check if it's a metadata type that should be ignored
                if self.is_metadata_type(finding_type):
                    self.logger.log_metadata_ignored(finding_type, finding_id)
                    return Response({"status": True, "message": f"Ignored metadata type: {finding_type}"}, status=200)

                self.logger.log_unknown_type("finding", finding_type, finding_id)
                return Response({"status": False, "error": f"Unknown finding type: {finding_type}"}, status=400)

            # Validate scan context
            is_valid, error_response, scan_history, domain = self.validate_scan_context(
                scan_history_id, domain_id, finding_type, prefix=self.logger.PREFIX_FINDING
            )
            if not is_valid:
                return error_response

            # Instantiate repository and save finding (upsert: create or update)
            repository = repository_class()
            self.logger._logger.debug(
                self.logger._format_debug_message(
                    self.logger.PREFIX_FINDING,
                    "UPDATE",
                    f"Using repository: {repository_class.__name__} "
                    f"for finding type: {finding_type}, finding_id: {finding_id}",
                )
            )

            try:
                if finding_type == "subdomain":
                    self.logger._logger.debug(
                        self.logger._format_debug_message(
                            self.logger.PREFIX_FINDING,
                            "UPDATE",
                            f"Saving subdomain with context: {context}, finding_id: {finding_id}",
                        )
                    )
                    saved_object = repository.save_from_secator(
                        finding_data, scan_history_id, domain_id, rengine_context=context
                    )
                else:
                    saved_object = repository.save_from_secator(finding_data, scan_history_id, domain_id)

                # Check if save was successful
                if saved_object is None:
                    self.logger.log_finding_save(
                        "UPDATE",
                        finding_type,
                        None,
                        scan_history_id,
                        domain_id,
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
                        domain_id,
                        success=True,
                    )
                    return Response({"status": True, "id": saved_finding_id})
                else:
                    self.logger.log_finding_save(
                        "UPDATE",
                        finding_type,
                        saved_object,
                        scan_history_id,
                        domain_id,
                        success=False,
                        error_message="Saved object has no 'id' attribute",
                    )
                    return Response({"status": False, "error": "Saved object has no ID attribute"}, status=500)

            except Exception as e:
                return self.handle_repository_error(e, finding_type, scan_history_id, domain_id, finding_id)

        except Exception as e:
            self.logger.log_error(
                e,
                {"prefix": self.logger.PREFIX_FINDING, "action": "UPDATE", "id": finding_id},
                exc_info=True,
            )
            # Check if it's a validation error that should return 400
            error_str = str(e).lower()
            if "validation" in error_str or "invalid" in error_str or "required" in error_str:
                return Response({"status": False, "error": str(e)}, status=400)
            return Response({"status": False, "error": str(e)}, status=500)
