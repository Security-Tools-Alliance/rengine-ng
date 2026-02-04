from django.contrib import admin
from django.utils.html import format_html

# Scan file links use build_scan_file_url; access control in api.scan_file.ServeScanFile
from api.scan_file import build_scan_file_url
from reNgine.admin_common import (
    SimpleLookupModelAdmin,
    TimestampedModelAdminMixin,
    build_fieldsets_with_timestamps,
)
from startScan.models import (
    Command,
    CountryISO,
    CveId,
    CweId,
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
    S3Bucket,
    ScanActivity,
    ScanHistory,
    SecatorRunner,
    Subdomain,
    SubScan,
    Technology,
    Vulnerability,
    VulnerabilityTags,
    Waf,
)


@admin.register(ScanHistory)
class ScanHistoryAdmin(admin.ModelAdmin):
    """Admin interface for ScanHistory model with legacy scan support."""

    list_display = [
        "domain",
        "scan_type",
        "is_legacy_scan",
        "scan_status",
        "start_scan_date",
        "stop_scan_date",
        "initiated_by",
    ]
    list_filter = [
        "is_legacy_scan",
        "scan_status",
        "scan_type__scan_type",
        "start_scan_date",
        "initiated_by",
    ]
    search_fields = [
        "domain__name",
        "scan_type__name",
        "initiated_by__username",
    ]
    readonly_fields = [
        "start_scan_date",
        "stop_scan_date",
        "results_dir",
        "tasks",
    ]
    fieldsets = (
        ("Scan Information", {"fields": ("domain", "scan_type", "is_legacy_scan", "scan_status")}),
        (
            "Execution Details",
            {
                "fields": ("start_scan_date", "stop_scan_date", "results_dir", "tasks", "error_message"),
                "classes": ("collapse",),
            },
        ),
        (
            "User Information",
            {
                "fields": ("initiated_by", "aborted_by"),
            },
        ),
        (
            "Results",
            {
                "fields": ("emails", "employees", "buckets", "dorks", "used_gf_patterns"),
                "classes": ("collapse",),
            },
        ),
    )
    filter_horizontal = [
        "emails",
        "employees",
        "buckets",
        "dorks",
    ]


@admin.register(SubScan)
class SubScanAdmin(admin.ModelAdmin):
    """Admin interface for SubScan model."""

    list_display = [
        "id",
        "type",
        "status",
        "scan_history",
        "subdomain",
        "start_scan_date",
        "stop_scan_date",
    ]
    list_filter = [
        "type",
        "status",
        "start_scan_date",
    ]
    search_fields = [
        "type",
        "error_message",
    ]
    readonly_fields = [
        "start_scan_date",
        "stop_scan_date",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("type", "status", "scan_history", "subdomain", "engine", "secator_runner")},
        ),
        (
            "Execution",
            {
                "fields": ("start_scan_date", "stop_scan_date", "error_message"),
                "classes": ("collapse",),
            },
        ),
        (
            "Subdomain Subscan IDs",
            {"fields": ("subdomain_subscan_ids",), "classes": ("collapse",)},
        ),
    )
    filter_horizontal = [
        "subdomain_subscan_ids",
    ]


@admin.register(Subdomain)
class SubdomainAdmin(admin.ModelAdmin):
    """Admin interface for Subdomain model."""

    list_display = [
        "name",
        "target_domain",
        "scan_history",
        "is_important",
        "http_status",
        "discovered_date",
    ]
    list_filter = [
        "is_important",
        "is_imported_subdomain",
        "is_cdn",
        "verified",
        "discovered_date",
    ]
    search_fields = [
        "name",
        "http_url",
        "cname",
        "page_title",
    ]
    readonly_fields = [
        "discovered_date",
    ]
    fieldsets = (
        (
            "Basic Information",
            {
                "fields": (
                    "name",
                    "scan_history",
                    "target_domain",
                    "is_imported_subdomain",
                    "is_important",
                )
            },
        ),
        (
            "HTTP",
            {
                "fields": (
                    "http_url",
                    "http_header_path",
                    "http_status",
                    "content_type",
                    "content_length",
                    "response_time",
                    "page_title",
                    "webserver",
                )
            },
        ),
        (
            "DNS / CDN",
            {"fields": ("cname", "is_cdn", "cdn_name")},
        ),
        (
            "Dates & Metadata",
            {"fields": ("discovered_date", "verified", "sources", "attack_surface")},
        ),
        (
            "Relations",
            {"fields": ("technologies", "ip_addresses", "directories", "waf"), "classes": ("collapse",)},
        ),
    )
    filter_horizontal = [
        "technologies",
        "ip_addresses",
        "directories",
        "waf",
    ]


@admin.register(ScanActivity)
class ScanActivityAdmin(admin.ModelAdmin):
    """Admin interface for ScanActivity model."""

    list_display = [
        "id",
        "title",
        "name",
        "scan_of",
        "time",
        "status",
    ]
    list_filter = [
        "status",
        "time",
    ]
    search_fields = [
        "title",
        "name",
        "error_message",
    ]
    readonly_fields = [
        "time",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("scan_of", "title", "name", "time", "status", "runner_id")},
        ),
        (
            "Details",
            {
                "fields": ("error_message", "traceback", "results_dir"),
                "classes": ("collapse",),
            },
        ),
    )


@admin.register(EndPoint)
class EndPointAdmin(admin.ModelAdmin):
    """Admin interface for EndPoint model."""

    list_display = [
        "id",
        "http_url",
        "http_status",
        "subdomain",
        "scan_history",
        "is_default",
        "discovered_date",
    ]
    list_filter = [
        "http_status",
        "is_default",
        "is_directory",
        "discovered_date",
    ]
    search_fields = [
        "http_url",
        "page_title",
        "source",
    ]
    readonly_fields = [
        "discovered_date",
        "screenshot_open_link",
        "stored_response_open_link",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("scan_history", "target_domain", "subdomain", "source", "http_url", "is_default")},
        ),
        (
            "HTTP Response",
            {
                "fields": (
                    "http_status",
                    "content_type",
                    "content_length",
                    "page_title",
                    "response_time",
                    "webserver",
                    "method",
                    "words",
                    "lines",
                )
            },
        ),
        (
            "Secator",
            {
                "fields": (
                    "headers",
                    "is_directory",
                    "stored_response_path",
                    "stored_response_open_link",
                    "confidence",
                )
            },
        ),
        (
            "Dates & Metadata",
            {
                "fields": (
                    "discovered_date",
                    "matched_gf_patterns",
                    "screenshot_path",
                    "screenshot_open_link",
                )
            },
        ),
        (
            "Relations",
            {"fields": ("techs", "endpoint_subscan_ids"), "classes": ("collapse",)},
        ),
    )
    filter_horizontal = [
        "techs",
        "endpoint_subscan_ids",
    ]

    @admin.display(description="Screenshot")
    def screenshot_open_link(self, obj):
        if not obj or not obj.screenshot_path:
            return ""
        # URL served with project check via api.scan_file.ServeScanFile
        url = build_scan_file_url(obj.screenshot_path)
        return format_html('<a href="{}" target="_blank" rel="noopener">Open</a>', url) if url else ""

    @admin.display(description="Stored response")
    def stored_response_open_link(self, obj):
        if not obj or not obj.stored_response_path:
            return ""
        # URL served with project check via api.scan_file.ServeScanFile
        url = build_scan_file_url(obj.stored_response_path)
        return format_html('<a href="{}" target="_blank" rel="noopener">Open</a>', url) if url else ""


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    """Admin interface for Vulnerability model."""

    list_display = [
        "name",
        "severity",
        "scan_history",
        "subdomain",
        "http_url",
        "discovered_date",
    ]
    list_filter = [
        "severity",
        "open_status",
        "is_llm_used",
        "discovered_date",
    ]
    search_fields = [
        "name",
        "template",
        "template_id",
        "matcher_name",
        "description",
        "http_url",
    ]
    readonly_fields = [
        "discovered_date",
    ]
    fieldsets = (
        (
            "Basic Information",
            {
                "fields": (
                    "scan_history",
                    "source",
                    "subdomain",
                    "endpoint",
                    "target_domain",
                    "name",
                    "severity",
                )
            },
        ),
        (
            "Template",
            {"fields": ("template", "template_url", "template_id", "matcher_name")},
        ),
        (
            "Details",
            {
                "fields": (
                    "description",
                    "impact",
                    "remediation",
                    "references",
                    "extracted_results",
                    "cvss_metrics",
                    "cvss_score",
                    "cvss_vec",
                    "epss_score",
                )
            },
        ),
        (
            "Request / Response",
            {"fields": ("curl_command", "type", "http_url", "request", "response"), "classes": ("collapse",)},
        ),
        (
            "Metadata",
            {
                "fields": (
                    "discovered_date",
                    "open_status",
                    "hackerone_report_id",
                    "is_llm_used",
                    "confidence_nb",
                    "severity_nb",
                    "ip",
                    "reference",
                )
            },
        ),
        (
            "Relations",
            {"fields": ("tags", "cve_ids", "cwe_ids", "vuln_subscan_ids")},
        ),
    )
    filter_horizontal = [
        "tags",
        "cve_ids",
        "cwe_ids",
        "vuln_subscan_ids",
    ]


@admin.register(CweId)
class CweIdAdmin(SimpleLookupModelAdmin):
    """Admin interface for CweId model; list_display and fieldsets from model _meta."""

    fieldset_title = "Basic Information"


@admin.register(CveId)
class CveIdAdmin(SimpleLookupModelAdmin):
    """Admin interface for CveId model; list_display and fieldsets from model _meta."""

    fieldset_title = "Basic Information"


@admin.register(VulnerabilityTags)
class VulnerabilityTagsAdmin(SimpleLookupModelAdmin):
    """Admin interface for VulnerabilityTags model; list_display and fieldsets from model _meta."""

    fieldset_title = "Basic Information"


@admin.register(Port)
class PortAdmin(admin.ModelAdmin):
    """Admin interface for Port model."""

    list_display = [
        "id",
        "number",
        "ip_address",
        "service_name",
        "is_uncommon",
        "state",
    ]
    list_filter = [
        "is_uncommon",
        "state",
    ]
    search_fields = [
        "service_name",
        "description",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("number", "ip_address", "service_name", "description", "state", "protocol", "host")},
        ),
        (
            "Metadata",
            {"fields": ("is_uncommon", "confidence", "cpes")},
        ),
    )


@admin.register(IpAddress)
class IpAddressAdmin(admin.ModelAdmin):
    """Admin interface for IpAddress model."""

    list_display = [
        "id",
        "address",
        "version",
        "is_cdn",
        "is_private",
        "alive",
    ]
    list_filter = [
        "is_cdn",
        "is_private",
        "alive",
        "version",
    ]
    search_fields = [
        "address",
        "reverse_pointer",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("address", "version", "protocol", "is_cdn", "is_private", "alive")},
        ),
        (
            "DNS",
            {"fields": ("reverse_pointer", "geo_iso")},
        ),
        (
            "Relations",
            {"fields": ("ip_subscan_ids",), "classes": ("collapse",)},
        ),
    )
    filter_horizontal = [
        "ip_subscan_ids",
    ]


@admin.register(DirectoryFile)
class DirectoryFileAdmin(admin.ModelAdmin):
    """Admin interface for DirectoryFile model."""

    list_display = [
        "id",
        "name",
        "url",
        "http_status",
        "length",
        "words",
    ]
    list_filter = [
        "http_status",
    ]
    search_fields = [
        "name",
        "url",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("name", "url", "http_status", "content_type")},
        ),
        (
            "Stats",
            {"fields": ("length", "lines", "words")},
        ),
    )


@admin.register(DirectoryScan)
class DirectoryScanAdmin(admin.ModelAdmin):
    """Admin interface for DirectoryScan model."""

    list_display = [
        "id",
        "command_line",
        "scanned_date",
    ]
    list_filter = [
        "scanned_date",
    ]
    search_fields = [
        "command_line",
    ]
    readonly_fields = [
        "scanned_date",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("command_line", "scanned_date")},
        ),
        (
            "Relations",
            {"fields": ("directory_files", "dir_subscan_ids"), "classes": ("collapse",)},
        ),
    )
    filter_horizontal = [
        "directory_files",
        "dir_subscan_ids",
    ]


@admin.register(Technology)
class TechnologyAdmin(SimpleLookupModelAdmin):
    """Admin interface for Technology model; list_display and fieldsets from model _meta."""

    fieldset_title = "Basic Information"


@admin.register(MetaFinderDocument)
class MetaFinderDocumentAdmin(admin.ModelAdmin):
    """Admin interface for MetaFinderDocument model."""

    list_display = [
        "id",
        "doc_name",
        "url",
        "scan_history",
        "subdomain",
        "http_status",
    ]
    list_filter = [
        "http_status",
    ]
    search_fields = [
        "doc_name",
        "url",
        "title",
        "author",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("scan_history", "target_domain", "subdomain", "doc_name", "url", "title")},
        ),
        (
            "Metadata",
            {"fields": ("author", "producer", "creator", "os", "http_status", "creation_date", "modified_date")},
        ),
    )


@admin.register(Email)
class EmailAdmin(admin.ModelAdmin):
    """Admin interface for Email model."""

    list_display = [
        "id",
        "address",
    ]
    list_filter = []
    search_fields = [
        "address",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("address", "password")},
        ),
    )


@admin.register(Employee)
class EmployeeAdmin(admin.ModelAdmin):
    """Admin interface for Employee model."""

    list_display = [
        "id",
        "name",
        "username",
        "designation",
        "scan_history",
        "target_domain",
    ]
    list_filter = []
    search_fields = [
        "name",
        "username",
        "designation",
        "site_name",
    ]
    readonly_fields = [
        "discovered_date",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("name", "username", "designation", "site_name", "url")},
        ),
        (
            "Associations",
            {"fields": ("scan_history", "target_domain", "subdomain", "endpoint", "discovered_date", "extra_data")},
        ),
        (
            "Emails",
            {"fields": ("emails",)},
        ),
    )
    filter_horizontal = [
        "emails",
    ]


@admin.register(Dork)
class DorkAdmin(admin.ModelAdmin):
    """Admin interface for Dork model."""

    list_display = [
        "id",
        "type",
        "url",
    ]
    list_filter = [
        "type",
    ]
    search_fields = [
        "type",
        "url",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("type", "url")},
        ),
    )


@admin.register(Waf)
class WafAdmin(SimpleLookupModelAdmin):
    """Admin interface for Waf model; list_display and fieldsets from model _meta."""

    fieldset_title = "Basic Information"


@admin.register(CountryISO)
class CountryISOAdmin(SimpleLookupModelAdmin):
    """Admin interface for CountryISO model; list_display and fieldsets from model _meta."""

    fieldset_title = "Basic Information"


@admin.register(Command)
class CommandAdmin(admin.ModelAdmin):
    """Admin interface for Command model."""

    list_display = [
        "id",
        "name",
        "scan_history",
        "time",
        "status",
        "return_code",
    ]
    list_filter = [
        "status",
        "return_code",
    ]
    search_fields = [
        "name",
        "command",
    ]
    readonly_fields = [
        "time",
        "end_time",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("scan_history", "activity", "name", "command", "status", "return_code")},
        ),
        (
            "Execution",
            {"fields": ("time", "end_time", "elapsed", "cwd", "output")},
        ),
        (
            "Secator",
            {
                "fields": (
                    "runner_type",
                    "workflow_name",
                    "node_id",
                    "ancestor_id",
                    "scan_type",
                    "has_parent",
                    "has_children",
                )
            },
        ),
        (
            "Details",
            {"fields": ("errors", "warnings"), "classes": ("collapse",)},
        ),
    )


@admin.register(LLMVulnerabilityReport)
class LLMVulnerabilityReportAdmin(admin.ModelAdmin):
    """Admin interface for LLMVulnerabilityReport model."""

    list_display = [
        "id",
        "title",
        "url_path",
    ]
    list_filter = []
    search_fields = [
        "title",
        "url_path",
        "description",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("url_path", "title")},
        ),
        (
            "Content",
            {"fields": ("description", "impact", "remediation", "references")},
        ),
    )


@admin.register(S3Bucket)
class S3BucketAdmin(admin.ModelAdmin):
    """Admin interface for S3Bucket model."""

    list_display = [
        "id",
        "name",
        "region",
        "provider",
        "owner_display_name",
    ]
    list_filter = [
        "provider",
    ]
    search_fields = [
        "name",
        "region",
        "owner_id",
        "owner_display_name",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("name", "region", "provider", "owner_id", "owner_display_name")},
        ),
        (
            "Permissions",
            {
                "fields": (
                    "perm_auth_users_read",
                    "perm_auth_users_write",
                    "perm_auth_users_read_acl",
                    "perm_auth_users_write_acl",
                    "perm_auth_users_full_control",
                    "perm_all_users_read",
                    "perm_all_users_write",
                    "perm_all_users_read_acl",
                    "perm_all_users_write_acl",
                    "perm_all_users_full_control",
                )
            },
        ),
        (
            "Stats",
            {"fields": ("num_objects", "size")},
        ),
    )


@admin.register(SecatorRunner)
class SecatorRunnerAdmin(TimestampedModelAdminMixin, admin.ModelAdmin):
    """Admin interface for SecatorRunner model."""

    list_display = [
        "id",
        "runner_type",
        "runner_name",
        "scan_history",
        "domain",
        "status",
        "created_at",
        "updated_at",
    ]
    list_filter = [
        "runner_type",
        "status",
        "created_at",
    ]
    search_fields = [
        "runner_name",
        "celery_id",
    ]
    fieldsets = build_fieldsets_with_timestamps(
        (
            "Basic Information",
            {"fields": ("runner_type", "runner_name", "scan_history", "domain", "status", "celery_id")},
        ),
        (
            "Data",
            {"fields": ("runner_data",), "classes": ("wide", "collapse")},
        ),
        model=SecatorRunner,
    )
