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
    Certificate,
    Command,
    CountryISO,
    CveId,
    CweId,
    DirectoryFile,
    DirectoryScan,
    DNSRecord,
    Domain,
    DomainInfo,
    DomainInfoDnsRecordsThrough,
    DomainInfoHistoricalIpsThrough,
    DomainInfoNameServersThrough,
    DomainInfoRelatedDomainsThrough,
    DomainInfoRelatedTldsThrough,
    DomainInfoSimilarDomainsThrough,
    DomainInfoStatusThrough,
    DomainRegistration,
    Dork,
    Email,
    Employee,
    EndPoint,
    Exploit,
    HistoricalIP,
    IpAddress,
    LLMVulnerabilityReport,
    MetaFinderDocument,
    NameServer,
    Port,
    Registrar,
    RelatedDomain,
    S3Bucket,
    ScanActivity,
    ScanHistory,
    ScanSchedule,
    SecatorRunner,
    Secret,
    Subdomain,
    SubScan,
    Technology,
    Vulnerability,
    VulnerabilityTags,
    Waf,
    WhoisStatus,
)


@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    """Admin interface for Domain model (startScan.models)."""

    list_display = [
        "name",
        "scan_history",
        "insert_date",
        "start_scan_date",
    ]
    list_display_links = ["name"]
    list_filter = [
        "insert_date",
        "start_scan_date",
    ]
    list_per_page = 50
    ordering = ["-insert_date"]
    date_hierarchy = "insert_date"
    raw_id_fields = ["scan_history"]
    search_fields = [
        "name",
        "description",
        "h1_team_handle",
        "ip_address_cidr",
    ]
    readonly_fields = [
        "insert_date",
        "start_scan_date",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("name", "scan_history", "description", "domain_info")},
        ),
        (
            "Scan / Network",
            {"fields": ("h1_team_handle", "ip_address_cidr", "insert_date", "start_scan_date", "custom_dns_servers")},
        ),
        (
            "Advanced",
            {"fields": ("request_headers",), "classes": ("collapse",)},
        ),
    )


@admin.register(DomainInfo)
class DomainInfoAdmin(admin.ModelAdmin):
    """Admin interface for DomainInfo model (startScan.models)."""

    list_display = [
        "id",
        "dnssec",
        "registrar",
        "whois_server",
    ]
    list_filter = [
        "dnssec",
    ]
    search_fields = [
        "whois_server",
        "geolocation_iso",
    ]
    readonly_fields = [
        "created",
        "updated",
        "expires",
    ]
    fieldsets = (
        (
            "Dates",
            {"fields": ("created", "updated", "expires")},
        ),
        (
            "DNS / WHOIS",
            {"fields": ("dnssec", "registrar", "whois_server", "geolocation_iso")},
        ),
        (
            "Contacts",
            {"fields": ("registrant", "admin", "tech")},
        ),
        (
            "Extra",
            {"fields": ("extra_data",), "classes": ("collapse",)},
        ),
    )


@admin.register(RelatedDomain)
class RelatedDomainAdmin(admin.ModelAdmin):
    list_display = ["id", "name"]
    list_display_links = ["name"]
    search_fields = ["name"]
    ordering = ["name"]


@admin.register(Registrar)
class RegistrarAdmin(admin.ModelAdmin):
    list_display = ["id", "name", "country"]
    list_filter = ["country"]
    search_fields = ["name", "email", "url"]
    fieldsets = (
        ("Basic Information", {"fields": ("name", "phone", "email", "url")}),
        ("Address", {"fields": ("address", "country", "fax")}),
    )


@admin.register(DomainRegistration)
class DomainRegistrationAdmin(admin.ModelAdmin):
    list_display = ["id", "name", "organization", "country"]
    list_filter = ["country"]
    search_fields = ["name", "organization", "email"]
    fieldsets = (
        ("Basic Information", {"fields": ("name", "organization", "contact", "type", "id_str")}),
        ("Address", {"fields": ("address", "city", "state", "zip_code", "country")}),
        ("Contact", {"fields": ("email", "phone", "fax")}),
    )


@admin.register(ScanHistory)
class ScanHistoryAdmin(admin.ModelAdmin):
    """Admin interface for ScanHistory model with legacy scan support."""

    list_display = [
        "target",
        "scan_type",
        "is_legacy_scan",
        "scan_status",
        "start_scan_date",
        "stop_scan_date",
        "initiated_by",
    ]
    list_display_links = ["target"]
    list_filter = [
        "is_legacy_scan",
        "scan_status",
        "scan_type__scan_type",
        "start_scan_date",
        "initiated_by",
    ]
    list_per_page = 50
    list_select_related = ["target", "scan_type", "initiated_by"]
    ordering = ["-start_scan_date"]
    date_hierarchy = "start_scan_date"
    raw_id_fields = ["target"]
    search_fields = [
        "target__value",
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
        ("Scan Information", {"fields": ("target", "scan_type", "is_legacy_scan", "scan_status")}),
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
    list_per_page = 50
    list_select_related = ["scan_history", "subdomain"]
    ordering = ["-start_scan_date"]
    date_hierarchy = "start_scan_date"
    raw_id_fields = ["scan_history", "subdomain"]
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
        "domain",
        "scan_history",
        "is_important",
        "http_status",
        "discovered_date",
    ]
    list_display_links = ["name"]
    list_filter = [
        "is_important",
        "is_imported_subdomain",
        "is_cdn",
        "verified",
        "discovered_date",
    ]
    list_per_page = 50
    list_select_related = ["domain", "scan_history"]
    ordering = ["-discovered_date"]
    date_hierarchy = "discovered_date"
    raw_id_fields = ["domain", "scan_history"]
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
                    "domain",
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
    list_select_related = ["scan_of"]
    ordering = ["-time"]
    date_hierarchy = "time"
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
    list_display_links = ["http_url"]
    list_filter = [
        "http_status",
        "is_default",
        "is_directory",
        "discovered_date",
    ]
    list_per_page = 50
    list_select_related = ["subdomain", "scan_history", "domain"]
    ordering = ["-id"]
    date_hierarchy = "discovered_date"
    raw_id_fields = ["scan_history", "domain", "subdomain"]
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
            {"fields": ("scan_history", "domain", "subdomain", "source", "http_url", "is_default")},
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
    list_display_links = ["name"]
    list_filter = [
        "severity",
        "open_status",
        "is_llm_used",
        "discovered_date",
    ]
    list_per_page = 50
    list_select_related = ["scan_history", "subdomain", "endpoint", "domain"]
    ordering = ["-discovered_date"]
    date_hierarchy = "discovered_date"
    raw_id_fields = ["scan_history", "subdomain", "endpoint", "domain"]
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
                    "domain",
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
    list_per_page = 50
    raw_id_fields = ["ip_address"]
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
    list_display_links = ["address"]
    list_filter = [
        "is_cdn",
        "is_private",
        "alive",
        "version",
    ]
    list_per_page = 50
    ordering = ["address"]
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
            {"fields": ("scan_history", "domain", "subdomain", "doc_name", "url", "title")},
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
    list_display_links = ["address"]
    list_filter = []
    ordering = ["address"]
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
        "domain",
    ]
    list_display_links = ["name"]
    list_filter = ["scan_history", "domain"]
    list_select_related = ["scan_history", "domain"]
    ordering = ["-id"]
    raw_id_fields = ["scan_history", "domain", "subdomain", "endpoint"]
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
            {"fields": ("scan_history", "domain", "subdomain", "endpoint", "discovered_date", "extra_data")},
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
    list_select_related = ["scan_history", "activity"]
    ordering = ["-time"]
    date_hierarchy = "time"
    raw_id_fields = ["scan_history", "activity"]
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
    list_display_links = ["title"]
    list_filter = []
    ordering = ["-id"]
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
    list_display_links = ["runner_name"]
    list_filter = [
        "runner_type",
        "status",
        "created_at",
    ]
    list_select_related = ["scan_history", "domain"]
    ordering = ["-created_at"]
    date_hierarchy = "created_at"
    raw_id_fields = ["scan_history", "domain"]
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


@admin.register(HistoricalIP)
class HistoricalIPAdmin(admin.ModelAdmin):
    """Admin interface for HistoricalIP model (managed=False)."""

    list_display = ["id", "ip", "location", "owner", "last_seen"]
    search_fields = ["ip", "location", "owner"]


@admin.register(WhoisStatus)
class WhoisStatusAdmin(admin.ModelAdmin):
    """Admin interface for WhoisStatus model (managed=False)."""

    list_display = ["id", "name"]
    search_fields = ["name"]


@admin.register(NameServer)
class NameServerAdmin(admin.ModelAdmin):
    """Admin interface for NameServer model (managed=False)."""

    list_display = ["id", "name"]
    search_fields = ["name"]


@admin.register(DNSRecord)
class DNSRecordAdmin(admin.ModelAdmin):
    """Admin interface for DNSRecord model (managed=False)."""

    list_display = ["id", "name", "type"]
    list_filter = ["type"]
    search_fields = ["name"]


@admin.register(DomainInfoStatusThrough)
class DomainInfoStatusThroughAdmin(admin.ModelAdmin):
    """Admin interface for DomainInfoStatusThrough (managed=False)."""

    list_display = ["id", "domaininfo", "whoisstatus"]


@admin.register(DomainInfoNameServersThrough)
class DomainInfoNameServersThroughAdmin(admin.ModelAdmin):
    """Admin interface for DomainInfoNameServersThrough (managed=False)."""

    list_display = ["id", "domaininfo", "nameserver"]


@admin.register(DomainInfoDnsRecordsThrough)
class DomainInfoDnsRecordsThroughAdmin(admin.ModelAdmin):
    """Admin interface for DomainInfoDnsRecordsThrough (managed=False)."""

    list_display = ["id", "domaininfo", "dnsrecord"]


@admin.register(DomainInfoRelatedDomainsThrough)
class DomainInfoRelatedDomainsThroughAdmin(admin.ModelAdmin):
    """Admin interface for DomainInfoRelatedDomainsThrough (managed=False)."""

    list_display = ["id", "domaininfo", "relateddomain"]


@admin.register(DomainInfoRelatedTldsThrough)
class DomainInfoRelatedTldsThroughAdmin(admin.ModelAdmin):
    """Admin interface for DomainInfoRelatedTldsThrough (managed=False)."""

    list_display = ["id", "domaininfo", "relateddomain"]


@admin.register(DomainInfoSimilarDomainsThrough)
class DomainInfoSimilarDomainsThroughAdmin(admin.ModelAdmin):
    """Admin interface for DomainInfoSimilarDomainsThrough (managed=False)."""

    list_display = ["id", "domaininfo", "relateddomain"]


@admin.register(DomainInfoHistoricalIpsThrough)
class DomainInfoHistoricalIpsThroughAdmin(admin.ModelAdmin):
    """Admin interface for DomainInfoHistoricalIpsThrough (managed=False)."""

    list_display = ["id", "domaininfo", "historicalip"]


@admin.register(Secret)
class SecretAdmin(admin.ModelAdmin):
    """Admin interface for Secret model."""

    list_display = ["id", "rule_name", "scan_history", "matched_at", "source", "discovered_date"]
    list_display_links = ["rule_name"]
    list_filter = ["source", "discovered_date"]
    ordering = ["-discovered_date"]
    date_hierarchy = "discovered_date"
    raw_id_fields = ["scan_history"]
    search_fields = ["rule_name", "matched_at", "source"]
    readonly_fields = ["discovered_date"]


@admin.register(Exploit)
class ExploitAdmin(admin.ModelAdmin):
    """Admin interface for Exploit model."""

    list_display = ["id", "name", "exploit_id", "scan_history", "ip_address", "discovered_date"]
    list_display_links = ["name"]
    list_filter = ["provider", "discovered_date"]
    ordering = ["-discovered_date"]
    date_hierarchy = "discovered_date"
    raw_id_fields = ["scan_history", "ip_address"]
    search_fields = ["name", "exploit_id", "matched_at", "reference"]
    filter_horizontal = ["cve_ids", "tags"]


@admin.register(Certificate)
class CertificateAdmin(admin.ModelAdmin):
    """Admin interface for Certificate model."""

    list_display = ["id", "host", "subject_cn", "scan_history", "not_after", "discovered_date"]
    list_display_links = ["subject_cn"]
    list_filter = ["self_signed", "trusted", "discovered_date"]
    list_per_page = 50
    ordering = ["-discovered_date"]
    date_hierarchy = "discovered_date"
    raw_id_fields = ["scan_history"]
    search_fields = ["host", "fingerprint_sha256", "subject_cn", "issuer_cn"]
    readonly_fields = ["discovered_date"]


@admin.register(ScanSchedule)
class ScanScheduleAdmin(admin.ModelAdmin):
    """Admin interface for ScanSchedule model."""

    list_display = ["id", "name", "target", "schedule_mode", "next_run", "enabled", "initiated_by", "created_at"]
    list_display_links = ["name"]
    list_filter = ["schedule_mode", "enabled", "created_at"]
    list_select_related = ["target", "initiated_by"]
    ordering = ["-created_at"]
    date_hierarchy = "created_at"
    raw_id_fields = ["target"]
    search_fields = ["name"]
    readonly_fields = ["created_at"]
