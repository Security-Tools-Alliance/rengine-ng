from django.contrib import admin

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
        "celery_ids",
        "tasks",
    ]
    fieldsets = (
        ("Scan Information", {
            "fields": ("domain", "scan_type", "is_legacy_scan", "scan_status")
        }),
        ("Execution Details", {
            "fields": ("start_scan_date", "stop_scan_date", "results_dir", "celery_ids", "tasks", "error_message"),
            "classes": ("collapse",),
        }),
        ("User Information", {
            "fields": ("initiated_by", "aborted_by"),
        }),
        ("Results", {
            "fields": ("emails", "employees", "buckets", "dorks", "used_gf_patterns"),
            "classes": ("collapse",),
        }),
    )
    filter_horizontal = [
        "emails",
        "employees", 
        "buckets",
        "dorks",
    ]
admin.site.register(SubScan)
admin.site.register(Subdomain)
admin.site.register(ScanActivity)
admin.site.register(EndPoint)
admin.site.register(Vulnerability)
admin.site.register(CweId)
admin.site.register(CveId)
admin.site.register(VulnerabilityTags)
admin.site.register(Port)
admin.site.register(IpAddress)
admin.site.register(DirectoryFile)
admin.site.register(DirectoryScan)
admin.site.register(Technology)
admin.site.register(MetaFinderDocument)
admin.site.register(Email)
admin.site.register(Employee)
admin.site.register(Dork)
admin.site.register(Waf)
admin.site.register(CountryISO)
admin.site.register(Command)
admin.site.register(LLMVulnerabilityReport)
admin.site.register(S3Bucket)
