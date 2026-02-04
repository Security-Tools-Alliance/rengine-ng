from django.contrib import admin

from .models import (
    Domain,
    DomainInfo,
    DomainRegistration,
    Organization,
    Registrar,
    RelatedDomain,
)


@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    """Admin interface for Domain model."""

    list_display = [
        "name",
        "project",
        "insert_date",
        "start_scan_date",
    ]
    list_filter = [
        "insert_date",
        "start_scan_date",
    ]
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
            {"fields": ("name", "project", "description", "domain_info")},
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


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    """Admin interface for Organization model."""

    list_display = [
        "name",
        "project",
        "insert_date",
    ]
    list_filter = [
        "insert_date",
    ]
    search_fields = [
        "name",
        "description",
    ]
    readonly_fields = [
        "insert_date",
    ]
    filter_horizontal = [
        "domains",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("name", "description", "project", "insert_date")},
        ),
        (
            "Domains",
            {"fields": ("domains",)},
        ),
    )


@admin.register(RelatedDomain)
class RelatedDomainAdmin(admin.ModelAdmin):
    """Admin interface for RelatedDomain model."""

    list_display = [
        "id",
        "name",
    ]
    list_filter = []
    search_fields = [
        "name",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("name",)},
        ),
    )


@admin.register(Registrar)
class RegistrarAdmin(admin.ModelAdmin):
    """Admin interface for Registrar model."""

    list_display = [
        "id",
        "name",
        "country",
    ]
    list_filter = [
        "country",
    ]
    search_fields = [
        "name",
        "email",
        "url",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("name", "phone", "email", "url")},
        ),
        (
            "Address",
            {"fields": ("address", "country", "fax")},
        ),
    )


@admin.register(DomainRegistration)
class DomainRegistrationAdmin(admin.ModelAdmin):
    """Admin interface for DomainRegistration model."""

    list_display = [
        "id",
        "name",
        "organization",
        "country",
    ]
    list_filter = [
        "country",
    ]
    search_fields = [
        "name",
        "organization",
        "email",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("name", "organization", "contact", "type", "id_str")},
        ),
        (
            "Address",
            {"fields": ("address", "city", "state", "zip_code", "country")},
        ),
        (
            "Contact",
            {"fields": ("email", "phone", "fax")},
        ),
    )


@admin.register(DomainInfo)
class DomainInfoAdmin(admin.ModelAdmin):
    """Admin interface for DomainInfo model."""

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
            "Status & Nameservers",
            {"fields": ("status", "name_servers", "dns_records")},
        ),
        (
            "Related",
            {"fields": ("related_domains", "related_tlds", "similar_domains", "historical_ips")},
        ),
        (
            "Extra",
            {"fields": ("extra_data",), "classes": ("collapse",)},
        ),
    )
    filter_horizontal = [
        "status",
        "name_servers",
        "dns_records",
        "related_domains",
        "related_tlds",
        "similar_domains",
        "historical_ips",
    ]
