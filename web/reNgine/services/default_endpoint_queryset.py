"""
Queryset helpers for default ``EndPoint`` rows used in API serialization.

``apply_endpoint_techs_prefetch`` — use when serializers only need ``techs`` (e.g. endpoint
DataTable rows) to avoid an extra join on ``port``.

``apply_endpoint_port_and_techs_related`` — use when code reads ``endpoint.port`` and ``techs``
(e.g. ``DefaultEndpointTechnologyMixin._serialize_endpoint_defaults_by_port`` and subdomain
``default_endpoint_list`` prefetch).
"""

from django.db.models import F, Prefetch, QuerySet

from startScan.models import EndPoint, Technology


def apply_endpoint_techs_prefetch(queryset: QuerySet) -> QuerySet:
    """
    Prefetch ``techs`` for endpoint list serialization without selecting ``port``.

    Keep the base queryset shape unchanged so upstream ``only()`` / ``defer()`` remains intact.
    Field narrowing is applied only on the related ``Technology`` queryset.
    """
    tech_qs = Technology.objects.only("id", "name", "value", "category", "stored_response_path")
    return queryset.prefetch_related(Prefetch("techs", queryset=tech_qs))


def apply_endpoint_port_and_techs_related(queryset: QuerySet) -> QuerySet:
    """
    Select ``port`` and prefetch ``techs`` when both are read during serialization.

    Keep base queryset fields untouched so upstream ``only()`` / ``defer()`` remains effective.
    """
    tech_qs = Technology.objects.only("id", "name", "value", "category", "stored_response_path")
    return queryset.select_related("port").prefetch_related(Prefetch("techs", queryset=tech_qs))


def subdomain_all_endpoints_for_tech_queryset() -> QuerySet:
    """
    EndPoint queryset for subdomain-level technology aggregation.

    Keep rows scoped to the owning subdomain scan (same semantics used by serializers)
    and order by id for deterministic output.
    """
    return EndPoint.objects.filter(scan_history_id=F("subdomain__scan_history_id")).order_by("id")
