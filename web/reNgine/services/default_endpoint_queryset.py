"""
Queryset helpers for default ``EndPoint`` rows used in API serialization.

``apply_endpoint_techs_prefetch`` — use when serializers only need ``techs`` (e.g. endpoint
DataTable rows) to avoid an extra join on ``port``.

``apply_endpoint_port_and_techs_related`` — use when code reads ``endpoint.port`` and ``techs``
(e.g. ``DefaultEndpointTechnologyMixin._serialize_endpoint_defaults_by_port`` and subdomain
``default_endpoint_list`` prefetch).
"""

from django.db.models import QuerySet


def apply_endpoint_techs_prefetch(queryset: QuerySet) -> QuerySet:
    """Prefetch ``techs`` for endpoint list serialization without selecting ``port``."""
    return queryset.prefetch_related("techs")


def apply_endpoint_port_and_techs_related(queryset: QuerySet) -> QuerySet:
    """Select ``port`` and prefetch ``techs`` when both are read during serialization."""
    return queryset.select_related("port").prefetch_related("techs")
