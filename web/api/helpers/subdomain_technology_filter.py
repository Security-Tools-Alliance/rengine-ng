"""
Subdomain list/search: technology filters including Secator endpoint-linked techs.

M2M ``Subdomain.technologies`` remains used for legacy scans and as a fallback when
no endpoints exist for a subdomain; non-legacy scans also match ``EndPoint.techs``.

**Integration:** ``SubdomainTechnologySearchMixin`` (advanced search) and explicit ``tech=`` filters
on ``ListSubdomains`` / ``SubdomainDatatableViewSet`` should use these Q objects so list, count,
and advanced-search value APIs share one definition of “technology on subdomain”.
"""

from __future__ import annotations

from django.db.models import Count, OuterRef, Q, Subquery

from startScan.models import Subdomain


def subdomain_scan_non_legacy_q() -> Q:
    """Subdomain rows whose owning scan is non-legacy (endpoint ``techs`` are in scope)."""
    return Q(scan_history__is_legacy_scan=False)


def technology_linked_via_non_legacy_endpoints_q(subdomain_id_subquery: Subquery) -> Q:
    """
    ``Technology`` rows linked through ``EndPoint.techs`` for subdomains in the subquery,
    excluding legacy scans (same rule as ``subdomain_scan_non_legacy_q`` on the endpoint FK).
    """
    return Q(
        techs__subdomain_id__in=subdomain_id_subquery,
        techs__scan_history__is_legacy_scan=False,
    )


def subdomain_technology_icontains_q(search_value: str) -> Q:
    """Match technology name (icontains) via subdomain M2M or Secator endpoint techs."""
    endpoint_branch = subdomain_scan_non_legacy_q() & Q(endpoint__techs__name__icontains=search_value)
    return Q(technologies__name__icontains=search_value) | endpoint_branch


def subdomain_technology_exact_q(value: str) -> Q:
    """Exact technology name match via subdomain M2M or Secator endpoint techs."""
    endpoint_branch = subdomain_scan_non_legacy_q() & Q(endpoint__techs__name=value)
    return Q(technologies__name=value) | endpoint_branch


def subdomain_technology_special_q(operator: str, lookup_content: str) -> Q:
    """
    Advanced-search ``technology`` atom, aligned with ``technologies__name__icontains`` semantics.
    Supports ``=`` and ``!`` like AdvancedSearchMixin special_fields.
    """
    if operator == "=":
        return subdomain_technology_icontains_q(lookup_content)
    if operator == "!":
        return ~subdomain_technology_icontains_q(lookup_content)
    return subdomain_technology_icontains_q(lookup_content)


def technology_scope_q_for_subdomains(subdomain_filter) -> Q:
    """
    Technology queryset scope for a subdomain queryset.

    Includes legacy/fallback Subdomain<->Technology M2M and non-legacy endpoint tech links.
    """
    subdomain_id_subquery = Subquery(subdomain_filter.values("id"))
    return Q(technologies__in=subdomain_filter) | technology_linked_via_non_legacy_endpoints_q(subdomain_id_subquery)


def _subdomain_carries_outer_technology_q(outer_technology_pk: OuterRef) -> Q:
    """
    ``Subdomain`` filter: the correlated technology primary key appears via M2M or non-legacy
    endpoint ``techs``. The ``OuterRef`` must point at ``Technology.pk`` in the query that
    ultimately wraps the ``Subquery`` (see ``list_technology_subdomain_count_values_subquery``).
    """
    return Q(technologies__id=outer_technology_pk) | (
        subdomain_scan_non_legacy_q() & Q(endpoint__techs__id=outer_technology_pk)
    )


def technology_presence_in_subdomain_scope_q() -> Q:
    """
    Correlated ``Subdomain`` filter for per-technology counts.

    ``OuterRef("pk")`` is the **technology** id from the **outer** queryset. Safe only when this
    ``Q`` is used inside a ``Subquery`` annotated on ``Technology.objects`` (not on a bare
    ``Subdomain`` queryset, where ``pk`` would mean subdomain id).
    """
    return _subdomain_carries_outer_technology_q(OuterRef("pk"))


def list_technology_subdomain_count_values_subquery(subdomain_id_subquery: Subquery):
    """
    Values queryset (column ``c``) for ``COUNT(DISTINCT subdomain.id)`` over subdomains in
    ``subdomain_id_subquery`` that carry the outer technology row.

    Use **only** as::

        Technology.objects.annotate(
            count=Coalesce(
                Subquery(
                    list_technology_subdomain_count_values_subquery(
                        subdomain_id_subquery
                    )[:1]
                ),
                Value(0),
                output_field=IntegerField(),
            ),
        )

    so ``OuterRef("pk")`` correlates to ``Technology.pk``. The inner queryset is built from
    ``Subdomain``, but correlation is defined by Django relative to the annotated outer model.
    """
    outer_technology_pk = OuterRef("pk")
    return (
        Subdomain.objects.filter(id__in=subdomain_id_subquery)
        .filter(_subdomain_carries_outer_technology_q(outer_technology_pk))
        .annotate(c=Count("id", distinct=True))
        .values("c")
    )
