"""
Database query optimizations (Django ORM).

Centralizes helpers that avoid heavy JOINs and cartesian products. Using a scalar
subquery per row (count_subquery / count_subquery_related) gives correct counts
without the duplicate rows that annotate(Count(..., distinct=True)) can produce
when joining across multiple relations; prefer these helpers over Count(distinct=...)
for related-object counts.
"""

from typing import Any, Optional, Type

from django.db.models import Count, IntegerField, Model, OuterRef, Subquery, Value
from django.db.models.functions import Coalesce


def count_subquery(
    model: Type[Model],
    fk_field: str,
    outer_ref_name: str = "pk",
    filter_kwargs: Optional[dict[str, Any]] = None,
    distinct: bool = False,
):
    """
    Build a Coalesce(Subquery(count), 0) expression for use in annotate().

    Avoids cartesian products when counting related rows: instead of joining and
    using Count(..., distinct=True), uses a scalar subquery per row.

    Conventions:
    - outer_ref_name: column on the queryset you are annotating (the "outer" one).
      Use "pk" or "id" when the outer queryset is a model with default primary key.
    - fk_field: the FK field on the *counted* model that points to the outer row.
      Must match the outer table (e.g. if outer is ScanHistory, use "scan_history_id";
      if outer is Subdomain, use "subdomain_id").

    Example (count subdomains per scan):
        ScanHistory.objects.annotate(
            subdomain_count=count_subquery(Subdomain, "scan_history_id")
        )
    Here outer_ref_name defaults to "pk" (ScanHistory.pk), and Subdomain.scan_history_id
    is the FK that links to it.

    Args:
        model: Django model class to count (e.g. Subdomain, EndPoint, Vulnerability).
        fk_field: Name of the FK field on that model pointing to the outer queryset
            (e.g. "scan_history_id", "subdomain_id").
        outer_ref_name: Column name on the outer queryset to match (default "pk").
        filter_kwargs: Optional extra filters applied to the counted queryset
            (e.g. {"severity": 4}, {"is_done": False}).
        distinct: If True, use Count("id", distinct=True) in the subquery to avoid
            counting duplicates when the subquery would otherwise be affected by
            joins or grouping that can produce duplicate rows.

    Returns:
        Expression suitable for .annotate(my_count=count_subquery(...)).
    """
    kwargs: dict[str, Any] = {fk_field: OuterRef(outer_ref_name)}
    kwargs |= filter_kwargs or {}
    count_expr = Count("id", distinct=distinct)
    qs = model.objects.filter(**kwargs).values(fk_field).annotate(c=count_expr).values("c")
    return Coalesce(Subquery(qs[:1]), Value(0), output_field=IntegerField())


def count_subquery_related(
    model: Type[Model],
    related_lookup: str,
    outer_ref_name: str = "pk",
    filter_kwargs: Optional[dict[str, Any]] = None,
    distinct: bool = False,
):
    """
    Build a Coalesce(Subquery(count), 0) when the link to the outer row is via a relation.

    Use when the outer queryset is not the direct FK of the counted model: the counted
    model links to the outer table through another table (e.g. Vulnerability has
    subdomain_id; Subdomain has domain_id; outer is Domain, so use
    related_lookup="subdomain__domain_id" and outer_ref_name="pk").

    Conventions:
    - outer_ref_name: column on the queryset you are annotating (e.g. "pk" for Domain).
    - related_lookup: Django lookup path on the *counted* model to the outer ref.
      Must end with the FK to the outer model (e.g. "subdomain__domain_id" for
      counting Vulnerability per Domain).

    Example (count vulnerabilities per domain):
        Domain.objects.annotate(
            vuln_count=count_subquery_related(Vulnerability, "subdomain__domain_id")
        )

    Args:
        model: Django model class to count (e.g. Vulnerability).
        related_lookup: Lookup path from model to the outer ref (e.g. "subdomain__domain_id").
        outer_ref_name: Column name on the outer queryset to match (default "pk").
        filter_kwargs: Optional extra filters (e.g. {"severity__gt": 0}).
        distinct: If True, use Count("id", distinct=True) in the subquery.

    Returns:
        Expression suitable for .annotate(my_count=count_subquery_related(...)).
    """
    kwargs: dict[str, Any] = {related_lookup: OuterRef(outer_ref_name)}
    kwargs |= filter_kwargs or {}
    count_expr = Count("id", distinct=distinct)
    qs = model.objects.filter(**kwargs).values(related_lookup).annotate(c=count_expr).values("c")
    return Coalesce(Subquery(qs[:1]), Value(0), output_field=IntegerField())
