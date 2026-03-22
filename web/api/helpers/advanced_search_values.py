"""
Distinct field values for advanced-search Build filter (aligned with DataTable querysets).
"""

from __future__ import annotations

from typing import Any, Optional

from django.db.models import CharField, F, IntegerField, OuterRef, QuerySet, Subquery, TextField
from django.db.models.functions import Cast, Coalesce

from api.helpers.advanced_search import (
    ADVANCED_SEARCH_FIELD_CATALOG,
    ADVANCED_SEARCH_FIELD_VALUE_SPECS,
    ALLOWED_CONTEXTS,
)
from api.helpers.query import (
    build_endpoint_datatable_queryset,
    build_ip_datatable_base_queryset,
    build_vulnerability_datatable_base_queryset,
    subdomain_datatable_from_request,
)
from reNgine.definitions import NUCLEI_REVERSE_SEVERITY_MAP
from startScan.models import EndPoint


SUBDOMAIN_DISPLAY_VALUE_FIELDS = frozenset({"page_title", "http_status", "content_length"})


def _catalog_field_names(context: str) -> set[str]:
    return {f["name"] for f in ADVANCED_SEARCH_FIELD_CATALOG.get(context, [])}


def _normalize_out(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float):
        if v == int(v):
            return str(int(v))
        return str(v)
    s = str(v).strip()
    return s if s else None


def _sort_values(values: list[str], kind: str, *, numeric_sort: bool = False) -> list[str]:
    if numeric_sort and values:
        try:
            return sorted(values, key=lambda x: int(x))
        except ValueError:
            pass
    return sorted(values, key=lambda x: (x.lower(), x))


def _base_queryset_for_context(request: Any, ctx: str) -> tuple[Optional[QuerySet], Optional[str]]:
    if ctx == "endpoints":
        return build_endpoint_datatable_queryset(request), None
    if ctx == "subdomains":
        qs, _ = subdomain_datatable_from_request(request)
        return qs, None
    if ctx == "vulnerabilities":
        return build_vulnerability_datatable_base_queryset(request), None
    if ctx == "ips":
        return build_ip_datatable_base_queryset(request), None
    return None, "unknown_context"


def _distinct_severity_labels(qs: QuerySet, lim: int) -> list[str]:
    codes = {c for c in qs.values_list("severity", flat=True).distinct() if c is not None}
    raw = []
    for c in sorted(codes, key=lambda x: int(x)):
        lab = NUCLEI_REVERSE_SEVERITY_MAP.get(int(c))
        if lab:
            raw.append(lab)
    return raw[:lim]


def _distinct_open_closed(qs: QuerySet, lim: int) -> list[str]:
    bools = set(qs.values_list("open_status", flat=True).distinct())
    raw = []
    if True in bools:
        raw.append("open")
    if False in bools:
        raw.append("closed")
    raw = sorted(raw)
    return raw[:lim]


def _dedupe_normalized_list(raw: list[Any], lim: int) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        s = _normalize_out(item)
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= lim:
            break
    return out


def _subdomain_distinct_display_values(qs: QuerySet, field: str, q_prefix: str, lim: int) -> list[str]:
    """
    Distinct values aligned with SubdomainSerializer display_* (default EndPoint, else Subdomain).
    """
    ep = EndPoint.objects.filter(subdomain_id=OuterRef("pk"), is_default=True)
    alias = "_adv_disp"
    if field == "page_title":
        coalesced = Coalesce(
            Subquery(ep.values("page_title")[:1]),
            F("page_title"),
            output_field=CharField(max_length=30000),
        )
    elif field == "http_status":
        coalesced = Coalesce(
            Subquery(ep.values("http_status")[:1]),
            F("http_status"),
            output_field=IntegerField(),
        )
    elif field == "content_length":
        coalesced = Coalesce(
            Subquery(ep.values("content_length")[:1]),
            F("content_length"),
            output_field=IntegerField(),
        )
    else:
        raise ValueError(field)
    fqs = qs.annotate(**{alias: coalesced})
    if q_prefix:
        if field == "page_title":
            fqs = fqs.filter(**{f"{alias}__icontains": q_prefix})
        else:
            fqs = fqs.annotate(_adv_disp_txt=Cast(F(alias), output_field=TextField())).filter(
                _adv_disp_txt__istartswith=q_prefix
            )
    raw = list(fqs.values_list(alias, flat=True).distinct())
    return _finalize_scalar_like_values(raw, lim, field)


def _scalar_m2m_raw_values(qs: QuerySet, db_path: str, q_prefix: str) -> list[Any]:
    fqs = qs
    if q_prefix:
        fqs = fqs.filter(**{f"{db_path}__istartswith": q_prefix})
    return list(fqs.values_list(db_path, flat=True).distinct())


def _finalize_scalar_like_values(
    raw: list[Any],
    lim: int,
    fld: str,
) -> list[str]:
    out = _dedupe_normalized_list(raw, lim)
    numeric_sort = fld in ("http_status", "content_length", "cvss_score", "port")
    out = _sort_values(out, "text", numeric_sort=numeric_sort)
    if len(out) > lim:
        out = out[:lim]
    return out


def distinct_values_for_context_field(
    request: Any,
    context: str,
    field: str,
    q_prefix: str = "",
    limit: int = 200,
) -> tuple[Optional[list[str]], Optional[str]]:
    """
    Returns (values, error_code). error_code set on validation failure.
    """
    ctx = (context or "").strip().lower()
    fld = (field or "").strip().lower()
    if ctx not in ALLOWED_CONTEXTS:
        return None, "unknown_context"
    if fld not in _catalog_field_names(ctx):
        return None, "unknown_field"
    spec = ADVANCED_SEARCH_FIELD_VALUE_SPECS.get(ctx, {}).get(fld)
    if not spec:
        return None, "unknown_field"

    kind, db_path = spec
    max_lim = 500
    lim = max(1, min(max_lim, int(limit) if limit else 200))

    qs, err = _base_queryset_for_context(request, ctx)
    if err or qs is None:
        return None, err or "unknown_context"

    q_prefix = (q_prefix or "").strip()

    if kind == "severity":
        return _distinct_severity_labels(qs, lim), None
    if kind == "status":
        return _distinct_open_closed(qs, lim), None
    if kind == "bool":
        assert db_path is not None
        raw = list(qs.values_list(db_path, flat=True).distinct())
        return _finalize_scalar_like_values(raw, lim, fld), None
    if kind in ("scalar", "m2m"):
        assert db_path is not None
        if ctx == "subdomains" and fld in SUBDOMAIN_DISPLAY_VALUE_FIELDS:
            return _subdomain_distinct_display_values(qs, fld, q_prefix, lim), None
        raw = _scalar_m2m_raw_values(qs, db_path, q_prefix)
        return _finalize_scalar_like_values(raw, lim, fld), None
    return None, "unknown_field"
