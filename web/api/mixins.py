"""
Shared mixins for API viewsets that serve DataTables and REST list endpoints.

Centralizes no_page handling, optional default ordering for pagination, and the
list() behaviour that supports both DataTables params (start/length) and REST
params (page/page_size) to avoid duplication and inconsistent behaviour.
"""

from typing import Any, List, Optional

from django.db.models import Q
from rest_framework.response import Response

from api.helpers.advanced_search import parse_advanced_search_ast, parse_advanced_search_term
from api.helpers.advanced_search_eval import (
    ast_branch_children,
    ast_requires_legacy_eval,
    ast_to_q,
    atom_requires_port_bang_legacy,
    boolean_field_value_from_token,
)
from api.pagination import parse_pagination_params
from reNgine.utilities.logger import get_module_logger


_advanced_search_logger = get_module_logger(__name__)


def build_datatables_serverside_response(
    request: Any,
    records_total: int,
    records_filtered: int,
    data: List[Any],
) -> dict:
    """
    Build the official DataTables server-side response format.

    Returns only draw, recordsTotal, recordsFiltered, data as per
    https://datatables.net/manual/server-side. Draw is cast to int for security (XSS).
    """
    raw_draw = request.GET.get("draw", "1")
    try:
        draw = int(raw_draw)
    except (TypeError, ValueError):
        draw = 1
    return {
        "draw": draw,
        "recordsTotal": records_total,
        "recordsFiltered": records_filtered,
        "data": data,
    }


class DatatablePaginationMixin:
    """
    Mixin for viewsets that need DataTables-style no_page and optional default ordering.

    Set `datatable_default_ordering` on the viewset (e.g. ("name",) or ("-severity",)).
    If set, paginate_queryset will apply this ordering before paginating when the
    queryset is not already a list.
    """

    datatable_default_ordering: Optional[tuple[str, ...]] = None

    def paginate_queryset(self, queryset, view=None):
        if "no_page" in self.request.query_params:
            return None
        if self.datatable_default_ordering and not isinstance(queryset, list):
            queryset = queryset.order_by(*self.datatable_default_ordering)
        return self.paginator.paginate_queryset(queryset, self.request, view=self)


class DatatableListMixin:
    """
    Mixin that implements list() with support for DataTables (start/length) and REST (page/page_size).

    When start+length or page+page_size are present, returns the official DataTables
    server-side format via build_datatables_serverside_response. Otherwise delegates
    to default DRF list (paginate_queryset + get_paginated_response or full list).
    """

    def list(self, request, *args, **kwargs):
        base_queryset = self.get_queryset()
        filtered_queryset = self.filter_queryset(base_queryset)
        context = {"request": request}

        if pagination := parse_pagination_params(
            start=request.query_params.get("start"),
            length=request.query_params.get("length"),
            page=request.query_params.get("page"),
            page_size=request.query_params.get("page_size"),
        ):
            records_total = base_queryset.count()
            records_filtered = filtered_queryset.count()
            paginated_queryset = filtered_queryset[pagination["start"] : pagination["start"] + pagination["length"]]
            if hasattr(self, "get_list_serializer_context") and callable(self.get_list_serializer_context):
                context = {**context, **self.get_list_serializer_context(paginated_queryset)}
            serializer = self.get_serializer(paginated_queryset, many=True, context=context)
            return Response(
                build_datatables_serverside_response(request, records_total, records_filtered, serializer.data)
            )

        queryset = filtered_queryset

        page = self.paginate_queryset(queryset)
        if page is not None:
            if hasattr(self, "get_list_serializer_context") and callable(self.get_list_serializer_context):
                context = {**context, **self.get_list_serializer_context(page)}
            serializer = self.get_serializer(page, many=True, context=context)
            return self.get_paginated_response(serializer.data)

        if hasattr(self, "get_list_serializer_context") and callable(self.get_list_serializer_context):
            context = {**context, **self.get_list_serializer_context(queryset)}
        serializer = self.get_serializer(queryset, many=True, context=context)
        return Response(serializer.data)


class AdvancedSearchMixin:
    """
    Mixin providing advanced search with field operators and boolean joiners.

    Subclasses set ``search_config`` with general_fields, special_fields,
    numeric_fields, boolean_fields, and optional custom_handlers.
    Expressions are compiled to a single ``Q`` tree when possible (one ``.filter()``).
    Legacy queryset union/chaining is kept only for ``port!`` on subdomain DataTable
    (non-composable exclude semantics).
    """

    search_config = None

    def apply_advanced_search(self, queryset, search_value):
        """Apply advanced search: AND/OR, parentheses, != ; AND binds before OR."""
        if not search_value or not str(search_value).strip():
            return queryset

        raw = str(search_value).strip()
        ast, err = parse_advanced_search_ast(raw)
        if err == "empty":
            return queryset
        if err:
            _advanced_search_logger.warning(
                "Ignoring invalid advanced search expression (parse_error=%s); expression length=%s",
                err,
                len(raw),
            )
            return queryset
        if ast_requires_legacy_eval(ast, self._advanced_search_atom_requires_legacy_eval):
            return self._eval_advanced_search_ast_legacy(queryset, ast)
        q = ast_to_q(ast, self._advanced_search_atom_to_q)
        return queryset.filter(q)

    def _advanced_search_atom_requires_legacy_eval(self, term_raw: str) -> bool:
        cfg = self.search_config
        if not cfg:
            return False
        return atom_requires_port_bang_legacy(term_raw, cfg.get("custom_handlers"))

    def _custom_handler_to_q(self, lookup_title: str, operator: str, lookup_content: str) -> Optional[Q]:
        return None

    def general_lookup_q(self, search_value: str) -> Q:
        if not self.search_config or "general_fields" not in self.search_config:
            return Q()
        combined_q = Q()
        for field_q in self.search_config["general_fields"]:
            combined_q |= field_q(search_value) if callable(field_q) else field_q
        return combined_q

    def _special_lookup_q(self, term: str) -> Q:
        cfg = self.search_config
        if not cfg:
            return Q()
        parsed_term, term_err = parse_advanced_search_term(term)
        if term_err == "invalid_quoted_value":
            return Q(pk__in=[])
        if not parsed_term:
            return Q()
        lookup_title, operator, lookup_content = parsed_term
        custom_handlers = cfg.get("custom_handlers") or {}
        if lookup_title in custom_handlers:
            built = self._custom_handler_to_q(lookup_title, operator, lookup_content)
            return built if built is not None else Q()

        boolean_fields = cfg.get("boolean_fields") or {}
        if lookup_title in boolean_fields:
            field_path, true_val, false_val = boolean_fields[lookup_title]
            b = boolean_field_value_from_token(lookup_content, true_val, false_val)
            if b is None:
                return Q()
            if operator == "=":
                return Q(**{field_path: b})
            if operator == "!":
                return ~Q(**{field_path: b})
            return Q()

        numeric_fields = cfg.get("numeric_fields") or {}
        if lookup_title in numeric_fields:
            field_path = numeric_fields[lookup_title]
            try:
                int_value = int(lookup_content)
            except (ValueError, TypeError):
                return Q()
            if operator == "=":
                return Q(**{field_path: int_value})
            if operator == ">":
                return Q(**{f"{field_path}__gt": int_value})
            if operator == "<":
                return Q(**{f"{field_path}__lt": int_value})
            if operator == "!":
                return ~Q(**{field_path: int_value})
            return Q()

        special_fields = cfg.get("special_fields") or {}
        if lookup_title in special_fields:
            field_path = special_fields[lookup_title]
            if operator == "=":
                return Q(**{field_path: lookup_content})
            if operator == "!":
                return ~Q(**{field_path: lookup_content})
            return Q()

        return Q()

    def _advanced_search_atom_to_q(self, term: str) -> Q:
        parsed, term_err = parse_advanced_search_term(term)
        if term_err == "invalid_quoted_value":
            return Q(pk__in=[])
        if parsed is not None:
            return self._special_lookup_q(term)
        return self.general_lookup_q(term)

    def _eval_advanced_search_ast_legacy(self, queryset, node):
        if not isinstance(node, tuple) or len(node) != 2:
            return queryset
        kind = node[0]
        if kind == "atom":
            if not isinstance(node[1], str):
                return queryset
            term = node[1].strip()
            if not term:
                return queryset
            _parsed, te = parse_advanced_search_term(term)
            if te == "invalid_quoted_value":
                return queryset.none()
            if _parsed is not None:
                return self.special_lookup(queryset, term)
            return self.general_lookup(queryset, term)
        children = ast_branch_children(node)
        if children is None:
            return queryset
        if kind == "and":
            q = queryset
            for ch in children:
                q = self._eval_advanced_search_ast_legacy(q, ch)
            return q
        if kind == "or":
            union_qs = queryset.none()
            for ch in children:
                union_qs = union_qs | self._eval_advanced_search_ast_legacy(queryset, ch)
            return union_qs
        return queryset

    def general_lookup(self, queryset, search_value):
        q = self.general_lookup_q(search_value)
        return queryset.filter(q) if q else queryset

    def special_lookup(self, queryset, search_value):
        if not self.search_config:
            return queryset

        parsed_term, term_err = parse_advanced_search_term(search_value)
        if term_err == "invalid_quoted_value":
            return queryset.none()
        if not parsed_term:
            return queryset

        lookup_title, operator, lookup_content = parsed_term

        special_fields = self.search_config.get("special_fields", {})
        numeric_fields = self.search_config.get("numeric_fields", {})
        boolean_fields = self.search_config.get("boolean_fields", {})
        custom_handlers = self.search_config.get("custom_handlers", {})

        if lookup_title in custom_handlers:
            return custom_handlers[lookup_title](queryset, operator, lookup_content)

        if lookup_title in boolean_fields:
            field_path, true_val, false_val = boolean_fields[lookup_title]
            b = boolean_field_value_from_token(lookup_content, true_val, false_val)
            if b is None:
                return queryset
            if operator == "=":
                return queryset.filter(**{field_path: b})
            if operator == "!":
                return queryset.exclude(**{field_path: b})

        if lookup_title in numeric_fields:
            field_path = numeric_fields[lookup_title]
            try:
                int_value = int(lookup_content)
                if operator == "=":
                    return queryset.filter(**{field_path: int_value})
                if operator == ">":
                    return queryset.filter(**{f"{field_path}__gt": int_value})
                if operator == "<":
                    return queryset.filter(**{f"{field_path}__lt": int_value})
                if operator == "!":
                    return queryset.exclude(**{field_path: int_value})
            except (ValueError, TypeError):
                return queryset

        if lookup_title in special_fields:
            field_path = special_fields[lookup_title]
            if operator == "=":
                return queryset.filter(**{field_path: lookup_content})
            if operator == "!":
                return queryset.exclude(**{field_path: lookup_content})

        return queryset
