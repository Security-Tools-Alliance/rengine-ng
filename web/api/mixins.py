"""
Shared mixins for API viewsets that serve DataTables and REST list endpoints.

Centralizes no_page handling, optional default ordering for pagination, and the
list() behaviour that supports both DataTables params (start/length) and REST
params (page/page_size) to avoid duplication and inconsistent behaviour.
"""

from typing import Any, List, Optional

from rest_framework.response import Response

from api.pagination import parse_pagination_params


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
