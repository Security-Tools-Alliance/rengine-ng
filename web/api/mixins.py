"""
Shared mixins for API viewsets that serve DataTables and REST list endpoints.

Centralizes no_page handling, optional default ordering for pagination, and the
list() behaviour that supports both DataTables params (start/length) and REST
params (page/page_size) to avoid duplication and inconsistent behaviour.
"""

from typing import Any, List, Optional

from rest_framework.response import Response

from api.pagination import parse_pagination_params


def build_datatables_list_response(total_count: int, results: List[Any]) -> dict:
    """
    Build the standard DataTables list JSON shape used by classic and scroller use cases.

    Single place for the response payload so count/results (and any future keys like
    total_count) stay consistent across viewsets and do not diverge.
    """
    return {"count": total_count, "results": results}


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

    When start+length or page+page_size are present, returns the standard DataTables
    list shape via build_datatables_list_response(count, results). Otherwise delegates
    to default DRF list (paginate_queryset + get_paginated_response or full list).
    """

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        context = {"request": request}

        if pagination := parse_pagination_params(
            start=request.query_params.get("start"),
            length=request.query_params.get("length"),
            page=request.query_params.get("page"),
            page_size=request.query_params.get("page_size"),
        ):
            total_count = queryset.count()
            paginated_queryset = queryset[pagination["start"] : pagination["start"] + pagination["length"]]
            if hasattr(self, "get_list_serializer_context") and callable(self.get_list_serializer_context):
                context = {**context, **self.get_list_serializer_context(paginated_queryset)}
            serializer = self.get_serializer(paginated_queryset, many=True, context=context)
            return Response(build_datatables_list_response(total_count, serializer.data))

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
