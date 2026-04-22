"""API for advanced DataTable search: field catalog and expression validation."""

from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from api.helpers.advanced_search import (
    ADVANCED_SEARCH_FIELD_CATALOG,
    ALLOWED_CONTEXTS,
    validate_expression_for_context,
)
from api.helpers.advanced_search_values import distinct_values_for_context_field
from reNgine.core.data import safe_int_cast


class AdvancedSearchFieldsView(APIView):
    """GET ?context=subdomains|endpoints|vulnerabilities — searchable fields and syntax hints."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        ctx = (request.query_params.get("context") or "").strip().lower()
        if ctx not in ALLOWED_CONTEXTS:
            return Response(
                {"detail": "Invalid or missing context. Use: subdomains, endpoints, vulnerabilities."},
                status=400,
            )
        return Response(
            {
                "context": ctx,
                "fields": ADVANCED_SEARCH_FIELD_CATALOG[ctx],
                "operators": ["=", "!=", "!", ">", "<"],
                "joiners": ["&", "|", "AND", "OR"],
                "note": "AND groups before OR. Example: a|b&c means a OR (b AND c). Use parentheses to override.",
            }
        )


class AdvancedSearchValidateView(APIView):
    """POST JSON { expression, context } — syntax validation and unknown-field hints."""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        expression = request.data.get("expression") if hasattr(request, "data") else ""
        ctx = (request.data.get("context") or "").strip().lower() if hasattr(request, "data") else ""
        if ctx not in ALLOWED_CONTEXTS:
            return Response({"valid": False, "error": "unknown_context", "warnings": []}, status=400)
        result = validate_expression_for_context(str(expression or ""), ctx)
        return Response(result)


class AdvancedSearchValuesView(APIView):
    """GET ?context=&field=&project=&scan_history=&... — distinct values for Build filter."""

    permission_classes = [IsAuthenticated]
    renderer_classes = [JSONRenderer]

    def get(self, request):
        ctx = (request.query_params.get("context") or "").strip().lower()
        field = (request.query_params.get("field") or "").strip().lower()
        q = (request.query_params.get("q") or "").strip()
        limit_raw = safe_int_cast(request.query_params.get("limit"))
        limit = limit_raw if limit_raw and limit_raw > 0 else 200
        values, err = distinct_values_for_context_field(request, ctx, field, q_prefix=q, limit=limit)
        if err == "unknown_context":
            return Response(
                {
                    "detail": "Invalid or missing context. Use: subdomains, endpoints, vulnerabilities.",
                    "context": ctx,
                },
                status=400,
            )
        if err == "unknown_field":
            return Response(
                {
                    "detail": "Invalid field for this context.",
                    "context": ctx,
                    "field": field,
                },
                status=400,
            )
        return Response({"context": ctx, "field": field, "values": values or []})
