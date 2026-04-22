"""
Unit tests for api.pagination (parse_pagination_params, parse_limit_from_request).
"""

from rest_framework.exceptions import ValidationError

from api.pagination import (
    DEFAULT_LIST_LIMIT,
    PAGINATION_MAX_LENGTH,
    parse_limit_from_request,
    parse_pagination_params,
)
from utils.test_base import BaseTestCase


class ParsePaginationParamsTestCase(BaseTestCase):
    """Tests for parse_pagination_params."""

    def test_datatables_start_length_returns_expected(self):
        """DataTables style start/length returns type, start, length."""
        result = parse_pagination_params(start=0, length=10)
        self.assertEqual(result["type"], "datatables")
        self.assertEqual(result["start"], 0)
        self.assertEqual(result["length"], 10)

    def test_datatables_length_minus_one_capped_to_max(self):
        """length=-1 is capped to PAGINATION_MAX_LENGTH."""
        result = parse_pagination_params(start=0, length=-1)
        self.assertEqual(result["length"], PAGINATION_MAX_LENGTH)

    def test_rest_page_page_size_returns_expected(self):
        """REST style page/page_size returns correct start and length."""
        result = parse_pagination_params(page=2, page_size=20)
        self.assertEqual(result["type"], "rest")
        self.assertEqual(result["start"], 20)
        self.assertEqual(result["length"], 20)
        self.assertEqual(result["page"], 2)

    def test_no_params_returns_none(self):
        """When no pagination params given, returns None."""
        self.assertIsNone(parse_pagination_params())
        self.assertIsNone(parse_pagination_params(start=0))
        self.assertIsNone(parse_pagination_params(page=1))

    def test_datatables_negative_start_raises(self):
        """Negative start raises ValidationError."""
        with self.assertRaises(ValidationError):
            parse_pagination_params(start=-1, length=10)

    def test_datatables_zero_length_raises(self):
        """Zero length raises ValidationError."""
        with self.assertRaises(ValidationError):
            parse_pagination_params(start=0, length=0)

    def test_rest_invalid_page_raises(self):
        """Page < 1 raises ValidationError."""
        with self.assertRaises(ValidationError):
            parse_pagination_params(page=0, page_size=10)


class ParseLimitFromRequestTestCase(BaseTestCase):
    """Tests for parse_limit_from_request (uses mock request with .query_params / .data)."""

    def test_get_missing_limit_returns_default(self):
        """GET with no limit returns DEFAULT_LIST_LIMIT."""
        request = type("Req", (), {"method": "GET", "data": None, "query_params": {}})()
        self.assertEqual(parse_limit_from_request(request), DEFAULT_LIST_LIMIT)

    def test_get_limit_in_query_returns_value(self):
        """GET with limit in query_params returns validated limit."""
        request = type("Req", (), {"method": "GET", "data": None, "query_params": {"limit": "50"}})()
        self.assertEqual(parse_limit_from_request(request, default_limit=200), 50)

    def test_post_limit_in_data_returns_value(self):
        """POST with limit in data returns validated limit."""
        request = type("Req", (), {"method": "POST", "data": {"limit": 30}, "query_params": {}})()
        self.assertEqual(parse_limit_from_request(request, default_limit=200), 30)

    def test_limit_capped_at_max(self):
        """Limit above PAGINATION_MAX_LENGTH is capped."""
        request = type(
            "Req",
            (),
            {"method": "GET", "data": None, "query_params": {"limit": str(PAGINATION_MAX_LENGTH + 100)}},
        )()
        self.assertEqual(parse_limit_from_request(request), PAGINATION_MAX_LENGTH)

    def test_invalid_limit_uses_default(self):
        """Invalid or zero limit falls back to default."""
        request = type("Req", (), {"method": "GET", "data": None, "query_params": {"limit": "invalid"}})()
        self.assertEqual(parse_limit_from_request(request, default_limit=100), 100)
        request2 = type("Req", (), {"method": "GET", "data": None, "query_params": {"limit": "0"}})()
        self.assertEqual(parse_limit_from_request(request2, default_limit=100), 100)
