"""Tests for reNgine.utilities.request (get_string_from_post_or_json)."""

import json

from django.test import RequestFactory

from reNgine.utilities.request import get_string_from_post_or_json
from utils.test_base import BaseTestCase


class GetStringFromPostOrJsonTest(BaseTestCase):
    """Tests for get_string_from_post_or_json."""

    def setUp(self) -> None:
        super().setUp()
        self.factory = RequestFactory()

    def test_post_form_returns_value(self) -> None:
        request = self.factory.post("/", data={"raw": "scope text here"})
        value, error = get_string_from_post_or_json(request, key="raw")
        self.assertIsNone(error)
        self.assertEqual(value, "scope text here")

    def test_post_form_missing_key_returns_none_none(self) -> None:
        request = self.factory.post("/", data={"other": "x"})
        value, error = get_string_from_post_or_json(request, key="raw")
        self.assertIsNone(error)
        self.assertIsNone(value)

    def test_json_body_returns_value(self) -> None:
        request = self.factory.post(
            "/",
            data=json.dumps({"raw": "json scope"}),
            content_type="application/json",
        )
        value, error = get_string_from_post_or_json(request, key="raw")
        self.assertIsNone(error)
        self.assertEqual(value, "json scope")

    def test_json_body_invalid_returns_error(self) -> None:
        request = self.factory.post(
            "/",
            data="not valid json",
            content_type="application/json",
        )
        value, error = get_string_from_post_or_json(request, key="raw")
        self.assertEqual(error, "Invalid JSON body")
        self.assertIsNone(value)

    def test_empty_body_returns_none_none(self) -> None:
        request = self.factory.post("/")
        value, error = get_string_from_post_or_json(request, key="raw")
        self.assertIsNone(error)
        self.assertIsNone(value)

    def test_json_body_non_string_value_returns_none(self) -> None:
        request = self.factory.post(
            "/",
            data=json.dumps({"raw": 123}),
            content_type="application/json",
        )
        value, error = get_string_from_post_or_json(request, key="raw")
        self.assertIsNone(error)
        self.assertIsNone(value)

    def test_custom_key(self) -> None:
        request = self.factory.post("/", data={"input_text": "custom"})
        value, error = get_string_from_post_or_json(request, key="input_text")
        self.assertIsNone(error)
        self.assertEqual(value, "custom")
