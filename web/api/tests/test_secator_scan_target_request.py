"""Tests for shared Secator scan target request parsing helpers."""

from api.helpers.secator_scan_target_request import (
    coerce_json_ip_address_ids,
    parse_comma_separated_int_ids,
    positive_ip_ids,
)
from utils.test_base import BaseTestCase


class SecatorScanTargetRequestParsingTest(BaseTestCase):
    def test_parse_comma_separated_int_ids_success(self) -> None:
        self.assertEqual(parse_comma_separated_int_ids("1, 2, 3", field_label="x"), [1, 2, 3])

    def test_parse_comma_separated_int_ids_rejects_non_int(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            parse_comma_separated_int_ids("1, a", field_label="ip_address_ids")
        self.assertIn("comma-separated list of integers", str(ctx.exception))

    def test_coerce_json_ip_address_ids_none_and_int(self) -> None:
        self.assertEqual(coerce_json_ip_address_ids(None), [])
        self.assertEqual(coerce_json_ip_address_ids(7), [7])

    def test_coerce_json_ip_address_ids_list(self) -> None:
        self.assertEqual(coerce_json_ip_address_ids([1, "2"]), [1, 2])

    def test_coerce_json_ip_address_ids_tuple(self) -> None:
        self.assertEqual(coerce_json_ip_address_ids((3, 4)), [3, 4])

    def test_coerce_json_ip_address_ids_comma_string(self) -> None:
        self.assertEqual(coerce_json_ip_address_ids(" 1, 2 ,3"), [1, 2, 3])

    def test_coerce_json_ip_address_ids_empty_string(self) -> None:
        self.assertEqual(coerce_json_ip_address_ids(""), [])
        self.assertEqual(coerce_json_ip_address_ids("  \t  "), [])

    def test_positive_ip_ids(self) -> None:
        self.assertEqual(positive_ip_ids([0, -1, 2, 3]), [2, 3])

    def test_coerce_json_ip_address_ids_invalid(self) -> None:
        with self.assertRaises(ValueError):
            coerce_json_ip_address_ids("not-a-list")
