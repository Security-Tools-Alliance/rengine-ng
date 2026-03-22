"""Unit tests for subdomain / IP mutual-exclusion API helpers."""

from django.test import SimpleTestCase

from api.helpers.subdomain_ip_xor import (
    both_subdomain_and_ip_provided_error,
    subdomain_ids_conflict_when_ip_address_ids_requested_error,
    xor_subdomain_ids_or_ip_address_ids_error,
    xor_subdomain_ip_single_ids_error,
)


class SubdomainIpXorHelpersTests(SimpleTestCase):
    def test_xor_single_ids_ok_subdomain(self) -> None:
        self.assertIsNone(xor_subdomain_ip_single_ids_error(1, None))
        self.assertIsNone(xor_subdomain_ip_single_ids_error(1, 0))

    def test_xor_single_ids_ok_ip(self) -> None:
        self.assertIsNone(xor_subdomain_ip_single_ids_error(None, 2))

    def test_xor_single_ids_rejects_both_or_neither(self) -> None:
        msg = "Provide exactly one of subdomain_id or ip_address_id"
        self.assertEqual(xor_subdomain_ip_single_ids_error(None, None), msg)
        self.assertEqual(xor_subdomain_ip_single_ids_error(1, 2), msg)

    def test_both_provided_recon_note(self) -> None:
        self.assertIsNone(both_subdomain_and_ip_provided_error(None, None))
        self.assertIsNone(both_subdomain_and_ip_provided_error(1, None))
        self.assertIsNotNone(both_subdomain_and_ip_provided_error(1, 2))

    def test_xor_list_targets(self) -> None:
        msg = "Provide exactly one of subdomain_ids or ip_address_ids"
        self.assertIsNone(xor_subdomain_ids_or_ip_address_ids_error([1], []))
        self.assertIsNone(xor_subdomain_ids_or_ip_address_ids_error([], [2]))
        self.assertEqual(xor_subdomain_ids_or_ip_address_ids_error([], []), msg)
        self.assertEqual(xor_subdomain_ids_or_ip_address_ids_error([1], [2]), msg)

    def test_subdomain_ids_conflict_with_ip_param(self) -> None:
        self.assertIsNone(subdomain_ids_conflict_when_ip_address_ids_requested_error([]))
        self.assertIsNotNone(subdomain_ids_conflict_when_ip_address_ids_requested_error([1]))
