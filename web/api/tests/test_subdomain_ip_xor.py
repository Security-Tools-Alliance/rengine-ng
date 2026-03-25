"""Unit tests for subdomain / IP mutual-exclusion API helpers."""

from django.http import QueryDict
from django.test import SimpleTestCase

from api.helpers.subdomain_ip_xor import (
    ATTACK_SURFACE_ENTITY_QUERY_ID_KEYS,
    ATTACK_SURFACE_ENTITY_XOR_MESSAGE,
    ATTACK_SURFACE_KIND_ORGANIZATION,
    ATTACK_SURFACE_KIND_SCAN_HISTORY,
    ATTACK_SURFACE_KIND_SUBDOMAIN,
    ATTACK_SURFACE_QUERY_ID_KIND_BY_KEY,
    attack_surface_entity_query_params_invalid_error,
    both_subdomain_and_ip_provided_error,
    iter_attack_surface_entity_kinds_and_ids,
    resolve_attack_surface_entity_kind_and_pk,
    subdomain_ids_conflict_when_ip_address_ids_requested_error,
    xor_attack_surface_entity_ids_error,
    xor_subdomain_ids_or_ip_address_ids_error,
    xor_subdomain_ip_single_ids_error,
)


class SubdomainIpXorHelpersTests(SimpleTestCase):
    def test_query_id_keys_stay_aligned_with_iter_helper(self) -> None:
        key_set = set(ATTACK_SURFACE_ENTITY_QUERY_ID_KEYS)
        map_key_set = {k for k, _ in ATTACK_SURFACE_QUERY_ID_KIND_BY_KEY}
        self.assertSetEqual(key_set, map_key_set)

        kinds = {
            kind
            for kind, _ in iter_attack_surface_entity_kinds_and_ids(
                subdomain_id=1,
                ip_address_id=2,
                target_id=3,
                scope_id=4,
                organization_id=5,
                scan_history_id=6,
            )
        }
        self.assertSetEqual(kinds, {kind for _, kind in ATTACK_SURFACE_QUERY_ID_KIND_BY_KEY})

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

    def test_xor_attack_surface_entity_ids_ok_single(self) -> None:
        self.assertIsNone(xor_attack_surface_entity_ids_error(1, None, None, None, None, None))
        self.assertIsNone(xor_attack_surface_entity_ids_error(None, 2, None, None, None, None))
        self.assertIsNone(xor_attack_surface_entity_ids_error(None, None, 3, None, None, None))
        self.assertIsNone(xor_attack_surface_entity_ids_error(None, None, None, 4, None, None))
        self.assertIsNone(xor_attack_surface_entity_ids_error(None, None, None, None, 5, None))
        self.assertIsNone(xor_attack_surface_entity_ids_error(None, None, None, None, None, 6))

    def test_xor_attack_surface_entity_ids_rejects_zero_or_multiple(self) -> None:
        msg = xor_attack_surface_entity_ids_error(None, None, None, None, None, None)
        self.assertIsNotNone(msg)
        self.assertEqual(msg, ATTACK_SURFACE_ENTITY_XOR_MESSAGE)
        self.assertIn("exactly one", msg.lower())
        self.assertIsNotNone(xor_attack_surface_entity_ids_error(1, 2, None, None, None, None))
        self.assertIsNotNone(xor_attack_surface_entity_ids_error(1, None, 3, None, None, None))
        self.assertIsNotNone(xor_attack_surface_entity_ids_error(1, None, None, None, None, 7))

    def test_xor_attack_surface_entity_ids_ignores_non_positive_ints(self) -> None:
        self.assertIsNotNone(xor_attack_surface_entity_ids_error(0, None, None, None, None, None))
        self.assertIsNotNone(xor_attack_surface_entity_ids_error(None, -1, None, None, None, None))
        self.assertIsNone(xor_attack_surface_entity_ids_error(1, -1, None, None, None, None))

    def test_attack_surface_query_params_reject_non_positive_when_present(self) -> None:
        q = QueryDict("target_id=0&organization_id=5")
        err = attack_surface_entity_query_params_invalid_error(q)
        self.assertIsNotNone(err)
        self.assertIn("target_id", err)

    def test_attack_surface_query_params_reject_non_positive_analysis_id_when_present(self) -> None:
        q = QueryDict("target_id=1&attack_surface_analysis_id=0")
        err = attack_surface_entity_query_params_invalid_error(q)
        self.assertIsNotNone(err)
        self.assertIn("attack_surface_analysis_id", err)

    def test_attack_surface_query_params_ok_single_positive_only(self) -> None:
        q = QueryDict("organization_id=5")
        self.assertIsNone(attack_surface_entity_query_params_invalid_error(q))

    def test_attack_surface_query_params_reject_non_numeric(self) -> None:
        q = QueryDict("subdomain_id=not_an_int")
        err = attack_surface_entity_query_params_invalid_error(q)
        self.assertIsNotNone(err)
        self.assertIn("subdomain_id", err)

    def test_resolve_attack_surface_entity_kind_and_pk_single(self) -> None:
        self.assertEqual(
            resolve_attack_surface_entity_kind_and_pk(1, None, None, None, None, None),
            (ATTACK_SURFACE_KIND_SUBDOMAIN, 1),
        )
        self.assertEqual(
            resolve_attack_surface_entity_kind_and_pk(None, None, None, None, 99, None),
            (ATTACK_SURFACE_KIND_ORGANIZATION, 99),
        )
        self.assertEqual(
            resolve_attack_surface_entity_kind_and_pk(None, None, None, None, None, 123),
            (ATTACK_SURFACE_KIND_SCAN_HISTORY, 123),
        )

    def test_resolve_attack_surface_entity_kind_and_pk_none_or_ambiguous(self) -> None:
        self.assertIsNone(resolve_attack_surface_entity_kind_and_pk(None, None, None, None, None, None))
        self.assertIsNone(resolve_attack_surface_entity_kind_and_pk(1, 2, None, None, None, None))
