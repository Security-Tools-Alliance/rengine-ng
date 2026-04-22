from reNgine.services.endpoint_port_resolution import (
    RESOLUTION_RULES_SUMMARY,
    extract_port_number_from_http_url,
    resolve_port_id_for_subdomain_from_ip_port_map,
    resolve_port_id_from_ip_port_map,
    resolve_port_pk_for_endpoint_maps,
)
from utils.test_base import BaseTestCase


class EndpointPortResolutionTestCase(BaseTestCase):
    def test_summary_is_documented(self) -> None:
        self.assertIn("IP", RESOLUTION_RULES_SUMMARY)
        self.assertIn("subdomain", RESOLUTION_RULES_SUMMARY.lower())

    def test_resolve_from_ip_map(self) -> None:
        m = {(1, 443): 99}
        self.assertEqual(resolve_port_id_from_ip_port_map(m, 1, 443), 99)
        self.assertIsNone(resolve_port_id_from_ip_port_map(m, 1, 80))

    def test_resolve_subdomain_unique_candidate(self) -> None:
        m = {(10, 8080): 5, (11, 8080): 5}
        self.assertEqual(resolve_port_id_for_subdomain_from_ip_port_map(m, {10, 11}, 8080), 5)

    def test_resolve_subdomain_ambiguous_returns_none(self) -> None:
        m = {(10, 8080): 5, (11, 8080): 6}
        self.assertIsNone(resolve_port_id_for_subdomain_from_ip_port_map(m, {10, 11}, 8080))

    def test_extract_port_explicit_and_defaults(self) -> None:
        self.assertEqual(extract_port_number_from_http_url("https://x.example:8443/"), 8443)
        self.assertEqual(extract_port_number_from_http_url("https://x.example/"), 443)
        self.assertEqual(extract_port_number_from_http_url("http://x.example/"), 80)
        self.assertIsNone(extract_port_number_from_http_url(""))
        self.assertIsNone(extract_port_number_from_http_url(None))
        self.assertIsNone(extract_port_number_from_http_url("ftp://x.example/"))

    def test_resolve_port_pk_for_endpoint_maps_ip_branch(self) -> None:
        m = {(1, 443): 99}
        pid = resolve_port_pk_for_endpoint_maps(
            port_number=443,
            ip_address_id=1,
            subdomain_id=None,
            subdomain_to_ip_ids={},
            port_id_by_ip_and_number=m,
        )
        self.assertEqual(pid, 99)

    def test_resolve_port_pk_for_endpoint_maps_subdomain_cache(self) -> None:
        m = {(10, 80): 7}
        cache: dict[tuple[int, int], int | None] = {}
        sid = 5
        pid = resolve_port_pk_for_endpoint_maps(
            port_number=80,
            ip_address_id=None,
            subdomain_id=sid,
            subdomain_to_ip_ids={sid: {10}},
            port_id_by_ip_and_number=m,
            subdomain_port_cache=cache,
        )
        self.assertEqual(pid, 7)
        self.assertEqual(cache[(sid, 80)], 7)
        self.assertEqual(
            resolve_port_pk_for_endpoint_maps(
                port_number=80,
                ip_address_id=None,
                subdomain_id=sid,
                subdomain_to_ip_ids={sid: {10}},
                port_id_by_ip_and_number=m,
                subdomain_port_cache=cache,
            ),
            7,
        )
