import importlib

from django.apps import apps as global_apps
from django.db import models

from startScan.models import EndPoint, IpAddress, Port, Subdomain
from utils.test_base import BaseTestCase


def _live_subdomain_ip_m2m_column_names() -> tuple[str, str]:
    """Mirror migration logic: FK attnames on the automatic through table for Subdomain.ip_addresses."""
    m2m = Subdomain._meta.get_field("ip_addresses")
    through = m2m.remote_field.through
    lhs_model = m2m.model
    rhs_model = m2m.remote_field.model
    lhs_key = (lhs_model._meta.app_label, lhs_model._meta.model_name)
    rhs_key = (rhs_model._meta.app_label, rhs_model._meta.model_name)
    lhs_att: str | None = None
    rhs_att: str | None = None
    for cand in through._meta.fields:
        if not isinstance(cand, models.ForeignKey):
            continue
        rel_meta = cand.remote_field.model._meta
        rel_key = (rel_meta.app_label, rel_meta.model_name)
        if rel_key == lhs_key:
            lhs_att = cand.get_attname()
        elif rel_key == rhs_key:
            rhs_att = cand.get_attname()
    assert lhs_att is not None and rhs_att is not None
    return lhs_att, rhs_att


class EndpointPortBackfillMigrationTestCase(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.scan_history = self.data_generator.create_scan_history()
        self.domain = self.data_generator.create_domain(scan_history=self.scan_history)

    def test_migration_ip_addresses_m2m_through_meta_matches_live_model(self) -> None:
        mod = importlib.import_module("startScan.migrations.0130_endpoint_port_fk_and_backfill")
        through_model, sub_att, ip_att = mod._ip_addresses_m2m_through_meta(Subdomain)
        self.assertIs(through_model, Subdomain.ip_addresses.through)
        exp_sub, exp_ip = _live_subdomain_ip_m2m_column_names()
        self.assertEqual(sub_att, exp_sub)
        self.assertEqual(ip_att, exp_ip)

    def test_backfill_sets_port_for_ip_endpoint(self):
        ip = IpAddress.objects.create(address="203.0.113.10", scan_history=self.scan_history)
        port = Port.objects.create(number=8080, ip_address=ip)
        endpoint = EndPoint.objects.create(
            scan_history=self.scan_history,
            domain=self.domain,
            ip_address=ip,
            subdomain=None,
            http_url="http://203.0.113.10:8080/",
            port=None,
        )

        migration_module = importlib.import_module("startScan.migrations.0130_endpoint_port_fk_and_backfill")
        migration_module.backfill_endpoint_port(global_apps, schema_editor=None)

        endpoint.refresh_from_db()
        self.assertEqual(endpoint.port_id, port.id)

    def test_backfill_sets_port_for_subdomain_endpoint_with_single_candidate(self):
        subdomain = Subdomain.objects.create(
            name="api.example.com",
            scan_history=self.scan_history,
            domain=self.domain,
        )
        ip = IpAddress.objects.create(address="198.51.100.21", scan_history=self.scan_history)
        subdomain.ip_addresses.add(ip)
        port = Port.objects.create(number=8443, ip_address=ip)
        endpoint = EndPoint.objects.create(
            scan_history=self.scan_history,
            domain=self.domain,
            ip_address=None,
            subdomain=subdomain,
            http_url="https://api.example.com:8443/",
            port=None,
        )

        migration_module = importlib.import_module("startScan.migrations.0130_endpoint_port_fk_and_backfill")
        migration_module.backfill_endpoint_port(global_apps, schema_editor=None)

        endpoint.refresh_from_db()
        self.assertEqual(endpoint.port_id, port.id)
