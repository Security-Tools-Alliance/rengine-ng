import importlib

from django.apps import apps as global_apps

from startScan.models import (
    Certificate,
    Domain,
    Employee,
    EndPoint,
    Exploit,
    MetaFinderDocument,
    SecatorRunner,
    Subdomain,
    Vulnerability,
)
from utils.test_base import BaseTestCase


class CleanupIpDomainsMigrationTestCase(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.scan_history = self.data_generator.create_scan_history()

    def test_cleanup_ip_domains_detaches_children_before_delete(self):
        ip_domain = Domain.objects.create(name="192.0.2.10", scan_history=self.scan_history)
        cidr_domain = Domain.objects.create(name="198.51.100.0/24", scan_history=self.scan_history)
        range_domain = Domain.objects.create(name="203.0.113.10-203.0.113.20", scan_history=self.scan_history)
        valid_domain = Domain.objects.create(name="clean-example.test", scan_history=self.scan_history)

        subdomain = Subdomain.objects.create(
            name="api.clean-example.test",
            scan_history=self.scan_history,
            domain=ip_domain,
        )
        endpoint = EndPoint.objects.create(
            http_url="https://api.clean-example.test/health",
            scan_history=self.scan_history,
            domain=ip_domain,
            subdomain=subdomain,
        )
        vulnerability = Vulnerability.objects.create(
            name="sample vuln",
            severity=2,
            domain=ip_domain,
            scan_history=self.scan_history,
        )
        document = MetaFinderDocument.objects.create(
            domain=ip_domain,
            scan_history=self.scan_history,
            doc_name="report.txt",
        )
        employee = Employee.objects.create(domain=ip_domain, scan_history=self.scan_history, name="Test User")
        exploit = Exploit.objects.create(name="sample exploit", domain=ip_domain, scan_history=self.scan_history)
        runner = SecatorRunner.objects.create(runner_type="scan", domain=ip_domain, scan_history=self.scan_history)
        certificate = Certificate.objects.create(host="192.0.2.10", domain=ip_domain, scan_history=self.scan_history)

        migration_module = importlib.import_module("startScan.migrations.0124_cleanup_ip_domains")
        migration_module.cleanup_ip_domains(global_apps, schema_editor=None)

        self.assertFalse(Domain.objects.filter(pk=ip_domain.pk).exists())
        self.assertFalse(Domain.objects.filter(pk=cidr_domain.pk).exists())
        self.assertFalse(Domain.objects.filter(pk=range_domain.pk).exists())
        self.assertTrue(Domain.objects.filter(pk=valid_domain.pk).exists())

        for model, pk in (
            (Subdomain, subdomain.pk),
            (EndPoint, endpoint.pk),
            (Vulnerability, vulnerability.pk),
            (MetaFinderDocument, document.pk),
            (Employee, employee.pk),
            (Exploit, exploit.pk),
            (SecatorRunner, runner.pk),
            (Certificate, certificate.pk),
        ):
            instance = model.objects.get(pk=pk)
            self.assertIsNone(instance.domain_id)
