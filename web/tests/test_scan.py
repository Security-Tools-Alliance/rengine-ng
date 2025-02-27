import json
import os
import unittest
import yaml
from dotenv import load_dotenv
from reNgine.settings import CELERY_DEBUG
from celery.utils.log import get_task_logger
from scanEngine.models import EngineType
from django.utils import timezone
from reNgine.tasks.url import fetch_url
from reNgine.tasks.http import http_crawl
from reNgine.tasks.port_scan import port_scan
from reNgine.tasks.subdomain import subdomain_discovery
from reNgine.tasks.vulnerability import vulnerability_scan
from startScan.models import Endpoint, Domain, ScanHistory, Subdomain

# Load environment variables from a .env file
load_dotenv()

os.environ.setdefault('RENGINE_SECRET_KEY', os.getenv('RENGINE_SECRET_KEY', 'secret'))
os.environ.setdefault('CELERY_ALWAYS_EAGER', os.getenv('CELERY_ALWAYS_EAGER', 'True'))


logger = get_task_logger(__name__)
# To pass the DOMAIN_NAME variable when running tests, you can use:
# DOMAIN_NAME=example.com python3 manage.py test
# Or set a default value if the environment variable is not defined
DOMAIN_NAME = os.environ.get('DOMAIN_NAME', 'example.com')
# if not CELERY_DEBUG:
#     logging.disable(logging.CRITICAL)


class TestOnlineScan(unittest.TestCase):
    def setUp(self):
        self.url = f'https://{DOMAIN_NAME}'
        self.yaml_configuration = {
            'subdomain_discovery': {},
            'port_scan': {},
            'vulnerability_scan': {},
            'osint': {},
            'fetch_url': {},
            'dir_file_fuzz': {},
            'screenshot': {}
        }
        self.domain, _ = Domain.objects.get_or_create(name=DOMAIN_NAME)
        self.engine = EngineType(
            engine_name='test_engine',
            yaml_configuration=yaml.dump(self.yaml_configuration))
        self.engine.save()
        self.scan = ScanHistory(
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now())
        self.scan.save()
        self.endpoint, _ = Endpoint.objects.get_or_create(
            scan_history=self.scan,
            target_domain=self.domain,
            http_url=self.url)
        self.subdomain, _ = Subdomain.objects.get_or_create(
            name=DOMAIN_NAME,
            target_domain=self.domain,
            scan_history=self.scan,
            http_url=self.url)

        self.ctx = {
            'track': False,
            'yaml_configuration': self.yaml_configuration,
            'results_dir': '/tmp',
            'scan_history_id': self.scan.id,
            'engine_id': self.engine.id
        }

    def tearDown(self):
        self.domain.delete()
        self.subdomain.delete()
        self.endpoint.delete()
        self.scan.delete()
        self.engine.delete()

    def test_http_crawl(self):
        results = http_crawl([DOMAIN_NAME], ctx=self.ctx)
        self.assertGreater(len(results), 0)
        self.assertIn('final_url', results[0])
        url = results[0]['final_url']

    def test_subdomain_discovery(self):
        domain = DOMAIN_NAME.lstrip('rengine.')
        subdomains = subdomain_discovery(domain, ctx=self.ctx)
        self.assertTrue(subdomains is not None)
        self.assertGreater(len(subdomains), 0)

    def test_fetch_url(self):
        urls = fetch_url(urls=[self.url], ctx=self.ctx)
        self.assertGreater(len(urls), 0)

    # def test_dir_file_fuzz(self):
    #     urls = dir_file_fuzz(ctx=self.ctx)
    #     self.assertGreater(len(urls), 0)

    def test_vulnerability_scan(self):
        vulns = vulnerability_scan(urls=[self.url], ctx=self.ctx)
        self.assertTrue(vulns is not None)

    def test_network_scan(self):
        subdomains = subdomain_discovery(DOMAIN_NAME, ctx=self.ctx)
        self.assertGreater(len(subdomains), 0)
        host = subdomains[0]['name']
        ports = port_scan(hosts=[host], ctx=self.ctx)
        urls = []
        for host, ports in ports.items():
            print(f'Host {host} opened ports: {ports}')
            self.assertGreater(len(ports), 0)
            self.assertIn(80, ports)
            self.assertIn(443, ports)
            for port in ports:
                if port in [80, 443]: # http
                    results = http_crawl(urls=[f'{host}:{port}'])
                    self.assertGreater(len(results), 0)
                    final_url = results[0]['final_url']
                    urls.append(final_url)
        self.assertGreater(len(urls), 0)
        vulns = vulnerability_scan(urls=urls, ctx=self.ctx)

    # def test_initiate_scan(self):
    #     scan = ScanHistory()
    #     domain = Domain(name=DOMAIN_NAME)
    #     domain.save()
    #     subdomain = Subdomain(name=DOMAIN_NAME, domain=domain)
    #     subdomain.save()