import json
import logging
import os
import yaml
from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()

os.environ.setdefault('RENGINE_SECRET_KEY', os.getenv('RENGINE_SECRET_KEY', 'secret'))
os.environ.setdefault('CELERY_ALWAYS_EAGER', os.getenv('CELERY_ALWAYS_EAGER', 'True'))

from reNgine.settings import CELERY_DEBUG
from celery.utils.log import get_task_logger
from reNgine.tasks import (dir_file_fuzz, fetch_url, http_crawl, initiate_scan,
                           osint, port_scan, subdomain_discovery,
                           vulnerability_scan)
from utils.test_base import BaseTestCase

logger = get_task_logger(__name__)
# To pass the DOMAIN_NAME variable when running tests, you can use:
# DOMAIN_NAME=example.com python3 manage.py test
# Or set a default value if the environment variable is not defined
DOMAIN_NAME = os.environ.get('DOMAIN_NAME', 'example.com')
# if not CELERY_DEBUG:
#     logging.disable(logging.CRITICAL)


class TestOnlineScan(BaseTestCase):
    def setUp(self):
        super().setUp()
        
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
        
        # Use data from TestDataGenerator instead of creating manually
        self.domain = self.data_generator.domain
        self.engine = self.data_generator.engine_type
        self.scan = self.data_generator.scan_history
        self.endpoint = self.data_generator.endpoint
        self.subdomain = self.data_generator.subdomain

        self.ctx = {
            'track': False,
            'yaml_configuration': self.yaml_configuration,
            'results_dir': '/tmp',
            'scan_history_id': self.scan.id,
            'engine_id': self.engine.id
        }

    def test_http_crawl(self):
        results = http_crawl([DOMAIN_NAME], ctx=self.ctx)
        self.assertGreater(len(results), 0)
        self.assertIn('final_url', results[0])
        url = results[0]['final_url']
        if CELERY_DEBUG:
            print(url)

    def test_subdomain_discovery(self):
        domain = DOMAIN_NAME.lstrip('rengine.')
        subdomains = subdomain_discovery(domain, ctx=self.ctx)
        if CELERY_DEBUG:
            print(json.dumps(subdomains, indent=4))
        self.assertTrue(subdomains is not None)
        self.assertGreater(len(subdomains), 0)

    def test_fetch_url(self):
        urls = fetch_url(urls=[self.url], ctx=self.ctx)
        if CELERY_DEBUG:
            print(urls)
        self.assertGreater(len(urls), 0)

    def test_dir_file_fuzz(self):
        """Test directory file fuzzing functionality with race condition handling."""
        import threading
        from reNgine.utilities.database import save_fuzzing_file
        
        # Test basic functionality - create new file (use unique data different from TestDataGenerator)
        directory_file, created = save_fuzzing_file(
            name="test_admin",
            url="https://test.example.com/admin", 
            http_status=200,
            length=1024,
            words=50,
            lines=25,
            content_type="text/html"
        )
        self.assertIsNotNone(directory_file)
        self.assertTrue(created)
        self.assertEqual(directory_file.name, "test_admin")
        self.assertEqual(directory_file.url, "https://test.example.com/admin")
        self.assertEqual(directory_file.http_status, 200)
        
        # Test finding existing file
        existing_file, created = save_fuzzing_file(
            name="test_admin",
            url="https://test.example.com/admin",
            http_status=200,
            length=2048,  # Different values
            words=100
        )
        self.assertIsNotNone(existing_file)
        self.assertFalse(created)
        self.assertEqual(existing_file.id, directory_file.id)
        
        # Test different files are created separately 
        different_file, created = save_fuzzing_file(
            name="test_login",
            url="https://test.example.com/login",
            http_status=200
        )
        self.assertIsNotNone(different_file)
        self.assertTrue(created)
        self.assertNotEqual(different_file.id, directory_file.id)
        
        # Test concurrent access with same data (race condition test)
        results = []
        errors = []
        
        def create_concurrent_file():
            try:
                file_obj, created = save_fuzzing_file(
                    name="test_concurrent",
                    url="https://test.example.com/concurrent",
                    http_status=200,
                    length=512
                )
                results.append((file_obj.id if file_obj else None, created))
            except Exception as e:
                errors.append(str(e))
        
        # Run 3 threads concurrently
        threads = []
        for i in range(3):
            thread = threading.Thread(target=create_concurrent_file)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify results
        self.assertEqual(len(errors), 0, f"Errors occurred: {errors}")
        self.assertEqual(len(results), 3, "All threads should complete")
        
        # Check that all threads got the same file ID (no duplicates)
        file_ids = [result[0] for result in results if result[0] is not None]
        unique_ids = set(file_ids)
        self.assertEqual(len(unique_ids), 1, f"Expected 1 unique file ID, got {len(unique_ids)}: {unique_ids}")
        
        # Exactly one thread should have created=True, others should have created=False
        created_flags = [result[1] for result in results]
        created_count = sum(created_flags)
        self.assertEqual(created_count, 1, f"Expected exactly 1 creation, got {created_count}")
        
        if CELERY_DEBUG:
            print(f"Concurrent test results: {results}")
            print(f"Unique file IDs: {unique_ids}")

    def test_vulnerability_scan(self):
        vulns = vulnerability_scan(urls=[self.url], ctx=self.ctx)
        if CELERY_DEBUG:
            print(json.dumps(vulns, indent=4))
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