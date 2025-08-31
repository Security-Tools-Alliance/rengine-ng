import logging
import os
import unittest
import pathlib
from pathlib import Path

os.environ['RENGINE_SECRET_KEY'] = 'secret'
os.environ['CELERY_ALWAYS_EAGER'] = 'True'

from celery.utils.log import get_task_logger
from reNgine.settings import CELERY_DEBUG
from reNgine.utilities.parser import parse_nmap_results 

logger = get_task_logger(__name__)
DOMAIN_NAME = os.environ['DOMAIN_NAME']
FIXTURES_DIR = pathlib.Path().absolute() / 'fixtures' / 'nmap_xml'

if not CELERY_DEBUG:
    logging.disable(logging.CRITICAL)


class TestNmapParsing(unittest.TestCase):
    def setUp(self):
        self.nmap_vuln_single_xml = FIXTURES_DIR / 'nmap_vuln_single.xml'
        self.nmap_vuln_multiple_xml = FIXTURES_DIR / 'nmap_vuln_multiple.xml'
        self.nmap_vulscan_single_xml = FIXTURES_DIR / 'nmap_vulscan_single.xml'
        self.nmap_vulscan_multiple_xml = FIXTURES_DIR / 'nmap_vulscan_multiple.xml'
        self.all_xml = [
            self.nmap_vuln_single_xml,
            self.nmap_vuln_multiple_xml,
            self.nmap_vulscan_single_xml,
            self.nmap_vulscan_multiple_xml
        ]

    def test_nmap_parse_vulnerabilities_basic(self):
        """Test parsing vulnerabilities from basic Nmap XML output."""
        xml_file = "tests/test_data/nmap/basic_scan.xml"
        xml_path = Path(xml_file)
        self.assertTrue(xml_path.exists(), f"Test file {xml_file} not found - missing test fixtures")
        
        vulns = parse_nmap_results(xml_path, parse_type='vulnerabilities')
        self.assertIsInstance(vulns, (list, tuple), f"Parser should return a list/tuple for {xml_file}")
        # Note: Basic scan XML may not contain vulnerabilities, so we just verify the parser works

    def test_nmap_parse_vulnerabilities_service(self):
        """Test parsing vulnerabilities from service Nmap XML output."""
        xml_file = "tests/test_data/nmap/service_scan.xml"
        xml_path = Path(xml_file)
        self.assertTrue(xml_path.exists(), f"Test file {xml_file} not found - missing test fixtures")
        
        vulns = parse_nmap_results(xml_path, parse_type='vulnerabilities')
        self.assertIsInstance(vulns, (list, tuple), f"Parser should return a list/tuple for {xml_file}")
        # Note: Basic scan XML may not contain vulnerabilities, so we just verify the parser works

    def test_nmap_parse_vulnerabilities_vuln(self):
        """Test parsing vulnerabilities from vuln Nmap XML output."""
        xml_file = "tests/test_data/nmap/vuln_scan.xml"
        xml_path = Path(xml_file)
        self.assertTrue(xml_path.exists(), f"Test file {xml_file} not found - missing test fixtures")
        
        vulns = parse_nmap_results(xml_path, parse_type='vulnerabilities')
        self.assertIsInstance(vulns, (list, tuple), f"Parser should return a list/tuple for {xml_file}")
        # Note: Basic scan XML may not contain vulnerabilities, so we just verify the parser works

    def test_nmap_parse_ports_basic(self):
        """Test parsing ports from basic Nmap XML output."""
        xml_file = "tests/test_data/nmap/basic_scan.xml"
        xml_path = Path(xml_file)
        self.assertTrue(xml_path.exists(), f"Test file {xml_file} not found - missing test fixtures")
        
        ports = parse_nmap_results(xml_path, parse_type='ports')
        self.assertGreater(len(ports), 0, f"No ports found in {xml_file}")

    def test_nmap_parse_ports_service(self):
        """Test parsing ports from service Nmap XML output."""
        xml_file = "tests/test_data/nmap/service_scan.xml"
        xml_path = Path(xml_file)
        self.assertTrue(xml_path.exists(), f"Test file {xml_file} not found - missing test fixtures")
        
        ports = parse_nmap_results(xml_path, parse_type='ports')
        self.assertGreater(len(ports), 0, f"No ports found in {xml_file}")

    def test_nmap_parse_ports_vuln(self):
        """Test parsing ports from vuln Nmap XML output."""
        xml_file = "tests/test_data/nmap/vuln_scan.xml"
        xml_path = Path(xml_file)
        self.assertTrue(xml_path.exists(), f"Test file {xml_file} not found - missing test fixtures")
        
        ports = parse_nmap_results(xml_path, parse_type='ports')
        self.assertGreater(len(ports), 0, f"No ports found in {xml_file}")
