import logging
import os
import unittest
import pathlib
import pytest
from pathlib import Path

os.environ['RENGINE_SECRET_KEY'] = 'secret'
os.environ['CELERY_ALWAYS_EAGER'] = 'True'

from celery.utils.log import get_task_logger
from reNgine.settings import CELERY_DEBUG
from reNgine.utils.parsers import parse_nmap_results 

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

    @pytest.mark.parametrize("xml_file", [
        "web/tests/test_data/nmap/basic_scan.xml",
        "web/tests/test_data/nmap/service_scan.xml",
        "web/tests/test_data/nmap/vuln_scan.xml"
    ])
    def test_nmap_parse_vulnerabilities(self, xml_file):
        """Test parsing vulnerabilities from Nmap XML output files."""
        # Arrange
        xml_path = Path(xml_file)
        assert xml_path.exists(), f"Test file {xml_file} not found"
        
        # Act
        vulns = parse_nmap_results(xml_path, parse_type='vulnerabilities')
        
        # Assert
        assert len(vulns) > 0, f"No vulnerabilities found in {xml_file}"

    @pytest.mark.parametrize("xml_file", [
        "web/tests/test_data/nmap/basic_scan.xml",
        "web/tests/test_data/nmap/service_scan.xml",
        "web/tests/test_data/nmap/vuln_scan.xml"
    ])
    def test_nmap_parse_ports(self, xml_file):
        """Test parsing ports from Nmap XML output files."""
        # Arrange
        xml_path = Path(xml_file)
        assert xml_path.exists(), f"Test file {xml_file} not found"
        
        # Act
        ports = parse_nmap_results(xml_path, parse_type='ports')
        
        # Assert
        assert len(ports) > 0, f"No ports found in {xml_file}"

    def test_nmap_vuln_single(self):
        pass

    def test_nmap_vuln_multiple(self):
        pass

    def test_nmap_vulscan_single(self):
        pass

    def test_nmap_vulscan_multiple(self):
        pass