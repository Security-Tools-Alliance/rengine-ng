import unittest
from unittest.mock import patch, MagicMock
from reNgine.utilities.path import get_scan_results_dir, get_subscan_results_dir


class TestPathUtilities(unittest.TestCase):
    """Test cases for path utility functions that fix issue #1519"""

    def test_get_scan_results_dir_basic(self):
        """Test basic scan results directory generation"""
        result = get_scan_results_dir('/test/base', 42, 123)
        expected_path = '/test/base/domain_42_scan_123'
        
        # The result should contain our expected pattern
        self.assertIn('domain_42_scan_123', result)
        self.assertTrue(result.startswith('/test/base'))
        
    def test_get_scan_results_dir_length_limit(self):
        """Test that scan results directory path stays under database limit"""
        # Test with very long base directory and large IDs
        long_base_dir = '/very/long/base/directory/path/for/testing/purposes'
        large_domain_id = 999999999
        large_scan_id = 999999999
        
        result = get_scan_results_dir(long_base_dir, large_domain_id, large_scan_id)
        
        # Should be well under the 500 character database limit
        self.assertLess(len(result), 500)
        self.assertLess(len(result), 100)  # Should even be under old limit in most cases
        
    def test_get_scan_results_dir_predictable_length(self):
        """Test that scan results directory has predictable, short length"""
        test_cases = [
            ('/usr/src/app/scan_results', 1, 1),
            ('/usr/src/app/scan_results', 999999, 999999),
            ('/very/long/base/path/here', 42, 123),
        ]
        
        for base_dir, domain_id, scan_id in test_cases:
            result = get_scan_results_dir(base_dir, domain_id, scan_id)
            # Should always be under 200 characters (very conservative)
            self.assertLess(len(result), 200, 
                f"Path too long: {result} ({len(result)} chars)")
            
    def test_get_subscan_results_dir_basic(self):
        """Test basic subscan results directory generation"""
        with patch('uuid.uuid1') as mock_uuid:
            mock_uuid.return_value = MagicMock()
            mock_uuid.return_value.__str__ = lambda: 'test-uuid-123'
            
            result = get_subscan_results_dir('/test/base', 42, 456)
            
            # Should contain domain ID and subscans
            self.assertIn('domain_42_subscans', result)
            self.assertTrue(result.startswith('/test/base'))
            
    def test_get_subscan_results_dir_length_limit(self):
        """Test that subscan results directory path stays under database limit"""
        # Test with various inputs
        test_cases = [
            ('/usr/src/app/scan_results', 1, 1),
            ('/usr/src/app/scan_results', 999999, 999999),
            ('/very/long/base/directory/path', 42, 123),
        ]
        
        for base_dir, domain_id, subscan_id in test_cases:
            result = get_subscan_results_dir(base_dir, domain_id, subscan_id)
            # Should be well under the 500 character database limit
            self.assertLess(len(result), 500,
                f"Subscan path too long: {result} ({len(result)} chars)")
                
    def test_domain_id_vs_domain_name_comparison(self):
        """Test that domain ID approach is shorter than domain name approach"""
        # Simulate the old problematic approach
        def old_approach_simulation(base_dir, domain_name, scan_id):
            return f'{base_dir}/{domain_name}_{scan_id}'
        
        # Test with a long domain name that would cause the original issue
        base_dir = '/usr/src/app/scan_results'
        long_domain_name = 'really-really-long-subdomain-name-that-exceeds-100-characters.example.com'
        scan_id = 123
        domain_id = 42
        
        old_path = old_approach_simulation(base_dir, long_domain_name, scan_id)
        new_path = get_scan_results_dir(base_dir, domain_id, scan_id)
        
        # Old approach should exceed 100 characters
        self.assertGreater(len(old_path), 100)
        
        # New approach should be much shorter
        self.assertLess(len(new_path), 100)
        self.assertLess(len(new_path), len(old_path))
        
    def test_path_generation_consistency(self):
        """Test that path generation is consistent for same inputs"""
        base_dir = '/test/base'
        domain_id = 42
        scan_id = 123
        
        # Should generate the same path every time for scan results
        path1 = get_scan_results_dir(base_dir, domain_id, scan_id)
        path2 = get_scan_results_dir(base_dir, domain_id, scan_id)
        
        self.assertEqual(path1, path2)
        
    def test_path_uniqueness_different_inputs(self):
        """Test that different inputs generate different paths"""
        base_dir = '/test/base'
        
        path1 = get_scan_results_dir(base_dir, 42, 123)
        path2 = get_scan_results_dir(base_dir, 43, 123)  # Different domain ID
        path3 = get_scan_results_dir(base_dir, 42, 124)  # Different scan ID
        
        # All paths should be different
        self.assertNotEqual(path1, path2)
        self.assertNotEqual(path1, path3)
        self.assertNotEqual(path2, path3)


if __name__ == '__main__':
    unittest.main()
