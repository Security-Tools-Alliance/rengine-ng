"""
Comprehensive unit tests for the save_fuzzing_file functionality.
"""

import os

# Set essential environment variables for testing
os.environ.setdefault('RENGINE_HOME', '/Users/felixschledorn/GitHub/rengine-ng/web')
os.environ.setdefault('RENGINE_SECRET_KEY', 'test-secret-key-for-testing')
os.environ.setdefault('POSTGRES_DB', 'test_rengine')
os.environ.setdefault('POSTGRES_USER', 'test_user')
os.environ.setdefault('POSTGRES_PASSWORD', 'test_password')
os.environ.setdefault('POSTGRES_HOST', 'localhost')
os.environ.setdefault('POSTGRES_PORT', '5432')
os.environ.setdefault('CELERY_ALWAYS_EAGER', 'True')
os.environ.setdefault('DOMAIN_NAME', 'test.example.com')

import unittest
import threading
import time
from unittest.mock import patch, MagicMock
from concurrent.futures import ThreadPoolExecutor
from django.test import TestCase
from django.db import DatabaseError
from startScan.models import DirectoryFile
from reNgine.utilities.database import save_fuzzing_file


class TestSaveFuzzingFile(TestCase):
    """Test suite for save_fuzzing_file functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.test_data = {
            'name': 'admin',
            'url': 'https://example.com/admin',
            'http_status': 200,
            'length': 1024,
            'words': 50,
            'lines': 20,
            'content_type': 'text/html'
        }
        
    def tearDown(self):
        """Clean up test data."""
        DirectoryFile.objects.all().delete()
    
    def test_create_new_file_success(self):
        """Test successful creation of a new DirectoryFile."""
        dfile, created = save_fuzzing_file(**self.test_data)
        
        self.assertTrue(created)
        self.assertIsInstance(dfile, DirectoryFile)
        self.assertEqual(dfile.name, self.test_data['name'])
        self.assertEqual(dfile.url, self.test_data['url'])
        self.assertEqual(dfile.http_status, self.test_data['http_status'])
        self.assertEqual(dfile.length, self.test_data['length'])
        self.assertEqual(dfile.words, self.test_data['words'])
        self.assertEqual(dfile.lines, self.test_data['lines'])
        self.assertEqual(dfile.content_type, self.test_data['content_type'])
    
    def test_find_existing_file(self):
        """Test finding an existing DirectoryFile."""
        # Create initial file
        initial_file = DirectoryFile.objects.create(**self.test_data)
        
        # Try to save the same file again
        dfile, created = save_fuzzing_file(**self.test_data)
        
        self.assertFalse(created)
        self.assertEqual(dfile.id, initial_file.id)
        self.assertEqual(DirectoryFile.objects.count(), 1)
    
    def test_different_files_created_separately(self):
        """Test that different files are created as separate records."""
        # Create first file
        dfile1, created1 = save_fuzzing_file(**self.test_data)
        
        # Create second file with different URL
        test_data2 = self.test_data.copy()
        test_data2['url'] = 'https://example.com/login'
        dfile2, created2 = save_fuzzing_file(**test_data2)
        
        self.assertTrue(created1)
        self.assertTrue(created2)
        self.assertNotEqual(dfile1.id, dfile2.id)
        self.assertEqual(DirectoryFile.objects.count(), 2)
    
    def test_same_name_different_status(self):
        """Test files with same name but different HTTP status are separate."""
        # Create first file with 200 status
        dfile1, created1 = save_fuzzing_file(**self.test_data)
        
        # Create second file with 404 status
        test_data2 = self.test_data.copy()
        test_data2['http_status'] = 404
        dfile2, created2 = save_fuzzing_file(**test_data2)
        
        self.assertTrue(created1)
        self.assertTrue(created2)
        self.assertNotEqual(dfile1.id, dfile2.id)
        self.assertEqual(DirectoryFile.objects.count(), 2)
    
    def test_optional_parameters_default_values(self):
        """Test that optional parameters use default values correctly."""
        minimal_data = {
            'name': 'test',
            'url': 'https://example.com/test',
            'http_status': 200
        }
        
        dfile, created = save_fuzzing_file(**minimal_data)
        
        self.assertTrue(created)
        self.assertEqual(dfile.length, 0)
        self.assertEqual(dfile.words, 0)
        self.assertEqual(dfile.lines, 0)
        self.assertIsNone(dfile.content_type)
    
    @patch('reNgine.utilities.database.DirectoryFile.objects.create')
    def test_creation_error_with_existing_fallback(self, mock_create):
        """Test error during creation with successful fallback to existing record."""
        # Create an existing record first
        existing_file = DirectoryFile.objects.create(**self.test_data)
        
        # Mock create() to raise an exception
        mock_create.side_effect = DatabaseError("Simulated database error")
        
        # Should find the existing record despite creation error
        dfile, created = save_fuzzing_file(**self.test_data)
        
        self.assertFalse(created)
        self.assertEqual(dfile.id, existing_file.id)
        mock_create.assert_called_once()
    
    @patch('reNgine.utilities.database.DirectoryFile.objects.create')
    @patch('reNgine.utilities.database.DirectoryFile.objects.filter')
    def test_creation_error_without_existing_fallback(self, mock_filter, mock_create):
        """Test error during creation without existing record fallback."""
        # Mock create() to raise an exception
        mock_create.side_effect = DatabaseError("Simulated database error")
        
        # Mock filter to return empty queryset (no existing record)
        mock_queryset = MagicMock()
        mock_queryset.first.return_value = None
        mock_filter.return_value = mock_queryset
        
        # Should re-raise the original error
        with self.assertRaises(DatabaseError):
            save_fuzzing_file(**self.test_data)
        
        mock_create.assert_called_once()
        self.assertEqual(mock_filter.call_count, 2)  # Called twice: initial check + fallback
    
    def test_concurrent_creation_same_file(self):
        """Test concurrent creation of the same file by multiple threads."""
        results = []
        num_threads = 5
        
        def create_file(thread_id):
            """Thread function to create the same file."""
            try:
                dfile, created = save_fuzzing_file(**self.test_data)
                results.append({
                    'thread_id': thread_id,
                    'dfile_id': dfile.id,
                    'created': created,
                    'success': True
                })
            except Exception as e:
                results.append({
                    'thread_id': thread_id,
                    'error': str(e),
                    'success': False
                })
        
        # Run multiple threads trying to create the same file
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(create_file, i) for i in range(num_threads)]
            for future in futures:
                future.result()  # Wait for completion
        
        # Verify results
        successful_results = [r for r in results if r['success']]
        self.assertEqual(len(successful_results), num_threads)
        
        # All threads should get the same file ID
        file_ids = set(r['dfile_id'] for r in successful_results)
        self.assertEqual(len(file_ids), 1)  # Only one unique file created
        
        # Only one thread should have created=True, others should have created=False
        created_count = sum(1 for r in successful_results if r['created'])
        found_count = sum(1 for r in successful_results if not r['created'])
        
        # At least one should have created it, others should have found it
        self.assertGreaterEqual(created_count, 1)
        self.assertGreaterEqual(found_count, 1)
        self.assertEqual(created_count + found_count, num_threads)
        
        # Verify only one record exists in database
        self.assertEqual(DirectoryFile.objects.count(), 1)
    
    def test_concurrent_creation_different_files(self):
        """Test concurrent creation of different files by multiple threads."""
        results = []
        num_threads = 5
        
        def create_file(thread_id):
            """Thread function to create different files."""
            test_data = self.test_data.copy()
            test_data['url'] = f'https://example.com/path_{thread_id}'
            
            try:
                dfile, created = save_fuzzing_file(**test_data)
                results.append({
                    'thread_id': thread_id,
                    'dfile_id': dfile.id,
                    'created': created,
                    'success': True
                })
            except Exception as e:
                results.append({
                    'thread_id': thread_id,
                    'error': str(e),
                    'success': False
                })
        
        # Run multiple threads creating different files
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(create_file, i) for i in range(num_threads)]
            for future in futures:
                future.result()  # Wait for completion
        
        # Verify results
        successful_results = [r for r in results if r['success']]
        self.assertEqual(len(successful_results), num_threads)
        
        # All files should be different
        file_ids = set(r['dfile_id'] for r in successful_results)
        self.assertEqual(len(file_ids), num_threads)  # All unique files
        
        # All should be created (not found existing)
        created_count = sum(1 for r in successful_results if r['created'])
        self.assertEqual(created_count, num_threads)
        
        # Verify all records exist in database
        self.assertEqual(DirectoryFile.objects.count(), num_threads)
    
    def test_performance_characteristics(self):
        """Test performance characteristics of save_fuzzing_file."""
        # Create a file that will be found (not created)
        DirectoryFile.objects.create(**self.test_data)
        
        # Measure time for finding existing file
        start_time = time.time()
        for _ in range(100):
            save_fuzzing_file(**self.test_data)
        find_time = time.time() - start_time
        
        # Measure time for creating new files
        start_time = time.time()
        for i in range(100):
            test_data = self.test_data.copy()
            test_data['url'] = f'https://example.com/perf_test_{i}'
            save_fuzzing_file(**test_data)
        create_time = time.time() - start_time
        
        # Finding existing should be faster than creating new
        # This is a basic performance check
        self.assertLess(find_time, create_time * 2)  # Allow some margin
        
        # Verify correct number of records
        self.assertEqual(DirectoryFile.objects.count(), 101)  # 1 initial + 100 new
    
    def test_filter_query_efficiency(self):
        """Test that the filter query uses the correct fields for efficiency."""
        with patch('startScan.models.DirectoryFile.objects.filter') as mock_filter:
            mock_queryset = MagicMock()
            mock_queryset.first.return_value = None
            mock_filter.return_value = mock_queryset
            
            # Mock create to avoid actual database interaction
            with patch('startScan.models.DirectoryFile.objects.create') as mock_create:
                mock_file = MagicMock()
                mock_create.return_value = mock_file
                
                save_fuzzing_file(**self.test_data)
                
                # Verify filter was called with correct parameters
                mock_filter.assert_called_with(
                    name=self.test_data['name'],
                    url=self.test_data['url'],
                    http_status=self.test_data['http_status']
                )


class TestSaveFuzzingFileIntegration(TestCase):
    """Integration tests for save_fuzzing_file with real database."""
    
    def setUp(self):
        """Set up test data."""
        self.base_data = {
            'name': 'admin',
            'url': 'https://test.com/admin',
            'http_status': 200,
            'length': 1024,
            'words': 50,
            'lines': 20,
            'content_type': 'text/html'
        }
    
    def tearDown(self):
        """Clean up test data."""
        DirectoryFile.objects.all().delete()
    
    def test_large_scale_concurrent_operations(self):
        """Test with a larger number of concurrent operations."""
        num_threads = 20
        operations_per_thread = 10
        results = []
        
        def worker(thread_id):
            """Worker function for stress testing."""
            thread_results = []
            for i in range(operations_per_thread):
                test_data = self.base_data.copy()
                # Mix of same and different files
                if i % 3 == 0:
                    # Same file (should find existing)
                    test_data['url'] = 'https://test.com/common'
                else:
                    # Unique file (should create new)
                    test_data['url'] = f'https://test.com/unique_{thread_id}_{i}'
                
                try:
                    dfile, created = save_fuzzing_file(**test_data)
                    thread_results.append({
                        'success': True,
                        'created': created,
                        'file_id': dfile.id,
                        'url': test_data['url']
                    })
                except Exception as e:
                    thread_results.append({
                        'success': False,
                        'error': str(e),
                        'url': test_data['url']
                    })
            
            results.extend(thread_results)
        
        # Run stress test
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(worker, i) for i in range(num_threads)]
            for future in futures:
                future.result()
        
        # Analyze results
        successful = [r for r in results if r['success']]
        failed = [r for r in results if not r['success']]
        
        # All operations should succeed
        self.assertEqual(len(failed), 0, f"Failed operations: {failed}")
        self.assertEqual(len(successful), num_threads * operations_per_thread)
        
        # Check database consistency
        total_files = DirectoryFile.objects.count()
        unique_urls = len(set(r['url'] for r in successful))
        
        # Should have one file per unique URL
        self.assertEqual(total_files, unique_urls)
        
        print(f"Stress test completed: {len(successful)} operations, "
              f"{total_files} unique files created")


if __name__ == '__main__':
    unittest.main()
