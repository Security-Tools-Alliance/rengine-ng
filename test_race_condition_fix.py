#!/usr/bin/env python3
"""
Standalone test script to verify race condition fixes.
This tests our Redis-based locking mechanisms and TaskContext isolation.
"""

import os
import sys
import time
import threading
import concurrent.futures
from unittest.mock import Mock, patch, MagicMock

# Add the web directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'web'))

# Mock Django settings before importing
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'reNgine.settings')

def test_imports():
    """Test that our modified code can be imported without errors."""
    print("🔍 Testing imports...")
    
    try:
        # Test basic imports
        from reNgine.utilities.database import save_fuzzing_file, save_subdomain, get_redis_connection
        from reNgine.celery_custom_task import TaskContext, RengineTask
        
        print("✅ All critical imports successful!")
        print(f"✅ TaskContext class: {TaskContext}")
        print(f"✅ RengineTask class: {RengineTask}")
        print(f"✅ save_fuzzing_file function: {save_fuzzing_file}")
        print(f"✅ save_subdomain function: {save_subdomain}")
        print(f"✅ get_redis_connection function: {get_redis_connection}")
        
        return True
    except Exception as e:
        print(f"❌ Import error: {e}")
        return False

def test_task_context_isolation():
    """Test that TaskContext provides proper isolation between threads."""
    print("\n🔍 Testing TaskContext isolation...")
    
    try:
        from reNgine.celery_custom_task import TaskContext
        
        # Create contexts in different threads
        results = {}
        
        def create_context(thread_id, scan_id):
            ctx_data = {'scan_history_id': scan_id, 'domain_id': thread_id}
            context = TaskContext(ctx=ctx_data, task_name=f'test_task_{thread_id}')
            
            # Store thread-specific data
            results[thread_id] = {
                'scan_id': context.scan_id,
                'task_name': context.task_name,
                'context_id': id(context)
            }
        
        # Create contexts in parallel threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=create_context, args=(i, i * 100))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Verify each context is isolated
        context_ids = set()
        for thread_id, data in results.items():
            assert data['scan_id'] == thread_id * 100, f"Wrong scan_id for thread {thread_id}"
            assert data['task_name'] == f'test_task_{thread_id}', f"Wrong task_name for thread {thread_id}"
            context_ids.add(data['context_id'])
        
        # Ensure all contexts are different objects
        assert len(context_ids) == 5, "Contexts should be separate objects"
        
        print("✅ TaskContext isolation working correctly!")
        return True
        
    except Exception as e:
        print(f"❌ TaskContext isolation test failed: {e}")
        return False

def test_redis_connection_mock():
    """Test Redis connection handling with mocks."""
    print("\n🔍 Testing Redis connection handling...")
    
    try:
        from reNgine.utilities.database import get_redis_connection
        
        # Mock Redis to test fallback behavior
        with patch('reNgine.utilities.database.redis') as mock_redis:
            # Test successful connection
            mock_pool = Mock()
            mock_redis.ConnectionPool.return_value = mock_pool
            mock_redis.Redis.return_value = Mock()
            
            connection = get_redis_connection()
            assert connection is not None, "Should return Redis connection"
            
            # Test connection failure
            mock_redis.Redis.side_effect = Exception("Connection failed")
            connection = get_redis_connection()
            assert connection is None, "Should return None on connection failure"
            
        print("✅ Redis connection handling working correctly!")
        return True
        
    except Exception as e:
        print(f"❌ Redis connection test failed: {e}")
        return False

def test_save_fuzzing_file_mock():
    """Test save_fuzzing_file function with mocked dependencies."""
    print("\n🔍 Testing save_fuzzing_file with mocks...")
    
    try:
        from reNgine.utilities.database import save_fuzzing_file
        
        # Mock all Django dependencies
        with patch('reNgine.utilities.database.DirectoryFile') as mock_model, \
             patch('reNgine.utilities.database.get_redis_connection') as mock_redis:
            
            # Test successful Redis lock path
            mock_redis_conn = Mock()
            mock_redis.return_value = mock_redis_conn
            
            # Mock successful lock acquisition
            mock_lock = Mock()
            mock_lock.__enter__ = Mock(return_value=mock_lock)
            mock_lock.__exit__ = Mock(return_value=None)
            mock_redis_conn.lock.return_value = mock_lock
            
            # Mock Django model
            mock_file = Mock()
            mock_model.objects.get_or_create.return_value = (mock_file, True)
            
            # Test the function
            result = save_fuzzing_file(
                name="test.txt",
                url="http://example.com/test.txt",
                http_status=200,
                length=1000
            )
            
            assert result == (mock_file, True), "Should return mocked result"
            
            # Verify Redis lock was used
            mock_redis_conn.lock.assert_called_once()
            mock_model.objects.get_or_create.assert_called_once()
            
            print("✅ save_fuzzing_file Redis locking working correctly!")
            
            # Test fallback when Redis is unavailable
            mock_redis.return_value = None
            result = save_fuzzing_file(
                name="test2.txt", 
                url="http://example.com/test2.txt",
                http_status=200
            )
            
            # Should still work via fallback
            assert result == (mock_file, True), "Should work with fallback"
            
            print("✅ save_fuzzing_file fallback working correctly!")
            return True
            
    except Exception as e:
        print(f"❌ save_fuzzing_file test failed: {e}")
        return False

def test_concurrent_save_fuzzing_file():
    """Test save_fuzzing_file under simulated concurrent load."""
    print("\n🔍 Testing save_fuzzing_file under concurrent load...")
    
    try:
        from reNgine.utilities.database import save_fuzzing_file
        
        results = []
        errors = []
        
        def concurrent_save(file_id):
            try:
                with patch('reNgine.utilities.database.DirectoryFile') as mock_model, \
                     patch('reNgine.utilities.database.get_redis_connection') as mock_redis:
                    
                    # Simulate Redis available
                    mock_redis_conn = Mock()
                    mock_redis.return_value = mock_redis_conn
                    
                    # Mock lock behavior
                    mock_lock = Mock()
                    mock_lock.__enter__ = Mock(return_value=mock_lock)
                    mock_lock.__exit__ = Mock(return_value=None)
                    mock_redis_conn.lock.return_value = mock_lock
                    
                    # Mock Django model
                    mock_file = Mock()
                    mock_model.objects.get_or_create.return_value = (mock_file, True)
                    
                    # Add small delay to increase chance of race conditions
                    time.sleep(0.01)
                    
                    result = save_fuzzing_file(
                        name=f"concurrent_test_{file_id}.txt",
                        url=f"http://example.com/test_{file_id}.txt", 
                        http_status=200
                    )
                    
                    results.append((file_id, result))
                    
            except Exception as e:
                errors.append((file_id, str(e)))
        
        # Run 20 concurrent saves
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(concurrent_save, i) for i in range(20)]
            concurrent.futures.wait(futures)
        
        assert len(errors) == 0, f"No errors should occur: {errors}"
        assert len(results) == 20, f"All saves should complete: got {len(results)}"
        
        print(f"✅ Concurrent save_fuzzing_file completed {len(results)} operations with {len(errors)} errors!")
        return True
        
    except Exception as e:
        print(f"❌ Concurrent save_fuzzing_file test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("🚀 Starting race condition fix verification tests...\n")
    
    tests = [
        test_imports,
        test_task_context_isolation,
        test_redis_connection_mock,
        test_save_fuzzing_file_mock,
        test_concurrent_save_fuzzing_file,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} crashed: {e}")
            failed += 1
    
    print(f"\n📊 Test Results:")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"📈 Success Rate: {(passed/(passed+failed)*100):.1f}%")
    
    if failed == 0:
        print("\n🎉 All tests passed! Race condition fixes are working correctly.")
        return True
    else:
        print("\n⚠️  Some tests failed. Please review the output above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
