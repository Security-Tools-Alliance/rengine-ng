"""
Distributed locking utilities for preventing race conditions in concurrent tasks.

This module provides a reusable DistributedLock class that can be used to prevent
race conditions when multiple Celery workers try to create the same database records
simultaneously.

Usage:
    from reNgine.utilities.distributed_lock import DistributedLock
    
    # Simple usage with context manager
    with DistributedLock("unique_operation_key") as lock:
        if lock.acquired:
            # Perform database operation that needs protection
            obj, created = Model.objects.get_or_create(...)
        else:
            # Handle case where lock wasn't acquired
            pass
    
    # Advanced usage with custom timeout and fallback
    lock = DistributedLock("operation_key", timeout=30, blocking_timeout=5)
    result = lock.execute_with_lock(
        protected_operation=lambda: Model.objects.get_or_create(...),
        fallback_operation=lambda: Model.objects.filter(...).first()
    )
"""

import hashlib
import time
from typing import Optional, Callable, Any
from celery.utils.log import get_task_logger
from django.conf import settings

logger = get_task_logger(__name__)

# Global Redis connection pool for efficient connection reuse
_redis_pool = None

def get_redis_connection():
    """Get a Redis connection from a connection pool for efficient reuse."""
    global _redis_pool
    
    if _redis_pool is None:
        try:
            import redis
            _redis_pool = redis.ConnectionPool(
                host=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                db=settings.REDIS_DB,
                password=settings.REDIS_PASSWORD,
                socket_timeout=5,
                socket_connect_timeout=5,
                retry_on_timeout=True,
                socket_keepalive=True,
                socket_keepalive_options={},
                max_connections=50,  # Pool size for concurrent operations
                health_check_interval=30  # Check connection health every 30 seconds
            )
            logger.debug("Created Redis connection pool for distributed locking")
        except Exception as e:
            logger.warning(f"Failed to create Redis connection pool: {e}")
            return None
    
    try:
        import redis
        return redis.Redis(connection_pool=_redis_pool)
    except Exception as e:
        logger.warning(f"Failed to get Redis connection from pool: {e}")
        return None


class DistributedLock:
    """
    A distributed lock implementation using Redis for preventing race conditions
    in concurrent Celery tasks.
    
    This class provides thread-safe, process-safe locking for database operations
    that might be executed concurrently by multiple workers.
    """
    
    def __init__(self, lock_key: str, timeout: int = 30, blocking_timeout: int = 5):
        """
        Initialize a distributed lock.
        
        Args:
            lock_key: Unique identifier for the lock (will be hashed for safety)
            timeout: How long the lock should be held (seconds)
            blocking_timeout: How long to wait trying to acquire the lock (seconds)
        """
        # Create a safe lock key by hashing the input
        self.lock_key = f"distributed_lock:{hashlib.md5(lock_key.encode()).hexdigest()}"
        self.timeout = timeout
        self.blocking_timeout = blocking_timeout
        self.acquired = False
        self._redis_client = None
        
    def __enter__(self):
        """Context manager entry - acquire the lock."""
        self.acquire()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - release the lock."""
        self.release()
        
    def acquire(self) -> bool:
        """
        Attempt to acquire the distributed lock.
        
        Returns:
            True if lock was acquired, False otherwise
        """
        self._redis_client = get_redis_connection()
        
        if not self._redis_client:
            logger.debug(f"Redis not available for lock {self.lock_key}, falling back to no locking")
            self.acquired = False
            return False
            
        try:
            # Try to acquire lock with timeout
            lock_acquired = self._redis_client.set(
                self.lock_key, 
                "locked", 
                nx=True,  # Only set if not exists
                ex=self.timeout  # Expire after timeout seconds
            )
            
            if lock_acquired:
                self.acquired = True
                logger.debug(f"Acquired distributed lock: {self.lock_key}")
                return True
            else:
                # Could not acquire lock immediately, try waiting
                for attempt in range(int(self.blocking_timeout * 10)):  # Check every 100ms
                    time.sleep(0.1)
                    lock_acquired = self._redis_client.set(
                        self.lock_key, 
                        "locked", 
                        nx=True, 
                        ex=self.timeout
                    )
                    if lock_acquired:
                        self.acquired = True
                        logger.debug(f"Acquired distributed lock after waiting: {self.lock_key}")
                        return True
                        
                logger.debug(f"Could not acquire distributed lock: {self.lock_key}")
                self.acquired = False
                return False
                
        except Exception as e:
            logger.warning(f"Redis locking failed for {self.lock_key}: {e}")
            self.acquired = False
            return False
            
    def release(self):
        """Release the distributed lock if we hold it."""
        if self.acquired and self._redis_client:
            try:
                self._redis_client.delete(self.lock_key)
                logger.debug(f"Released distributed lock: {self.lock_key}")
            except Exception as e:
                logger.warning(f"Failed to release lock {self.lock_key}: {e}")
            finally:
                self.acquired = False
                
    def execute_with_lock(
        self, 
        protected_operation: Callable[[], Any],
        fallback_operation: Optional[Callable[[], Any]] = None,
        retry_attempts: int = 3,
        retry_delay: float = 0.1
    ) -> Any:
        """
        Execute a protected operation with distributed locking and fallback handling.
        
        This method encapsulates the common pattern of:
        1. Try to acquire lock
        2. If successful, execute the protected operation
        3. If not successful, fall back to alternative operation
        4. Handle retries for race conditions
        
        Args:
            protected_operation: Function to execute when lock is acquired
            fallback_operation: Function to execute when lock cannot be acquired
            retry_attempts: Number of times to retry the operation
            retry_delay: Delay between retry attempts (seconds)
            
        Returns:
            Result of the executed operation
        """
        with self:
            if self.acquired:
                # We have the lock, execute the protected operation
                try:
                    return protected_operation()
                except Exception as e:
                    logger.error(f"Protected operation failed under lock {self.lock_key}: {e}")
                    raise
            else:
                # Could not acquire lock
                if fallback_operation:
                    # Try fallback operation with retries
                    for attempt in range(retry_attempts):
                        try:
                            result = fallback_operation()
                            if result:  # If fallback found existing record
                                return result
                        except Exception as e:
                            if attempt < retry_attempts - 1:
                                time.sleep(retry_delay * (attempt + 1))
                                continue
                            else:
                                logger.error(f"Fallback operation failed for {self.lock_key}: {e}")
                                raise
                                
                # If we get here, neither protected nor fallback operation succeeded
                logger.warning(f"All operations failed for lock {self.lock_key}")
                return None
    
    @staticmethod
    def safe_get_or_create_with_lock(
        model_class,
        lock_key: str,
        get_kwargs: dict,
        create_kwargs: dict,
        timeout: int = 30,
        blocking_timeout: int = 5,
        update_existing_callback: Callable = None
    ):
        """
        Safely get or create a model instance using distributed locking.
        
        Args:
            model_class: Django model class
            lock_key: Unique lock identifier
            get_kwargs: Keyword arguments for get operation
            create_kwargs: Keyword arguments for create operation
            timeout: Lock timeout in seconds
            blocking_timeout: Time to wait for lock acquisition
            update_existing_callback: Optional callback to update existing instances
            
        Returns:
            Model instance (with _was_created attribute if created)
        """
        from django.db import IntegrityError
        
        def locked_operation():
            try:
                # Try to get existing object first
                obj = model_class.objects.filter(**get_kwargs).first()
                if obj:
                    if update_existing_callback:
                        obj = update_existing_callback(obj)
                    obj._was_created = False
                    return obj
                
                # Create new object
                obj = model_class.objects.create(**create_kwargs)
                obj._was_created = True
                logger.debug(f"Created new {model_class.__name__} with distributed lock")
                return obj
                
            except IntegrityError:
                # Handle race condition - another process created the object
                obj = model_class.objects.filter(**get_kwargs).first()
                if obj:
                    if update_existing_callback:
                        obj = update_existing_callback(obj)
                    obj._was_created = False
                    logger.debug(f"Found existing {model_class.__name__} after integrity error")
                    return obj
                else:
                    logger.error(f"IntegrityError but no existing {model_class.__name__} found")
                    return None
        
        def fallback_operation():
            try:
                obj, created = model_class.objects.get_or_create(
                    defaults={k: v for k, v in create_kwargs.items() if k not in get_kwargs},
                    **get_kwargs
                )
                if not created and update_existing_callback:
                    obj = update_existing_callback(obj)
                obj._was_created = created
                logger.debug(f"Fallback get_or_create for {model_class.__name__}: created={created}")
                return obj
            except IntegrityError:
                # Final fallback - just try to get the object
                obj = model_class.objects.filter(**get_kwargs).first()
                if obj:
                    if update_existing_callback:
                        obj = update_existing_callback(obj)
                    obj._was_created = False
                    return obj
                logger.error(f"All fallback attempts failed for {model_class.__name__}")
                return None
        
        # Use distributed lock
        lock = DistributedLock(lock_key, timeout, blocking_timeout)
        return lock.execute_with_lock(
            protected_operation=locked_operation,
            fallback_operation=fallback_operation
        )


def with_distributed_lock(lock_key_generator: Callable, timeout: int = 30, blocking_timeout: int = 5):
    """
    Decorator for automatically applying distributed locking to functions.
    
    Args:
        lock_key_generator: Function that takes the decorated function's arguments
                          and returns a unique lock key string
        timeout: Lock timeout in seconds
        blocking_timeout: How long to wait for lock acquisition
        
    Example:
        @with_distributed_lock(lambda name, url, status: f"file:{name}:{url}:{status}")
        def save_file_safely(name, url, status):
            return File.objects.get_or_create(name=name, url=url, status=status)
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Generate lock key from function arguments
            lock_key = lock_key_generator(*args, **kwargs)
            
            # Execute function with distributed lock
            lock = DistributedLock(lock_key, timeout, blocking_timeout)
            with lock:
                if lock.acquired:
                    return func(*args, **kwargs)
                else:
                    # Could not acquire lock - you might want to implement
                    # specific fallback logic here depending on the use case
                    logger.warning(f"Could not acquire lock for {func.__name__}: {lock_key}")
                    return func(*args, **kwargs)  # Execute anyway as fallback
                    
        return wrapper
    return decorator
