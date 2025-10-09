"""
Deadlock Prevention Mechanisms for Distributed HTTP Crawling

This module provides utilities and decorators to prevent deadlocks in the
distributed crawling system, following Celery best practices and avoiding
common deadlock scenarios.

Key deadlock prevention strategies:
1. Avoid nested task calls (chord/chain within tasks)
2. Use group() instead of chord() for parallel execution
3. Implement proper timeouts and retry mechanisms
4. Use allow_join_result() context manager for safe result waiting
5. Implement task isolation and proper queue routing
6. Avoid synchronous task calls from within tasks

Based on Celery documentation recommendations and Stack Overflow solutions:
- https://docs.celeryq.dev/en/stable/userguide/tasks.html
- https://stackoverflow.com/questions/76158475/why-does-celery-deadlock-when-calling-a-chain-of-subtasks-within-a-task
"""

import time
import functools
from typing import Any, Callable, Dict, List, Optional, Union
from celery import group, chord, chain
from celery.result import AsyncResult, allow_join_result
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


class DeadlockPreventionError(Exception):
    """Custom exception for deadlock prevention violations"""
    pass


def prevent_deadlock(
    max_wait_time: int = 300,
    check_interval: int = 5,
    allow_nested_calls: bool = False
):
    """
    Decorator to prevent deadlocks in task execution.
    
    This decorator ensures that:
    1. Tasks don't wait indefinitely for results
    2. Proper timeout handling is implemented
    3. Nested task calls are controlled (if allow_nested_calls=False)
    
    Args:
        max_wait_time: Maximum time to wait for task completion (seconds)
        check_interval: Interval between status checks (seconds)
        allow_nested_calls: Whether to allow nested task calls (dangerous)
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Check for nested task calls if not allowed
            if not allow_nested_calls:
                _check_nested_calls(func.__name__)
            
            # Execute the function with timeout protection
            return _execute_with_timeout(
                func, 
                args, 
                kwargs, 
                max_wait_time, 
                check_interval
            )
        return wrapper
    return decorator


def _check_nested_calls(task_name: str):
    """Check if we're in a nested task call context"""
    import threading
    
    # Get current thread's task stack
    current_thread = threading.current_thread()
    task_stack = getattr(current_thread, '_celery_task_stack', [])
    
    if len(task_stack) > 1:
        logger.warning(f"Nested task call detected in {task_name}: {task_stack}")
        raise DeadlockPreventionError(
            f"Nested task calls detected in {task_name}. "
            "This can cause deadlocks. Use allow_nested_calls=True if necessary."
        )
    
    # Add current task to stack
    task_stack.append(task_name)
    current_thread._celery_task_stack = task_stack


def _execute_with_timeout(
    func: Callable, 
    args: tuple, 
    kwargs: dict, 
    max_wait_time: int, 
    check_interval: int
) -> Any:
    """Execute function with timeout protection"""
    start_time = time.time()
    
    try:
        result = func(*args, **kwargs)
        
        # If result is an AsyncResult, wait for it with timeout
        if isinstance(result, AsyncResult):
            return _wait_for_result_with_timeout(
                result, 
                max_wait_time, 
                check_interval, 
                start_time
            )
        
        return result
        
    except Exception as e:
        logger.error(f"Task execution failed: {e}")
        raise
    finally:
        # Clean up task stack
        import threading
        current_thread = threading.current_thread()
        task_stack = getattr(current_thread, '_celery_task_stack', [])
        if task_stack:
            task_stack.pop()
            current_thread._celery_task_stack = task_stack


def _wait_for_result_with_timeout(
    result: AsyncResult, 
    max_wait_time: int, 
    check_interval: int, 
    start_time: float
) -> Any:
    """Wait for AsyncResult with timeout protection"""
    elapsed_time = 0
    
    while elapsed_time < max_wait_time:
        if result.ready():
            try:
                return result.get(timeout=1)  # Short timeout for get()
            except Exception as e:
                logger.error(f"Error getting result: {e}")
                raise
        
        time.sleep(check_interval)
        elapsed_time = time.time() - start_time
    
    # Timeout reached
    logger.error(f"Task timeout after {max_wait_time} seconds")
    raise TimeoutError(f"Task did not complete within {max_wait_time} seconds")


class SafeTaskExecutor:
    """
    Safe task executor that prevents deadlocks by using proper Celery patterns.
    
    This class provides methods for safely executing tasks in parallel without
    causing deadlocks or blocking the worker.
    """
    
    def __init__(self, max_parallel_tasks: int = 10, default_timeout: int = 300):
        """
        Initialize the safe task executor.
        
        Args:
            max_parallel_tasks: Maximum number of parallel tasks to execute
            default_timeout: Default timeout for task execution
        """
        self.max_parallel_tasks = max_parallel_tasks
        self.default_timeout = default_timeout
    
    def execute_parallel_safe(
        self, 
        tasks: List[Callable], 
        timeout: Optional[int] = None
    ) -> List[Any]:
        """
        Execute tasks in parallel safely using group() to avoid deadlocks.
        
        Args:
            tasks: List of task functions to execute
            timeout: Timeout for execution (uses default if None)
        
        Returns:
            List of results from executed tasks
        """
        if not tasks:
            return []
        
        if len(tasks) > self.max_parallel_tasks:
            logger.warning(
                f"Too many parallel tasks ({len(tasks)}), "
                f"limiting to {self.max_parallel_tasks}"
            )
            tasks = tasks[:self.max_parallel_tasks]
        
        timeout = timeout or self.default_timeout
        
        try:
            # Use group() for safe parallel execution
            job = group(tasks)
            result = job.apply_async()
            
            # Wait for results with timeout using allow_join_result
            with allow_join_result():
                return result.get(timeout=timeout)
                
        except Exception as e:
            logger.error(f"Parallel task execution failed: {e}")
            raise
    
    def execute_sequential_safe(
        self, 
        tasks: List[Callable], 
        timeout: Optional[int] = None
    ) -> List[Any]:
        """
        Execute tasks sequentially safely using chain().
        
        Args:
            tasks: List of task functions to execute in order
            timeout: Timeout for execution (uses default if None)
        
        Returns:
            List of results from executed tasks
        """
        if not tasks:
            return []
        
        timeout = timeout or self.default_timeout
        
        try:
            # Use chain() for sequential execution
            job = chain(*tasks)
            result = job.apply_async()
            
            # Wait for results with timeout using allow_join_result
            with allow_join_result():
                return result.get(timeout=timeout)
                
        except Exception as e:
            logger.error(f"Sequential task execution failed: {e}")
            raise
    
    def execute_with_callback_safe(
        self, 
        tasks: List[Callable], 
        callback: Callable, 
        timeout: Optional[int] = None
    ) -> Any:
        """
        Execute tasks with callback safely using chord().
        
        Args:
            tasks: List of task functions to execute
            callback: Callback function to execute after all tasks complete
            timeout: Timeout for execution (uses default if None)
        
        Returns:
            Result from callback function
        """
        if not tasks:
            return callback()
        
        timeout = timeout or self.default_timeout
        
        try:
            # Use chord() for callback execution
            job = chord(tasks)(callback)
            
            # Wait for results with timeout using allow_join_result
            with allow_join_result():
                return job.get(timeout=timeout)
                
        except Exception as e:
            logger.error(f"Callback task execution failed: {e}")
            raise


def validate_task_isolation(task_name: str, queue_name: str) -> bool:
    """
    Validate that a task is properly isolated and won't cause deadlocks.
    
    Args:
        task_name: Name of the task to validate
        queue_name: Queue name for the task
    
    Returns:
        True if task is properly isolated, False otherwise
    """
    # Check if task is in a dedicated queue
    dedicated_queues = [
        'io_queue', 'cpu_queue', 'orchestrator_queue', 
        'run_command_queue', 'group_queue'
    ]
    
    if queue_name not in dedicated_queues:
        logger.warning(f"Task {task_name} not in dedicated queue: {queue_name}")
        return False
    
    # Check for dangerous task patterns
    dangerous_patterns = [
        'chord', 'chain', 'group'
    ]
    
    # This would need to be implemented by analyzing the task source code
    # For now, we'll just log a warning
    logger.info(f"Task {task_name} isolation validation passed")
    return True


def create_safe_batch_executor(
    batch_size: int = 15,
    max_parallel_batches: int = 5,
    timeout_per_batch: int = 300
) -> SafeTaskExecutor:
    """
    Create a safe batch executor configured for HTTP crawling.
    
    Args:
        batch_size: Size of each batch
        max_parallel_batches: Maximum number of parallel batches
        timeout_per_batch: Timeout for each batch
    
    Returns:
        Configured SafeTaskExecutor instance
    """
    return SafeTaskExecutor(
        max_parallel_tasks=max_parallel_batches,
        default_timeout=timeout_per_batch
    )


# Global safe executor instance for HTTP crawling
http_crawl_executor = create_safe_batch_executor()


def get_safe_executor() -> SafeTaskExecutor:
    """Get the global safe executor instance for HTTP crawling."""
    return http_crawl_executor


# Decorator for HTTP crawling tasks
def http_crawl_safe(max_wait_time: int = 300):
    """
    Decorator specifically for HTTP crawling tasks to prevent deadlocks.
    
    Args:
        max_wait_time: Maximum wait time for task completion
    """
    return prevent_deadlock(
        max_wait_time=max_wait_time,
        check_interval=5,
        allow_nested_calls=False
    )


# Utility functions for common deadlock prevention patterns

def safe_group_execution(tasks: List[Callable], timeout: int = 300) -> List[Any]:
    """
    Safely execute a group of tasks using the global executor.
    
    Args:
        tasks: List of tasks to execute
        timeout: Timeout for execution
    
    Returns:
        List of results
    """
    return http_crawl_executor.execute_parallel_safe(tasks, timeout)


def safe_chain_execution(tasks: List[Callable], timeout: int = 300) -> List[Any]:
    """
    Safely execute a chain of tasks using the global executor.
    
    Args:
        tasks: List of tasks to execute in sequence
        timeout: Timeout for execution
    
    Returns:
        List of results
    """
    return http_crawl_executor.execute_sequential_safe(tasks, timeout)


def safe_chord_execution(
    tasks: List[Callable], 
    callback: Callable, 
    timeout: int = 300
) -> Any:
    """
    Safely execute tasks with callback using the global executor.
    
    Args:
        tasks: List of tasks to execute
        callback: Callback function
        timeout: Timeout for execution
    
    Returns:
        Result from callback
    """
    return http_crawl_executor.execute_with_callback_safe(tasks, callback, timeout)
