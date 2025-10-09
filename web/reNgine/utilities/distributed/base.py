"""
Base classes and utilities for distributed task processing.

This module provides the foundation for creating distributed utilities that can
be reused across different task types while following SOLID, KISS, and DRY principles.

Key components:
1. DistributedTaskBase - Base class for distributed task utilities
2. DistributedProcessor - Generic processor for batch operations
3. DistributedConfig - Configuration management for distributed operations
4. DistributedResult - Result handling and aggregation
5. DistributedErrorHandler - Error handling and retry mechanisms
"""

import time
import threading
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union, Callable, TypeVar, Generic
from dataclasses import dataclass, field
from enum import Enum
from contextlib import contextmanager

from celery.utils.log import get_task_logger
from celery.result import AsyncResult

from reNgine.utilities.deadlock_prevention import (
    safe_group_execution,
    safe_chain_execution,
    safe_chord_execution,
    DeadlockPreventionError
)

logger = get_task_logger(__name__)

T = TypeVar('T')
R = TypeVar('R')


class ProcessingStatus(Enum):
    """Status of distributed processing operations"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"
    CANCELLED = "cancelled"


@dataclass
class DistributedResult(Generic[T]):
    """Generic result container for distributed operations"""
    data: T
    status: ProcessingStatus
    batch_id: Optional[str] = None
    worker_id: Optional[str] = None
    processing_time: float = 0.0
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_successful(self) -> bool:
        """Check if the result is successful"""
        return self.status == ProcessingStatus.COMPLETED and not self.errors
    
    @property
    def is_failed(self) -> bool:
        """Check if the result failed"""
        return self.status == ProcessingStatus.FAILED or bool(self.errors)


@dataclass
class DistributedConfig:
    """Configuration for distributed operations"""
    batch_size: int = 15
    max_batch_size: int = 25
    min_batch_size: int = 5
    worker_timeout: int = 300
    max_retries: int = 3
    retry_delay: int = 30
    parallel_workers: int = 5
    enable_retry: bool = True
    enable_metrics: bool = True
    
    def validate(self) -> bool:
        """Validate configuration parameters"""
        if self.batch_size < self.min_batch_size:
            self.batch_size = self.min_batch_size
        if self.batch_size > self.max_batch_size:
            self.batch_size = self.max_batch_size
        if self.worker_timeout <= 0:
            self.worker_timeout = 300
        if self.max_retries < 0:
            self.max_retries = 0
        return True


class DistributedErrorHandler:
    """Error handling and retry mechanisms for distributed operations"""
    
    def __init__(self, config: DistributedConfig):
        self.config = config
        self.retry_counts: Dict[str, int] = {}
        self.error_history: Dict[str, List[str]] = {}
    
    def should_retry(self, batch_id: str, error: Exception) -> bool:
        """Determine if a batch should be retried"""
        if not self.config.enable_retry:
            return False
        
        retry_count = self.retry_counts.get(batch_id, 0)
        if retry_count >= self.config.max_retries:
            return False
        
        # Check if error is retryable
        retryable_errors = (
            ConnectionError,
            TimeoutError,
            OSError,
            DeadlockPreventionError
        )
        
        return isinstance(error, retryable_errors)
    
    def record_error(self, batch_id: str, error: Exception) -> None:
        """Record an error for a batch"""
        error_msg = f"{type(error).__name__}: {str(error)}"
        
        if batch_id not in self.error_history:
            self.error_history[batch_id] = []
        
        self.error_history[batch_id].append(error_msg)
        self.retry_counts[batch_id] = self.retry_counts.get(batch_id, 0) + 1
        
        logger.error(f"Error recorded for batch {batch_id}: {error_msg}")
    
    def get_retry_delay(self, batch_id: str) -> int:
        """Get retry delay for a batch (exponential backoff)"""
        retry_count = self.retry_counts.get(batch_id, 0)
        return self.config.retry_delay * (2 ** retry_count)
    
    def get_error_summary(self, batch_id: str) -> List[str]:
        """Get error summary for a batch"""
        return self.error_history.get(batch_id, [])


class DistributedProcessor(ABC, Generic[T, R]):
    """Abstract base class for distributed processors"""
    
    def __init__(self, config: Optional[DistributedConfig] = None):
        self.config = config or DistributedConfig()
        self.config.validate()
        self.error_handler = DistributedErrorHandler(self.config)
        self.metrics = DistributedMetrics() if self.config.enable_metrics else None
    
    @abstractmethod
    def process_batch(self, batch: List[T], batch_id: str, **kwargs) -> DistributedResult[R]:
        """Process a single batch of items"""
        pass
    
    def create_batches(self, items: List[T]) -> List[List[T]]:
        """Create batches from a list of items"""
        if not items:
            return []
        
        batches = []
        for i in range(0, len(items), self.config.batch_size):
            batch = items[i:i + self.config.batch_size]
            batches.append(batch)
        
        return batches
    
    def process_distributed(
        self, 
        items: List[T], 
        task_func: Callable,
        **kwargs
    ) -> List[DistributedResult[R]]:
        """Process items in a distributed manner"""
        if not items:
            return []
        
        batches = self.create_batches(items)
        logger.info(f"Created {len(batches)} batches for distributed processing")
        
        # Create batch tasks
        batch_tasks = []
        for i, batch in enumerate(batches):
            batch_id = f"batch_{i + 1}"
            task = task_func.si(batch, batch_id=batch_id, **kwargs)
            batch_tasks.append(task)
        
        # Execute batches in parallel
        try:
            results = safe_group_execution(batch_tasks, self.config.worker_timeout * len(batches))
            return results
        except Exception as e:
            logger.error(f"Distributed processing failed: {e}")
            return []
    
    def aggregate_results(self, results: List[DistributedResult[R]]) -> DistributedResult[List[R]]:
        """Aggregate results from multiple batches"""
        aggregated_data = []
        all_errors = []
        total_processing_time = 0.0
        successful_batches = 0
        
        for result in results:
            if result.is_successful:
                aggregated_data.extend(result.data if isinstance(result.data, list) else [result.data])
                successful_batches += 1
            else:
                all_errors.extend(result.errors)
            
            total_processing_time += result.processing_time
        
        status = ProcessingStatus.COMPLETED if successful_batches > 0 else ProcessingStatus.FAILED
        
        return DistributedResult(
            data=aggregated_data,
            status=status,
            processing_time=total_processing_time,
            errors=all_errors,
            metadata={
                "total_batches": len(results),
                "successful_batches": successful_batches,
                "failed_batches": len(results) - successful_batches
            }
        )


class DistributedMetrics:
    """Metrics collection for distributed operations"""
    
    def __init__(self):
        self.start_time = time.time()
        self.batch_metrics: Dict[str, Dict[str, Any]] = {}
        self.worker_metrics: Dict[str, Dict[str, Any]] = {}
    
    def record_batch_start(self, batch_id: str, batch_size: int) -> None:
        """Record batch processing start"""
        self.batch_metrics[batch_id] = {
            "start_time": time.time(),
            "batch_size": batch_size,
            "status": ProcessingStatus.IN_PROGRESS
        }
    
    def record_batch_completion(self, batch_id: str, success: bool, processing_time: float) -> None:
        """Record batch processing completion"""
        if batch_id in self.batch_metrics:
            self.batch_metrics[batch_id].update({
                "end_time": time.time(),
                "processing_time": processing_time,
                "status": ProcessingStatus.COMPLETED if success else ProcessingStatus.FAILED,
                "success": success
            })
    
    def record_worker_activity(self, worker_id: str, activity: str, **kwargs) -> None:
        """Record worker activity"""
        if worker_id not in self.worker_metrics:
            self.worker_metrics[worker_id] = {"activities": []}
        
        self.worker_metrics[worker_id]["activities"].append({
            "activity": activity,
            "timestamp": time.time(),
            **kwargs
        })
    
    def get_summary(self) -> Dict[str, Any]:
        """Get metrics summary"""
        total_batches = len(self.batch_metrics)
        successful_batches = sum(1 for m in self.batch_metrics.values() if m.get("success", False))
        total_processing_time = sum(m.get("processing_time", 0) for m in self.batch_metrics.values())
        
        return {
            "total_batches": total_batches,
            "successful_batches": successful_batches,
            "failed_batches": total_batches - successful_batches,
            "success_rate": successful_batches / total_batches if total_batches > 0 else 0,
            "total_processing_time": total_processing_time,
            "average_processing_time": total_processing_time / total_batches if total_batches > 0 else 0,
            "total_workers": len(self.worker_metrics)
        }


class DistributedTaskBase(ABC):
    """Base class for distributed task utilities"""
    
    def __init__(self, config: Optional[DistributedConfig] = None):
        self.config = config or DistributedConfig()
        self.config.validate()
        self.error_handler = DistributedErrorHandler(self.config)
        self.metrics = DistributedMetrics() if self.config.enable_metrics else None
        self._lock = threading.Lock()
    
    @abstractmethod
    def get_task_name(self) -> str:
        """Get the name of the task"""
        pass
    
    @abstractmethod
    def get_queue_name(self) -> str:
        """Get the queue name for the task"""
        pass
    
    def validate_task_isolation(self) -> bool:
        """Validate task isolation to prevent deadlocks"""
        from reNgine.utilities.deadlock_prevention import validate_task_isolation
        return validate_task_isolation(self.get_task_name(), self.get_queue_name())
    
    @contextmanager
    def safe_execution(self):
        """Context manager for safe task execution"""
        try:
            if not self.validate_task_isolation():
                raise DeadlockPreventionError(f"Task isolation validation failed for {self.get_task_name()}")
            
            yield self
            
        except Exception as e:
            logger.error(f"Safe execution failed for {self.get_task_name()}: {e}")
            raise
    
    def create_batch_id(self, prefix: str = "batch") -> str:
        """Create a unique batch ID"""
        import uuid
        return f"{prefix}_{uuid.uuid4().hex[:8]}"
    
    def log_processing_start(self, batch_id: str, batch_size: int) -> None:
        """Log the start of batch processing"""
        logger.info(f"Starting {self.get_task_name()} batch {batch_id} with {batch_size} items")
        if self.metrics:
            self.metrics.record_batch_start(batch_id, batch_size)
    
    def log_processing_completion(self, batch_id: str, success: bool, processing_time: float) -> None:
        """Log the completion of batch processing"""
        status = "completed" if success else "failed"
        logger.info(f"{self.get_task_name()} batch {batch_id} {status} in {processing_time:.2f}s")
        if self.metrics:
            self.metrics.record_batch_completion(batch_id, success, processing_time)
    
    def log_processing_error(self, batch_id: str, error: str, processing_time: float) -> None:
        """Log an error during batch processing"""
        logger.error(f"{self.get_task_name()} batch {batch_id} failed after {processing_time:.2f}s: {error}")
        if self.metrics:
            self.metrics.record_batch_completion(batch_id, False, processing_time)


class DistributedCommandProcessor(DistributedTaskBase):
    """Base class for distributed command processing"""
    
    def __init__(self, config: Optional[DistributedConfig] = None):
        super().__init__(config)
        self.command_history: Dict[str, List[str]] = {}
    
    def get_queue_name(self) -> str:
        return "run_command_queue"
    
    def record_command(self, batch_id: str, command: str) -> None:
        """Record command execution"""
        if batch_id not in self.command_history:
            self.command_history[batch_id] = []
        self.command_history[batch_id].append(command)
    
    def get_command_history(self, batch_id: str) -> List[str]:
        """Get command history for a batch"""
        return self.command_history.get(batch_id, [])


class DistributedDatabaseProcessor(DistributedTaskBase):
    """Base class for distributed database operations"""
    
    def __init__(self, config: Optional[DistributedConfig] = None, db_interface=None):
        super().__init__(config)
        self.db_operations: Dict[str, List[str]] = {}
        self.db_interface = db_interface
    
    def get_queue_name(self) -> str:
        return "cpu_queue"
    
    def record_db_operation(self, batch_id: str, operation: str) -> None:
        """Record database operation"""
        if batch_id not in self.db_operations:
            self.db_operations[batch_id] = []
        self.db_operations[batch_id].append(operation)
    
    def get_db_operations(self, batch_id: str) -> List[str]:
        """Get database operations for a batch"""
        return self.db_operations.get(batch_id, [])


class DistributedParserProcessor(DistributedTaskBase):
    """Base class for distributed parsing operations"""
    
    def __init__(self, config: Optional[DistributedConfig] = None):
        super().__init__(config)
        self.parsed_items: Dict[str, List[Any]] = {}
    
    def get_queue_name(self) -> str:
        return "io_queue"
    
    def record_parsed_item(self, batch_id: str, item: Any) -> None:
        """Record parsed item"""
        if batch_id not in self.parsed_items:
            self.parsed_items[batch_id] = []
        self.parsed_items[batch_id].append(item)
    
    def get_parsed_items(self, batch_id: str) -> List[Any]:
        """Get parsed items for a batch"""
        return self.parsed_items.get(batch_id, [])


# Utility functions for common distributed operations

def create_distributed_config(
    batch_size: int = 15,
    worker_timeout: int = 300,
    max_retries: int = 3,
    **kwargs
) -> DistributedConfig:
    """Create a distributed configuration with common defaults"""
    return DistributedConfig(
        batch_size=batch_size,
        worker_timeout=worker_timeout,
        max_retries=max_retries,
        **kwargs
    )


def validate_distributed_input(items: List[Any], min_items: int = 1, max_items: int = 10000) -> bool:
    """Validate input for distributed processing"""
    if not items:
        logger.warning("Empty input list provided for distributed processing")
        return False
    
    if len(items) < min_items:
        logger.warning(f"Input list too small: {len(items)} < {min_items}")
        return False
    
    if len(items) > max_items:
        logger.warning(f"Input list too large: {len(items)} > {max_items}")
        return False
    
    return True


def create_batch_tasks(
    items: List[Any],
    task_func: Callable,
    batch_size: int = 15,
    **kwargs
) -> List[Any]:
    """Create batch tasks for distributed processing"""
    if not validate_distributed_input(items):
        return []
    
    batches = []
    for i in range(0, len(items), batch_size):
        batch = items[i:i + batch_size]
        batch_id = f"batch_{i // batch_size + 1}"
        task = task_func.si(batch, batch_id=batch_id, **kwargs)
        batches.append(task)
    
    return batches


def aggregate_distributed_results(results: List[DistributedResult[Any]]) -> Dict[str, Any]:
    """Aggregate results from distributed processing"""
    if not results:
        return {"success": False, "error": "No results to aggregate"}
    
    total_items = 0
    successful_items = 0
    total_errors = []
    total_processing_time = 0.0
    
    for result in results:
        if isinstance(result.data, list):
            total_items += len(result.data)
        else:
            total_items += 1
        
        if result.is_successful:
            if isinstance(result.data, list):
                successful_items += len(result.data)
            else:
                successful_items += 1
        
        total_errors.extend(result.errors)
        total_processing_time += result.processing_time
    
    return {
        "success": successful_items > 0,
        "total_items": total_items,
        "successful_items": successful_items,
        "failed_items": total_items - successful_items,
        "success_rate": successful_items / total_items if total_items > 0 else 0,
        "total_errors": len(total_errors),
        "errors": total_errors,
        "total_processing_time": total_processing_time,
        "average_processing_time": total_processing_time / len(results) if results else 0
    }
