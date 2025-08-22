"""
Optimization Module for MorphCloud SDK

This module provides:
- Data structure optimizations
- Async performance improvements
- Memory optimization utilities
- Network call batching and optimization
"""

import asyncio
import time
from typing import Any, Dict, List, Optional, Callable, TypeVar
from dataclasses import dataclass
from collections import deque
import threading
import logging

T = TypeVar("T")
F = TypeVar("F", bound=Callable[..., Any])


@dataclass
class BatchRequest:
    """Represents a batched request"""

    id: str
    data: Any
    callback: Optional[Callable[[Any], None]] = None
    timestamp: float = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()


class BatchProcessor:
    """Processes requests in batches for improved performance"""

    def __init__(self, batch_size: int = 10, max_wait_time: float = 0.1):
        self.batch_size = batch_size
        self.max_wait_time = max_wait_time
        self.pending_requests: deque = deque()
        self.lock = threading.Lock()
        self.logger = logging.getLogger("morphcloud.optimization")

    def add_request(self, request: BatchRequest) -> bool:
        """Add a request to the batch processor"""
        with self.lock:
            self.pending_requests.append(request)
            return len(self.pending_requests) >= self.batch_size

    def get_batch(self) -> List[BatchRequest]:
        """Get the next batch of requests"""
        with self.lock:
            if not self.pending_requests:
                return []

            batch = []
            current_time = time.time()

            # Get up to batch_size requests
            while len(batch) < self.batch_size and self.pending_requests:
                request = self.pending_requests.popleft()
                batch.append(request)

            # Check if we should wait for more requests
            if (
                len(batch) < self.batch_size
                and self.pending_requests
                and current_time - self.pending_requests[0].timestamp
                < self.max_wait_time
            ):
                # Put requests back and wait
                for req in reversed(batch):
                    self.pending_requests.appendleft(req)
                return []

            return batch


class ConnectionPool:
    """Manages connection pooling for network operations"""

    def __init__(self, max_connections: int = 10, max_idle_time: float = 300):
        self.max_connections = max_connections
        self.max_idle_time = max_idle_time
        self.active_connections: Dict[str, Any] = {}
        self.idle_connections: deque = deque()
        self.lock = threading.Lock()
        self.logger = logging.getLogger("morphcloud.optimization")

    def get_connection(self, key: str, factory: Callable[[], Any]) -> Any:
        """Get or create a connection"""
        with self.lock:
            # Check active connections first
            if key in self.active_connections:
                return self.active_connections[key]

            # Check idle connections
            if self.idle_connections:
                conn = self.idle_connections.popleft()
                self.active_connections[key] = conn
                return conn

            # Create new connection if under limit
            if len(self.active_connections) < self.max_connections:
                conn = factory()
                self.active_connections[key] = conn
                return conn

            # Wait for a connection to become available
            self.logger.warning(
                f"Connection pool full, waiting for available connection"
            )
            return None

    def release_connection(self, key: str, connection: Any):
        """Release a connection back to the pool"""
        with self.lock:
            if key in self.active_connections:
                del self.active_connections[key]

            # Add to idle pool if not at capacity
            if len(self.idle_connections) < self.max_connections:
                self.idle_connections.append(connection)


class AsyncTaskManager:
    """Manages async tasks for improved performance"""

    def __init__(self, max_concurrent: int = 10):
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.active_tasks: set = set()
        self.logger = logging.getLogger("morphcloud.optimization")

    async def execute_with_semaphore(self, coro, task_name: str = "unnamed"):
        """Execute a coroutine with semaphore control"""
        async with self.semaphore:
            task = asyncio.create_task(coro)
            self.active_tasks.add(task)
            try:
                result = await task
                return result
            finally:
                self.active_tasks.discard(task)

    async def execute_batch(
        self, coros: List[Callable], max_concurrent: Optional[int] = None
    ) -> List[Any]:
        """Execute multiple coroutines in batches"""
        if max_concurrent:
            semaphore = asyncio.Semaphore(max_concurrent)
        else:
            semaphore = self.semaphore

        async def execute_with_semaphore(coro):
            async with semaphore:
                return await coro

        tasks = [execute_with_semaphore(coro()) for coro in coros]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.logger.error(f"Task {i} failed: {result}")
            else:
                valid_results.append(result)

        return valid_results


class MemoryOptimizer:
    """Utilities for memory optimization"""

    @staticmethod
    def optimize_dict(d: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize dictionary memory usage"""
        # Use __slots__ for small dictionaries
        if len(d) <= 10:
            return dict(d)  # Small dicts are already optimized

        # For larger dicts, consider using more efficient structures
        return d

    @staticmethod
    def optimize_list(lst: List[Any]) -> List[Any]:
        """Optimize list memory usage"""
        # Use deque for frequent append/left operations
        if len(lst) > 1000:
            return deque(lst)
        return lst

    @staticmethod
    def batch_process(items: List[Any], batch_size: int = 1000):
        """Process items in batches to reduce memory usage"""
        for i in range(0, len(items), batch_size):
            yield items[i : i + batch_size]


class StringOptimizer:
    """String optimization utilities"""

    @staticmethod
    def join_strings(strings: List[str]) -> str:
        """Efficiently join strings"""
        return "".join(strings)

    @staticmethod
    def format_strings(template: str, *args, **kwargs) -> str:
        """Format strings efficiently"""
        return template.format(*args, **kwargs)

    @staticmethod
    def concat_strings(*strings: str) -> str:
        """Concatenate strings efficiently"""
        return "".join(strings)


class NetworkOptimizer:
    """Network call optimization utilities"""

    def __init__(self):
        self.connection_pool = ConnectionPool()
        self.batch_processor = BatchProcessor()

    async def batch_api_calls(
        self, calls: List[Callable], batch_size: int = 10
    ) -> List[Any]:
        """Batch multiple API calls for improved performance"""
        results = []

        for i in range(0, len(calls), batch_size):
            batch = calls[i : i + batch_size]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            results.extend(batch_results)

        return results

    def optimize_http_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Optimize HTTP headers for better performance"""
        # Remove unnecessary headers
        unnecessary = ["x-powered-by", "server", "x-aspnet-version"]
        optimized = {k: v for k, v in headers.items() if k.lower() not in unnecessary}

        # Add performance headers
        optimized.update(
            {"connection": "keep-alive", "keep-alive": "timeout=5, max=1000"}
        )

        return optimized


# Global instances
_global_network_optimizer = NetworkOptimizer()
_global_async_manager = AsyncTaskManager()


def get_network_optimizer() -> NetworkOptimizer:
    """Get the global network optimizer instance"""
    return _global_network_optimizer


def get_async_manager() -> AsyncTaskManager:
    """Get the global async task manager instance"""
    return _global_async_manager


def optimize_data_structures(data: Any) -> Any:
    """Apply data structure optimizations"""
    if isinstance(data, dict):
        return MemoryOptimizer.optimize_dict(data)
    elif isinstance(data, list):
        return MemoryOptimizer.optimize_list(data)
    return data


def batch_process_data(data: List[Any], batch_size: int = 1000):
    """Process data in batches for memory efficiency"""
    return MemoryOptimizer.batch_process(data, batch_size)
