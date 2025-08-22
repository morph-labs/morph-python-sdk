"""
Performance Monitoring and Optimization Module for MorphCloud SDK

This module provides:
- Performance metrics collection and monitoring
- Lazy loading utilities for resource optimization
- Performance profiling and optimization tools
- Caching mechanisms for improved response times
"""

import time
import functools
import threading
from typing import Any, Callable, Dict, List, Optional, TypeVar, Generic, Union
from dataclasses import dataclass, field
from enum import Enum
import logging
import asyncio
from collections import defaultdict, OrderedDict

# Type variables for generic functions
T = TypeVar("T")
F = TypeVar("F", bound=Callable[..., Any])


class MetricType(Enum):
    """Types of performance metrics"""

    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class PerformanceMetric:
    """Individual performance metric"""

    name: str
    value: Union[int, float]
    metric_type: MetricType
    timestamp: float = field(default_factory=time.time)
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


class PerformanceMonitor:
    """Central performance monitoring system"""

    def __init__(self):
        self.metrics: List[PerformanceMetric] = []
        self.lock = threading.Lock()
        self.logger = logging.getLogger("morphcloud.performance")
        self._start_time = time.time()

    def record_metric(
        self,
        name: str,
        value: Union[int, float],
        metric_type: MetricType = MetricType.GAUGE,
        tags: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Record a performance metric"""
        with self.lock:
            metric = PerformanceMetric(
                name=name,
                value=value,
                metric_type=metric_type,
                tags=tags or {},
                metadata=metadata or {},
            )
            self.metrics.append(metric)

    def record_timing(
        self, name: str, duration: float, tags: Optional[Dict[str, str]] = None
    ):
        """Record a timing metric"""
        self.record_metric(name, duration, MetricType.TIMER, tags)

    def record_counter(
        self, name: str, increment: int = 1, tags: Optional[Dict[str, str]] = None
    ):
        """Record a counter metric"""
        self.record_metric(name, increment, MetricType.COUNTER, tags)

    def get_metrics(
        self,
        name_filter: Optional[str] = None,
        metric_type: Optional[MetricType] = None,
    ) -> List[PerformanceMetric]:
        """Retrieve metrics with optional filtering"""
        with self.lock:
            filtered = self.metrics

            if name_filter:
                filtered = [m for m in filtered if name_filter in m.name]

            if metric_type:
                filtered = [m for m in filtered if m.metric_type == metric_type]

            return filtered.copy()

    def get_summary_stats(self) -> Dict[str, Any]:
        """Get summary statistics for all metrics"""
        with self.lock:
            if not self.metrics:
                return {}

            stats = {
                "total_metrics": len(self.metrics),
                "uptime": time.time() - self._start_time,
                "metric_types": defaultdict(int),
                "top_metrics": {},
            }

            # Count metric types
            for metric in self.metrics:
                stats["metric_types"][metric.metric_type.value] += 1

            # Get top metrics by value
            for metric_type in MetricType:
                type_metrics = [m for m in self.metrics if m.metric_type == metric_type]
                if type_metrics:
                    if metric_type == MetricType.TIMER:
                        # For timers, get min/max/avg
                        values = [m.value for m in type_metrics]
                        stats["top_metrics"][f"{metric_type.value}_stats"] = {
                            "min": min(values),
                            "max": max(values),
                            "avg": sum(values) / len(values),
                            "count": len(values),
                        }
                    else:
                        # For others, get top 5 by value
                        sorted_metrics = sorted(
                            type_metrics, key=lambda x: x.value, reverse=True
                        )[:5]
                        stats["top_metrics"][f"top_{metric_type.value}"] = [
                            {"name": m.name, "value": m.value, "timestamp": m.timestamp}
                            for m in sorted_metrics
                        ]

            return stats


class LazyLoader(Generic[T]):
    """Generic lazy loading container"""

    def __init__(self, factory: Callable[[], T], name: str = "unnamed"):
        self._factory = factory
        self._instance: Optional[T] = None
        self._loaded = False
        self.name = name
        self._load_time: Optional[float] = None

    def __get__(self, obj, objtype=None) -> T:
        if obj is None:
            return self

        if not self._loaded:
            start_time = time.time()
            self._instance = self._factory()
            self._loaded = True
            self._load_time = time.time() - start_time

            # Record performance metric
            if hasattr(obj, "_performance_monitor"):
                obj._performance_monitor.record_timing(
                    f"lazy_load_{self.name}", self._load_time, {"type": "lazy_loading"}
                )

        return self._instance

    def reset(self):
        """Reset the lazy loader to force reload"""
        self._instance = None
        self._loaded = False
        self._load_time = None


class CacheManager:
    """LRU cache manager with TTL support"""

    def __init__(self, max_size: int = 100, default_ttl: int = 300):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache: OrderedDict = OrderedDict()
        self.timestamps: Dict[str, float] = {}
        self.lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        """Get item from cache if not expired"""
        with self.lock:
            if key in self.cache:
                # Check TTL
                if time.time() - self.timestamps[key] > self.default_ttl:
                    # Expired, remove
                    del self.cache[key]
                    del self.timestamps[key]
                    return None

                # Move to end (LRU)
                value = self.cache.pop(key)
                self.cache[key] = value
                return value

        return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set item in cache with TTL"""
        with self.lock:
            # Remove if exists
            if key in self.cache:
                del self.cache[key]
                del self.timestamps[key]

            # Check size limit
            if len(self.cache) >= self.max_size:
                # Remove oldest
                oldest_key = next(iter(self.cache))
                del self.cache[oldest_key]
                del self.timestamps[oldest_key]

            # Add new item
            self.cache[key] = value
            self.timestamps[key] = time.time()

    def clear(self):
        """Clear all cached items"""
        with self.lock:
            self.cache.clear()
            self.timestamps.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.lock:
            current_time = time.time()
            expired_count = sum(
                1
                for ts in self.timestamps.values()
                if current_time - ts > self.default_ttl
            )

            return {
                "total_items": len(self.cache),
                "max_size": self.max_size,
                "expired_items": expired_count,
                "hit_rate": getattr(self, "_hits", 0)
                / max(getattr(self, "_total_requests", 1), 1),
            }


class PerformanceProfiler:
    """Context manager for performance profiling"""

    def __init__(self, name: str, monitor: Optional[PerformanceMonitor] = None):
        self.name = name
        self.monitor = monitor
        self.start_time: Optional[float] = None

    def __enter__(self):
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time and self.monitor:
            duration = time.time() - self.start_time
            self.monitor.record_timing(self.name, duration)

    async def __aenter__(self):
        self.start_time = time.time()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.start_time and self.monitor:
            duration = time.time() - self.start_time
            self.monitor.record_timing(self.name, duration)


def performance_monitor(monitor: Optional[PerformanceMonitor] = None):
    """Decorator to automatically monitor function performance"""

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            nonlocal monitor
            if monitor is None:
                # Try to get monitor from instance
                if args and hasattr(args[0], "_performance_monitor"):
                    monitor = args[0]._performance_monitor
                else:
                    # Create default monitor
                    monitor = PerformanceMonitor()

            with PerformanceProfiler(f"{func.__module__}.{func.__name__}", monitor):
                return func(*args, **kwargs)

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            nonlocal monitor
            if monitor is None:
                if args and hasattr(args[0], "_performance_monitor"):
                    monitor = args[0]._performance_monitor
                else:
                    monitor = PerformanceMonitor()

            async with PerformanceProfiler(
                f"{func.__module__}.{func.__name__}", monitor
            ):
                return await func(*args, **kwargs)

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return wrapper

    return decorator


def lazy_property(factory: Callable[[], T], name: Optional[str] = None):
    """Decorator to create lazy properties"""
    return LazyLoader(factory, name or factory.__name__)


# Global performance monitor instance
_global_monitor = PerformanceMonitor()


def get_global_monitor() -> PerformanceMonitor:
    """Get the global performance monitor instance"""
    return _global_monitor


def record_metric(
    name: str,
    value: Union[int, float],
    metric_type: MetricType = MetricType.GAUGE,
    tags: Optional[Dict[str, str]] = None,
):
    """Record a metric using the global monitor"""
    _global_monitor.record_metric(name, value, metric_type, tags)


def record_timing(name: str, duration: float, tags: Optional[Dict[str, str]] = None):
    """Record a timing metric using the global monitor"""
    _global_monitor.record_timing(name, duration, tags)


def get_performance_summary() -> Dict[str, Any]:
    """Get performance summary from global monitor"""
    return _global_monitor.get_summary_stats()
