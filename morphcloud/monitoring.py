"""
Monitoring and Observability Module for MorphCloud SDK

This module provides:
- Health checks and system monitoring
- Metrics collection and reporting
- Performance monitoring and alerting
- System diagnostics and troubleshooting
"""

import time
import threading
import logging
import psutil
from typing import Any, Dict, List, Optional, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict


class HealthStatus(Enum):
    """Health check status values"""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class MetricType(Enum):
    """Metric types for monitoring"""

    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class HealthCheck:
    """Individual health check result"""

    name: str
    status: HealthStatus
    message: str
    timestamp: float = field(default_factory=time.time)
    details: Optional[Dict[str, Any]] = None
    duration: Optional[float] = None


@dataclass
class SystemMetrics:
    """System performance metrics"""

    cpu_percent: float
    memory_percent: float
    memory_available: int
    disk_usage_percent: float
    disk_free: int
    network_io: Dict[str, int]
    timestamp: float = field(default_factory=time.time)


@dataclass
class ApplicationMetrics:
    """Application-specific metrics"""

    active_connections: int
    request_count: int
    error_count: int
    response_time_avg: float
    cache_hit_rate: float
    timestamp: float = field(default_factory=time.time)


class HealthChecker:
    """Performs health checks on system components"""

    def __init__(self):
        self.health_checks: List[Callable[[], HealthCheck]] = []
        self.logger = logging.getLogger("morphcloud.monitoring")

    def add_health_check(self, check_func: Callable[[], HealthCheck]):
        """Add a health check function"""
        self.health_checks.append(check_func)

    def remove_health_check(self, check_func: Callable[[], HealthCheck]):
        """Remove a health check function"""
        if check_func in self.health_checks:
            self.health_checks.remove(check_func)

    def run_health_checks(self) -> List[HealthCheck]:
        """Run all registered health checks"""
        results = []

        for check_func in self.health_checks:
            try:
                start_time = time.time()
                result = check_func()
                result.duration = time.time() - start_time
                results.append(result)
            except Exception as e:
                self.logger.error(f"Health check {check_func.__name__} failed: {e}")
                results.append(
                    HealthCheck(
                        name=check_func.__name__,
                        status=HealthStatus.UNHEALTHY,
                        message=f"Health check failed: {e}",
                        details={"error": str(e)},
                    )
                )

        return results

    def get_overall_health(self, checks: List[HealthCheck]) -> HealthStatus:
        """Determine overall health status from individual checks"""
        if not checks:
            return HealthStatus.UNKNOWN

        status_counts = {
            HealthStatus.HEALTHY: 0,
            HealthStatus.DEGRADED: 0,
            HealthStatus.UNHEALTHY: 0,
            HealthStatus.UNKNOWN: 0,
        }

        for check in checks:
            status_counts[check.status] += 1

        # Determine overall status
        if status_counts[HealthStatus.UNHEALTHY] > 0:
            return HealthStatus.UNHEALTHY
        elif status_counts[HealthStatus.DEGRADED] > 0:
            return HealthStatus.DEGRADED
        elif status_counts[HealthStatus.HEALTHY] > 0:
            return HealthStatus.HEALTHY
        else:
            return HealthStatus.UNKNOWN


class SystemMonitor:
    """Monitors system resources and performance"""

    def __init__(self, check_interval: float = 60.0):
        self.check_interval = check_interval
        self.logger = logging.getLogger("morphcloud.monitoring")
        self.metrics_history: List[SystemMetrics] = []
        self.max_history_size = 1000
        self._monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None

    def start_monitoring(self):
        """Start system monitoring in background thread"""
        if self._monitoring:
            return

        self._monitoring = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop)
        self._monitor_thread.daemon = True
        self._monitor_thread.start()
        self.logger.info("System monitoring started")

    def stop_monitoring(self):
        """Stop system monitoring"""
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join()
        self.logger.info("System monitoring stopped")

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self._monitoring:
            try:
                metrics = self._collect_system_metrics()
                self._store_metrics(metrics)
                time.sleep(self.check_interval)
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self.check_interval)

    def _collect_system_metrics(self) -> SystemMetrics:
        """Collect current system metrics"""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)

            # Memory metrics
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_available = memory.available

            # Disk metrics
            disk = psutil.disk_usage("/")
            disk_usage_percent = disk.percent
            disk_free = disk.free

            # Network metrics
            network_io = psutil.net_io_counters()._asdict()

            return SystemMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                memory_available=memory_available,
                disk_usage_percent=disk_usage_percent,
                disk_free=disk_free,
                network_io=network_io,
            )
        except Exception as e:
            self.logger.error(f"Error collecting system metrics: {e}")
            return SystemMetrics(
                cpu_percent=0.0,
                memory_percent=0.0,
                memory_available=0,
                disk_usage_percent=0.0,
                disk_free=0,
                network_io={},
            )

    def _store_metrics(self, metrics: SystemMetrics):
        """Store metrics in history"""
        self.metrics_history.append(metrics)

        # Maintain history size
        if len(self.metrics_history) > self.max_history_size:
            self.metrics_history.pop(0)

    def get_current_metrics(self) -> Optional[SystemMetrics]:
        """Get most recent system metrics"""
        if self.metrics_history:
            return self.metrics_history[-1]
        return None

    def get_metrics_summary(self, minutes: int = 60) -> Dict[str, Any]:
        """Get metrics summary for specified time period"""
        if not self.metrics_history:
            return {}

        cutoff_time = time.time() - (minutes * 60)
        recent_metrics = [m for m in self.metrics_history if m.timestamp >= cutoff_time]

        if not recent_metrics:
            return {}

        # Calculate averages and ranges
        cpu_values = [m.cpu_percent for m in recent_metrics]
        memory_values = [m.memory_percent for m in recent_metrics]
        disk_values = [m.disk_usage_percent for m in recent_metrics]

        return {
            "period_minutes": minutes,
            "sample_count": len(recent_metrics),
            "cpu": {
                "average": sum(cpu_values) / len(cpu_values),
                "min": min(cpu_values),
                "max": max(cpu_values),
            },
            "memory": {
                "average": sum(memory_values) / len(memory_values),
                "min": min(memory_values),
                "max": max(memory_values),
            },
            "disk": {
                "average": sum(disk_values) / len(disk_values),
                "min": min(disk_values),
                "max": max(disk_values),
            },
        }


class ApplicationMonitor:
    """Monitors application-specific metrics"""

    def __init__(self):
        self.metrics: Dict[str, Any] = {}
        self.counters: Dict[str, int] = defaultdict(int)
        self.timers: Dict[str, List[float]] = defaultdict(list)
        self.logger = logging.getLogger("morphcloud.monitoring")
        self.lock = threading.Lock()

    def increment_counter(self, name: str, value: int = 1):
        """Increment a counter metric"""
        with self.lock:
            self.counters[name] += value

    def set_gauge(self, name: str, value: Union[int, float]):
        """Set a gauge metric value"""
        with self.lock:
            self.metrics[name] = value

    def record_timer(self, name: str, duration: float):
        """Record a timing metric"""
        with self.lock:
            self.timers[name].append(duration)
            # Keep only last 1000 values
            if len(self.timers[name]) > 1000:
                self.timers[name] = self.timers[name][-1000:]

    def get_metrics(self) -> ApplicationMetrics:
        """Get current application metrics"""
        with self.lock:
            # Calculate timer statistics
            timer_stats = {}
            for name, values in self.timers.items():
                if values:
                    timer_stats[name] = {
                        "count": len(values),
                        "average": sum(values) / len(values),
                        "min": min(values),
                        "max": max(values),
                    }

            return ApplicationMetrics(
                active_connections=self.metrics.get("active_connections", 0),
                request_count=self.counters.get("requests", 0),
                error_count=self.counters.get("errors", 0),
                response_time_avg=timer_stats.get("response_time", {}).get(
                    "average", 0.0
                ),
                cache_hit_rate=self.metrics.get("cache_hit_rate", 0.0),
            )

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get comprehensive metrics summary"""
        with self.lock:
            return {
                "metrics": dict(self.metrics),
                "counters": dict(self.counters),
                "timers": {
                    name: {
                        "count": len(values),
                        "average": sum(values) / len(values) if values else 0,
                        "min": min(values) if values else 0,
                        "max": max(values) if values else 0,
                    }
                    for name, values in self.timers.items()
                },
            }


class MonitoringDashboard:
    """Provides monitoring dashboard and reporting"""

    def __init__(self):
        self.health_checker = HealthChecker()
        self.system_monitor = SystemMonitor()
        self.app_monitor = ApplicationMonitor()
        self.logger = logging.getLogger("morphcloud.monitoring")

        # Add default health checks
        self._setup_default_health_checks()

    def _setup_default_health_checks(self):
        """Setup default system health checks"""
        self.health_checker.add_health_check(self._check_disk_space)
        self.health_checker.add_health_check(self._check_memory_usage)
        self.health_checker.add_health_check(self._check_cpu_usage)

    def _check_disk_space(self) -> HealthCheck:
        """Check available disk space"""
        try:
            disk = psutil.disk_usage("/")
            usage_percent = disk.percent

            if usage_percent < 80:
                status = HealthStatus.HEALTHY
                message = f"Disk usage: {usage_percent:.1f}%"
            elif usage_percent < 90:
                status = HealthStatus.DEGRADED
                message = f"Disk usage high: {usage_percent:.1f}%"
            else:
                status = HealthStatus.UNHEALTHY
                message = f"Disk usage critical: {usage_percent:.1f}%"

            return HealthCheck(
                name="disk_space",
                status=status,
                message=message,
                details={
                    "usage_percent": usage_percent,
                    "free_gb": disk.free / (1024**3),
                },
            )
        except Exception as e:
            return HealthCheck(
                name="disk_space",
                status=HealthStatus.UNKNOWN,
                message=f"Disk check failed: {e}",
            )

    def _check_memory_usage(self) -> HealthCheck:
        """Check memory usage"""
        try:
            memory = psutil.virtual_memory()
            usage_percent = memory.percent

            if usage_percent < 80:
                status = HealthStatus.HEALTHY
                message = f"Memory usage: {usage_percent:.1f}%"
            elif usage_percent < 90:
                status = HealthStatus.DEGRADED
                message = f"Memory usage high: {usage_percent:.1f}%"
            else:
                status = HealthStatus.UNHEALTHY
                message = f"Memory usage critical: {usage_percent:.1f}%"

            return HealthCheck(
                name="memory_usage",
                status=status,
                message=message,
                details={
                    "usage_percent": usage_percent,
                    "available_gb": memory.available / (1024**3),
                },
            )
        except Exception as e:
            return HealthCheck(
                name="memory_usage",
                status=HealthStatus.UNKNOWN,
                message=f"Memory check failed: {e}",
            )

    def _check_cpu_usage(self) -> HealthCheck:
        """Check CPU usage"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)

            if cpu_percent < 80:
                status = HealthStatus.HEALTHY
                message = f"CPU usage: {cpu_percent:.1f}%"
            elif cpu_percent < 90:
                status = HealthStatus.DEGRADED
                message = f"CPU usage high: {cpu_percent:.1f}%"
            else:
                status = HealthStatus.UNHEALTHY
                message = f"CPU usage critical: {cpu_percent:.1f}%"

            return HealthCheck(
                name="cpu_usage",
                status=status,
                message=message,
                details={"usage_percent": cpu_percent},
            )
        except Exception as e:
            return HealthCheck(
                name="cpu_usage",
                status=HealthStatus.UNKNOWN,
                message=f"CPU check failed: {e}",
            )

    def start_monitoring(self):
        """Start all monitoring systems"""
        self.system_monitor.start_monitoring()
        self.logger.info("Monitoring dashboard started")

    def stop_monitoring(self):
        """Stop all monitoring systems"""
        self.system_monitor.stop_monitoring()
        self.logger.info("Monitoring dashboard stopped")

    def get_health_status(self) -> Dict[str, Any]:
        """Get comprehensive health status"""
        health_checks = self.health_checker.run_health_checks()
        overall_health = self.health_checker.get_overall_health(health_checks)

        return {
            "overall_status": overall_health.value,
            "timestamp": time.time(),
            "health_checks": [check.__dict__ for check in health_checks],
            "system_metrics": (
                self.system_monitor.get_current_metrics().__dict__
                if self.system_monitor.get_current_metrics()
                else None
            ),
            "application_metrics": self.app_monitor.get_metrics().__dict__,
        }

    def get_monitoring_summary(self) -> Dict[str, Any]:
        """Get comprehensive monitoring summary"""
        return {
            "health_status": self.get_health_status(),
            "system_summary": self.system_monitor.get_metrics_summary(),
            "application_summary": self.app_monitor.get_metrics_summary(),
        }


# Global monitoring dashboard instance
_monitoring_dashboard: Optional[MonitoringDashboard] = None


def get_monitoring_dashboard() -> MonitoringDashboard:
    """Get the global monitoring dashboard instance"""
    global _monitoring_dashboard
    if _monitoring_dashboard is None:
        _monitoring_dashboard = MonitoringDashboard()
    return _monitoring_dashboard


def start_monitoring():
    """Start global monitoring"""
    get_monitoring_dashboard().start_monitoring()


def stop_monitoring():
    """Stop global monitoring"""
    get_monitoring_dashboard().stop_monitoring()


def get_health_status() -> Dict[str, Any]:
    """Get global health status"""
    return get_monitoring_dashboard().get_health_status()


def get_monitoring_summary() -> Dict[str, Any]:
    """Get global monitoring summary"""
    return get_monitoring_dashboard().get_monitoring_summary()


def increment_counter(name: str, value: int = 1):
    """Increment a global counter metric"""
    get_monitoring_dashboard().app_monitor.increment_counter(name, value)


def set_gauge(name: str, value: Union[int, float]):
    """Set a global gauge metric"""
    get_monitoring_dashboard().app_monitor.set_gauge(name, value)


def record_timer(name: str, duration: float):
    """Record a global timing metric"""
    get_monitoring_dashboard().app_monitor.record_timer(name, duration)
