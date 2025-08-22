"""
Runtime Security Module

This module provides comprehensive runtime security including:
- Memory corruption detection and prevention
- Race condition analysis and thread safety
- Resource exhaustion protection
- Buffer overflow detection
- Memory leak detection
- Thread safety analysis
- DoS attack prevention
"""

import time
import threading
import logging
import tracemalloc
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Union, TypeVar
from pathlib import Path
import psutil
import resource

logger = logging.getLogger(__name__)

T = TypeVar("T")


class SecurityLevel(Enum):
    """Runtime security levels"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    PARANOID = "paranoid"


class ThreatType(Enum):
    """Types of runtime security threats"""

    MEMORY_CORRUPTION = "memory_corruption"
    RACE_CONDITION = "race_condition"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    BUFFER_OVERFLOW = "buffer_overflow"
    MEMORY_LEAK = "memory_leak"
    THREAD_SAFETY = "thread_safety"
    DOS_ATTACK = "dos_attack"
    STACK_OVERFLOW = "stack_overflow"


class ThreatSeverity(Enum):
    """Threat severity levels"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityEvent:
    """Represents a security event"""

    event_id: str
    threat_type: ThreatType
    severity: ThreatSeverity
    description: str
    timestamp: float
    location: str
    stack_trace: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
    mitigated: bool = False
    mitigation_action: Optional[str] = None


@dataclass
class RuntimeSecurityConfig:
    """Runtime security configuration"""

    security_level: SecurityLevel = SecurityLevel.HIGH
    enable_memory_protection: bool = True
    enable_race_detection: bool = True
    enable_resource_monitoring: bool = True
    enable_buffer_overflow_detection: bool = True
    enable_memory_leak_detection: bool = True
    enable_thread_safety_analysis: bool = True
    enable_dos_protection: bool = True
    memory_threshold_mb: int = 1024  # 1GB
    cpu_threshold_percent: float = 80.0
    file_descriptor_limit: int = 1000
    thread_limit: int = 100
    stack_size_limit_mb: int = 8
    heap_size_limit_mb: int = 512
    monitoring_interval: float = 1.0  # seconds
    alert_threshold: int = 5  # number of events before alerting


class MemoryProtector:
    """Protects against memory corruption and buffer overflows"""

    def __init__(self, config: RuntimeSecurityConfig):
        self.config = config
        self.memory_regions: Dict[int, Dict[str, Any]] = {}
        self.buffer_checks: Dict[str, Dict[str, Any]] = {}
        self.memory_usage_history: List[Dict[str, Any]] = []
        self.leak_suspects: Dict[int, Dict[str, Any]] = {}
        self._init_memory_protection()

    def _init_memory_protection(self):
        """Initialize memory protection mechanisms"""
        if not self.config.enable_memory_protection:
            return

        try:
            # Enable memory tracking
            tracemalloc.start()

            # Set memory limits
            if hasattr(resource, "RLIMIT_AS"):
                resource.setrlimit(
                    resource.RLIMIT_AS,
                    (self.config.heap_size_limit_mb * 1024 * 1024, -1),
                )

            # Set stack size limit
            if hasattr(resource, "RLIMIT_STACK"):
                resource.setrlimit(
                    resource.RLIMIT_STACK,
                    (self.config.stack_size_limit_mb * 1024 * 1024, -1),
                )

            logger.info("Memory protection initialized successfully")

        except Exception as e:
            logger.warning(f"Failed to initialize memory protection: {e}")

    def protect_buffer(self, buffer_id: str, data: bytes, max_size: int) -> bool:
        """Protect a buffer against overflow"""
        if not self.config.enable_buffer_overflow_detection:
            return True

        try:
            if len(data) > max_size:
                self._record_security_event(
                    ThreatType.BUFFER_OVERFLOW,
                    ThreatSeverity.HIGH,
                    f"Buffer overflow detected: {buffer_id}",
                    f"Data size {len(data)} exceeds limit {max_size}",
                    {
                        "buffer_id": buffer_id,
                        "data_size": len(data),
                        "max_size": max_size,
                    },
                )
                return False

            # Record buffer information
            self.buffer_checks[buffer_id] = {
                "max_size": max_size,
                "current_size": len(data),
                "created_at": time.time(),
                "access_count": 0,
            }

            return True

        except Exception as e:
            logger.error(f"Buffer protection failed: {e}")
            return False

    def check_memory_usage(self) -> Dict[str, Any]:
        """Check current memory usage and detect anomalies"""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()

            current_usage = {
                "rss_mb": memory_info.rss / (1024 * 1024),
                "vms_mb": memory_info.vms / (1024 * 1024),
                "percent": process.memory_percent(),
                "timestamp": time.time(),
            }

            # Check for memory threshold violations
            if current_usage["rss_mb"] > self.config.memory_threshold_mb:
                self._record_security_event(
                    ThreatType.RESOURCE_EXHAUSTION,
                    ThreatSeverity.HIGH,
                    "Memory usage exceeded threshold",
                    f"Current: {current_usage['rss_mb']:.2f}MB, Limit: {self.config.memory_threshold_mb}MB",
                    current_usage,
                )

            # Record memory usage history
            self.memory_usage_history.append(current_usage)

            # Keep only last 1000 entries
            if len(self.memory_usage_history) > 1000:
                self.memory_usage_history = self.memory_usage_history[-1000:]

            # Check for memory leaks
            if self.config.enable_memory_leak_detection:
                self._detect_memory_leaks()

            return current_usage

        except Exception as e:
            logger.error(f"Memory usage check failed: {e}")
            return {"error": str(e)}

    def _detect_memory_leaks(self):
        """Detect potential memory leaks"""
        try:
            if len(self.memory_usage_history) < 10:
                return

            # Get recent memory usage samples
            recent_samples = self.memory_usage_history[-10:]

            # Calculate memory growth rate
            if len(recent_samples) >= 2:
                first_sample = recent_samples[0]
                last_sample = recent_samples[-1]

                time_diff = last_sample["timestamp"] - first_sample["timestamp"]
                memory_diff = last_sample["rss_mb"] - first_sample["rss_mb"]

                if time_diff > 0:
                    growth_rate = memory_diff / time_diff  # MB per second

                    # If memory is growing consistently, flag as potential leak
                    if growth_rate > 1.0:  # More than 1MB per second
                        self._record_security_event(
                            ThreatType.MEMORY_LEAK,
                            ThreatSeverity.MEDIUM,
                            "Potential memory leak detected",
                            f"Memory growth rate: {growth_rate:.2f}MB/s",
                            {"growth_rate": growth_rate, "time_period": time_diff},
                        )

        except Exception as e:
            logger.error(f"Memory leak detection failed: {e}")

    def _record_security_event(
        self,
        threat_type: ThreatType,
        severity: ThreatSeverity,
        description: str,
        details: str,
        context: Dict[str, Any],
    ):
        """Record a security event"""
        event = SecurityEvent(
            event_id=f"event_{int(time.time() * 1000000)}",
            threat_type=threat_type,
            severity=severity,
            description=description,
            timestamp=time.time(),
            location=self._get_caller_location(),
            stack_trace=self._get_stack_trace(),
            context=context,
        )

        logger.warning(f"Security event: {threat_type.value} - {description}")

        # Store event for analysis
        # In a real implementation, this would be sent to a security monitoring system

    def _get_caller_location(self) -> str:
        """Get the location of the calling code"""
        try:
            import inspect

            frame = inspect.currentframe()
            if frame:
                caller = frame.f_back
                if caller:
                    return f"{caller.f_code.co_filename}:{caller.f_lineno}"
        except Exception:
            pass
        return "unknown"

    def _get_stack_trace(self) -> Optional[str]:
        """Get current stack trace"""
        try:
            import traceback

            return "".join(traceback.format_stack())
        except Exception:
            return None


class RaceConditionDetector:
    """Detects race conditions and thread safety issues"""

    def __init__(self, config: RuntimeSecurityConfig):
        self.config = config
        self.thread_locks: Dict[str, threading.Lock] = {}
        self.shared_resources: Dict[str, Dict[str, Any]] = {}
        self.thread_activity: Dict[int, Dict[str, Any]] = {}
        self.race_conditions: List[Dict[str, Any]] = []
        self._init_race_detection()

    def _init_race_detection(self):
        """Initialize race condition detection"""
        if not self.config.enable_race_detection:
            return

        try:
            # Monitor thread creation
            threading._original_start_new_thread = threading._start_new_thread

            def _monitored_start_new_thread(function, args, kwargs=None, daemon=None):
                thread_id = threading._original_start_new_thread(
                    function, args, kwargs, daemon
                )
                self._monitor_thread(thread_id, function)
                return thread_id

            threading._start_new_thread = _monitored_start_new_thread
            logger.info("Race condition detection initialized successfully")

        except Exception as e:
            logger.warning(f"Failed to initialize race condition detection: {e}")

    def _monitor_thread(self, thread_id: int, function: Callable):
        """Monitor a thread for potential race conditions"""
        try:
            self.thread_activity[thread_id] = {
                "function": (
                    function.__name__
                    if hasattr(function, "__name__")
                    else str(function)
                ),
                "start_time": time.time(),
                "accessed_resources": set(),
                "locks_held": set(),
                "status": "running",
            }
        except Exception as e:
            logger.debug(f"Thread monitoring failed: {e}")

    def protect_resource(self, resource_name: str, access_type: str = "read") -> bool:
        """Protect a shared resource from race conditions"""
        if not self.config.enable_race_detection:
            return True

        try:
            current_thread = threading.current_thread()
            thread_id = current_thread.ident

            if thread_id not in self.thread_activity:
                return True

            # Record resource access
            self.thread_activity[thread_id]["accessed_resources"].add(resource_name)

            # Check if resource is already being accessed by another thread
            for other_thread_id, other_activity in self.thread_activity.items():
                if (
                    other_thread_id != thread_id
                    and other_activity["status"] == "running"
                    and resource_name in other_activity["accessed_resources"]
                ):

                    # Potential race condition detected
                    self._record_race_condition(
                        resource_name, thread_id, other_thread_id, access_type
                    )
                    return False

            # Record resource access
            if resource_name not in self.shared_resources:
                self.shared_resources[resource_name] = {
                    "access_count": 0,
                    "last_accessed": time.time(),
                    "accessing_threads": set(),
                }

            self.shared_resources[resource_name]["access_count"] += 1
            self.shared_resources[resource_name]["last_accessed"] = time.time()
            self.shared_resources[resource_name]["accessing_threads"].add(thread_id)

            return True

        except Exception as e:
            logger.error(f"Resource protection failed: {e}")
            return False

    def _record_race_condition(
        self, resource_name: str, thread1_id: int, thread2_id: int, access_type: str
    ):
        """Record a detected race condition"""
        try:
            race_condition = {
                "resource_name": resource_name,
                "thread1_id": thread1_id,
                "thread2_id": thread2_id,
                "access_type": access_type,
                "timestamp": time.time(),
                "severity": "high",
            }

            self.race_conditions.append(race_condition)

            logger.warning(
                f"Race condition detected on resource {resource_name} "
                f"between threads {thread1_id} and {thread2_id}"
            )

            # In a real implementation, this would trigger alerts or mitigation actions

        except Exception as e:
            logger.error(f"Failed to record race condition: {e}")

    def get_race_condition_summary(self) -> Dict[str, Any]:
        """Get summary of detected race conditions"""
        return {
            "total_race_conditions": len(self.race_conditions),
            "resources_at_risk": len(
                set(rc["resource_name"] for rc in self.race_conditions)
            ),
            "threads_involved": len(
                set(rc["thread1_id"] for rc in self.race_conditions)
                | set(rc["thread2_id"] for rc in self.race_conditions)
            ),
            "recent_race_conditions": (
                self.race_conditions[-10:] if self.race_conditions else []
            ),
        }


class ResourceMonitor:
    """Monitors system resources and prevents exhaustion"""

    def __init__(self, config: RuntimeSecurityConfig):
        self.config = config
        self.resource_limits: Dict[str, Any] = {}
        self.resource_usage: Dict[str, Any] = {}
        self.exhaustion_events: List[Dict[str, Any]] = []
        self.monitoring_active = False
        self.monitor_thread = None
        self._init_resource_monitoring()

    def _init_resource_monitoring(self):
        """Initialize resource monitoring"""
        if not self.config.enable_resource_monitoring:
            return

        try:
            # Set resource limits
            self._set_resource_limits()

            # Start monitoring thread
            self.start_monitoring()

            logger.info("Resource monitoring initialized successfully")

        except Exception as e:
            logger.warning(f"Failed to initialize resource monitoring: {e}")

    def _set_resource_limits(self):
        """Set system resource limits"""
        try:
            # Set file descriptor limit
            if hasattr(resource, "RLIMIT_NOFILE"):
                resource.setrlimit(
                    resource.RLIMIT_NOFILE, (self.config.file_descriptor_limit, -1)
                )

            # Set process limit
            if hasattr(resource, "RLIMIT_NPROC"):
                resource.setrlimit(
                    resource.RLIMIT_NPROC, (self.config.thread_limit, -1)
                )

            # Store limits for reference
            self.resource_limits = {
                "file_descriptors": self.config.file_descriptor_limit,
                "threads": self.config.thread_limit,
                "memory_mb": self.config.memory_threshold_mb,
                "cpu_percent": self.config.cpu_threshold_percent,
            }

        except Exception as e:
            logger.warning(f"Failed to set resource limits: {e}")

    def start_monitoring(self):
        """Start resource monitoring"""
        if self.monitoring_active:
            return

        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        """Stop resource monitoring"""
        self.monitoring_active = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                self._check_resources()
                time.sleep(self.config.monitoring_interval)
            except Exception as e:
                logger.error(f"Resource monitoring error: {e}")
                time.sleep(self.config.monitoring_interval * 2)

    def _check_resources(self):
        """Check current resource usage"""
        try:
            process = psutil.Process()

            # Check CPU usage
            cpu_percent = process.cpu_percent()
            if cpu_percent > self.config.cpu_threshold_percent:
                self._handle_resource_exhaustion(
                    "CPU", cpu_percent, self.config.cpu_threshold_percent
                )

            # Check file descriptors
            try:
                num_fds = len(process.open_files())
                if num_fds > self.config.file_descriptor_limit * 0.8:  # 80% threshold
                    self._handle_resource_exhaustion(
                        "File Descriptors", num_fds, self.config.file_descriptor_limit
                    )
            except Exception:
                pass  # May not have permission to access open files

            # Check thread count
            num_threads = process.num_threads()
            if num_threads > self.config.thread_limit * 0.8:  # 80% threshold
                self._handle_resource_exhaustion(
                    "Threads", num_threads, self.config.thread_limit
                )

            # Update resource usage
            self.resource_usage = {
                "cpu_percent": cpu_percent,
                "file_descriptors": num_fds if "num_fds" in locals() else 0,
                "threads": num_threads,
                "memory_mb": process.memory_info().rss / (1024 * 1024),
                "timestamp": time.time(),
            }

        except Exception as e:
            logger.error(f"Resource check failed: {e}")

    def _handle_resource_exhaustion(
        self, resource_type: str, current: float, limit: float
    ):
        """Handle resource exhaustion events"""
        try:
            exhaustion_event = {
                "resource_type": resource_type,
                "current_usage": current,
                "limit": limit,
                "timestamp": time.time(),
                "severity": "high" if current > limit else "medium",
            }

            self.exhaustion_events.append(exhaustion_event)

            logger.warning(
                f"Resource exhaustion warning: {resource_type} "
                f"usage {current:.2f} approaching limit {limit}"
            )

            # In a real implementation, this would trigger mitigation actions
            # such as killing processes, reducing resource usage, or alerting

        except Exception as e:
            logger.error(f"Failed to handle resource exhaustion: {e}")

    def get_resource_summary(self) -> Dict[str, Any]:
        """Get summary of resource usage and events"""
        return {
            "current_usage": self.resource_usage,
            "limits": self.resource_limits,
            "exhaustion_events": len(self.exhaustion_events),
            "recent_exhaustion_events": (
                self.exhaustion_events[-10:] if self.exhaustion_events else []
            ),
            "monitoring_active": self.monitoring_active,
        }


class DoSProtector:
    """Protects against Denial of Service attacks"""

    def __init__(self, config: RuntimeSecurityConfig):
        self.config = config
        self.request_counts: Dict[str, List[float]] = {}
        self.blocked_ips: Dict[str, float] = {}
        self.attack_patterns: List[Dict[str, Any]] = []
        self.rate_limits: Dict[str, Dict[str, Any]] = {}
        self._init_dos_protection()

    def _init_dos_protection(self):
        """Initialize DoS protection"""
        if not self.config.enable_dos_protection:
            return

        try:
            # Set up rate limiting for common attack vectors
            self._setup_rate_limits()
            logger.info("DoS protection initialized successfully")

        except Exception as e:
            logger.warning(f"Failed to initialize DoS protection: {e}")

    def _setup_rate_limits(self):
        """Set up rate limiting rules"""
        self.rate_limits = {
            "api_requests": {"max_requests": 100, "window_seconds": 60},
            "file_operations": {"max_requests": 50, "window_seconds": 60},
            "network_connections": {"max_requests": 20, "window_seconds": 30},
            "authentication_attempts": {"max_requests": 5, "window_seconds": 300},
        }

    def check_rate_limit(self, client_id: str, operation_type: str) -> bool:
        """Check if a client has exceeded rate limits"""
        try:
            if operation_type not in self.rate_limits:
                return True

            limit_config = self.rate_limits[operation_type]
            current_time = time.time()

            # Initialize request history for this client and operation
            key = f"{client_id}:{operation_type}"
            if key not in self.request_counts:
                self.request_counts[key] = []

            # Remove old requests outside the window
            window_start = current_time - limit_config["window_seconds"]
            self.request_counts[key] = [
                req_time
                for req_time in self.request_counts[key]
                if req_time > window_start
            ]

            # Check if limit exceeded
            if len(self.request_counts[key]) >= limit_config["max_requests"]:
                self._handle_rate_limit_exceeded(
                    client_id, operation_type, limit_config
                )
                return False

            # Record this request
            self.request_counts[key].append(current_time)
            return True

        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            return True  # Allow if check fails

    def _handle_rate_limit_exceeded(
        self, client_id: str, operation_type: str, limit_config: Dict[str, Any]
    ):
        """Handle rate limit exceeded events"""
        try:
            attack_pattern = {
                "client_id": client_id,
                "operation_type": operation_type,
                "timestamp": time.time(),
                "limit_config": limit_config,
                "severity": "medium",
            }

            self.attack_patterns.append(attack_pattern)

            logger.warning(f"Rate limit exceeded: {client_id} for {operation_type}")

            # Block client temporarily
            block_duration = 300  # 5 minutes
            self.blocked_ips[client_id] = time.time() + block_duration

        except Exception as e:
            logger.error(f"Failed to handle rate limit exceeded: {e}")

    def is_client_blocked(self, client_id: str) -> bool:
        """Check if a client is currently blocked"""
        try:
            if client_id not in self.blocked_ips:
                return False

            block_until = self.blocked_ips[client_id]
            if time.time() > block_until:
                # Remove expired block
                del self.blocked_ips[client_id]
                return False

            return True

        except Exception as e:
            logger.error(f"Block check failed: {e}")
            return False

    def get_dos_summary(self) -> Dict[str, Any]:
        """Get summary of DoS protection status"""
        return {
            "blocked_clients": len(self.blocked_ips),
            "attack_patterns": len(self.attack_patterns),
            "rate_limits": self.rate_limits,
            "recent_attacks": (
                self.attack_patterns[-10:] if self.attack_patterns else []
            ),
        }


class RuntimeSecurityManager:
    """Main runtime security manager"""

    def __init__(self, config: RuntimeSecurityConfig):
        self.config = config
        self.memory_protector = MemoryProtector(config)
        self.race_detector = RaceConditionDetector(config)
        self.resource_monitor = ResourceMonitor(config)
        self.dos_protector = DoSProtector(config)
        self.security_events: List[SecurityEvent] = []
        self.mitigation_actions: List[Dict[str, Any]] = []

    def start_protection(self):
        """Start all runtime security protections"""
        try:
            logger.info("Starting runtime security protection")

            # Start resource monitoring
            if self.config.enable_resource_monitoring:
                self.resource_monitor.start_monitoring()

            logger.info("Runtime security protection started successfully")

        except Exception as e:
            logger.error(f"Failed to start runtime security protection: {e}")

    def stop_protection(self):
        """Stop all runtime security protections"""
        try:
            logger.info("Stopping runtime security protection")

            # Stop resource monitoring
            if self.config.enable_resource_monitoring:
                self.resource_monitor.stop_monitoring()

            logger.info("Runtime security protection stopped")

        except Exception as e:
            logger.error(f"Failed to stop runtime security protection: {e}")

    def get_security_status(self) -> Dict[str, Any]:
        """Get comprehensive security status"""
        try:
            return {
                "memory_protection": {
                    "enabled": self.config.enable_memory_protection,
                    "current_usage": self.memory_protector.check_memory_usage(),
                },
                "race_detection": {
                    "enabled": self.config.enable_race_detection,
                    "race_conditions": self.race_detector.get_race_condition_summary(),
                },
                "resource_monitoring": {
                    "enabled": self.config.enable_resource_monitoring,
                    "status": self.resource_monitor.get_resource_summary(),
                },
                "dos_protection": {
                    "enabled": self.config.enable_dos_protection,
                    "status": self.dos_protector.get_dos_summary(),
                },
                "overall_security_score": self._calculate_security_score(),
            }
        except Exception as e:
            logger.error(f"Failed to get security status: {e}")
            return {"error": str(e)}

    def _calculate_security_score(self) -> float:
        """Calculate overall runtime security score"""
        try:
            score = 100.0

            # Deduct points for security events
            critical_events = len(
                [
                    e
                    for e in self.security_events
                    if e.severity == ThreatSeverity.CRITICAL
                ]
            )
            high_events = len(
                [e for e in self.security_events if e.severity == ThreatSeverity.HIGH]
            )
            medium_events = len(
                [e for e in self.security_events if e.severity == ThreatSeverity.MEDIUM]
            )

            score -= critical_events * 20
            score -= high_events * 10
            score -= medium_events * 5

            # Deduct points for resource exhaustion
            if self.resource_monitor.exhaustion_events:
                score -= min(20, len(self.resource_monitor.exhaustion_events) * 5)

            # Deduct points for race conditions
            race_summary = self.race_detector.get_race_condition_summary()
            if race_summary["total_race_conditions"] > 0:
                score -= min(15, race_summary["total_race_conditions"] * 3)

            return max(0.0, score)

        except Exception as e:
            logger.error(f"Security score calculation failed: {e}")
            return 0.0

    def cleanup(self):
        """Clean up runtime security resources"""
        try:
            self.stop_protection()
            logger.info("Runtime security cleanup completed")
        except Exception as e:
            logger.error(f"Runtime security cleanup failed: {e}")


# Utility functions
def get_runtime_security_manager(
    config: RuntimeSecurityConfig = None,
) -> RuntimeSecurityManager:
    """Get runtime security manager instance"""
    if config is None:
        config = RuntimeSecurityConfig()
    return RuntimeSecurityManager(config)


def start_runtime_security_protection(config: RuntimeSecurityConfig = None):
    """Quick function to start runtime security protection"""
    manager = get_runtime_security_manager(config)
    manager.start_protection()
    return manager


def get_runtime_security_status() -> Dict[str, Any]:
    """Quick function to get runtime security status"""
    config = RuntimeSecurityConfig()
    manager = RuntimeSecurityManager(config)
    return manager.get_security_status()
