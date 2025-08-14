"""
Advanced Container Security & Sandboxing Module

This module provides comprehensive container security features including:
- Container security scanning and vulnerability assessment
- Runtime protection with seccomp, AppArmor, and SELinux
- Resource limits and isolation
- Secure base image validation
- Zero-trust container execution
- Advanced threat detection and response
"""

import os
import json
import tempfile
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any
import docker
from docker.errors import DockerException
import time
import asyncio
import threading


logger = logging.getLogger(__name__)


class SecurityLevel(Enum):
    """Container security levels"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    PARANOID = "paranoid"


class IsolationType(Enum):
    """Container isolation types"""

    NONE = "none"
    BASIC = "basic"
    ENHANCED = "enhanced"
    MAXIMUM = "maximum"


class ThreatLevel(Enum):
    """Threat levels for security events"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ResourceLimits:
    """Resource limits for containers"""

    memory_mb: int = 512
    cpu_quota: int = 50000  # microseconds
    cpu_period: int = 100000  # microseconds
    network_bandwidth_mbps: int = 100
    disk_read_mbps: int = 50
    disk_write_mbps: int = 50
    max_processes: int = 100
    max_file_descriptors: int = 1024
    max_open_files: int = 1000
    max_network_connections: int = 50
    max_socket_connections: int = 100


@dataclass
class SecurityProfile:
    """Security profile configuration"""

    seccomp_profile: Optional[str] = None
    apparmor_profile: Optional[str] = None
    selinux_policy: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)
    read_only_root: bool = True
    no_new_privileges: bool = True
    user_namespace: bool = True
    network_namespace: bool = True
    pid_namespace: bool = True
    uts_namespace: bool = True
    mount_namespace: bool = True
    ipc_namespace: bool = True
    seccomp_audit: bool = True
    apparmor_audit: bool = True


@dataclass
class ThreatDetectionConfig:
    """Threat detection configuration"""

    enable_behavioral_analysis: bool = True
    enable_network_analysis: bool = True
    enable_file_activity_monitoring: bool = True
    enable_process_monitoring: bool = True
    suspicious_patterns: List[str] = field(
        default_factory=lambda: [
            "rm -rf /",
            "dd if=/dev/zero",
            "format c:",
            "del /s /q",
        ]
    )
    network_blacklist: List[str] = field(
        default_factory=lambda: ["tor2web.org", "anonymous-proxy.com"]
    )
    file_extensions_blacklist: List[str] = field(
        default_factory=lambda: [".exe", ".bat", ".cmd", ".scr", ".pif"]
    )


@dataclass
class ContainerSecurityConfig:
    """Container security configuration"""

    security_level: SecurityLevel = SecurityLevel.HIGH
    isolation_type: IsolationType = IsolationType.ENHANCED
    resource_limits: ResourceLimits = field(default_factory=ResourceLimits)
    security_profile: SecurityProfile = field(default_factory=SecurityProfile)
    threat_detection: ThreatDetectionConfig = field(
        default_factory=ThreatDetectionConfig
    )
    enable_scanning: bool = True
    enable_runtime_protection: bool = True
    enable_resource_monitoring: bool = True
    enable_threat_detection: bool = True
    allow_privileged: bool = False
    allow_host_network: bool = False
    allow_host_pid: bool = False
    allow_host_uts: bool = False
    allow_host_mount: bool = False
    allow_host_ipc: bool = False
    scan_timeout: int = 300  # seconds
    max_scan_retries: int = 3


class AdvancedContainerScanner:
    """Advanced container security scanner with multiple scanning engines"""

    def __init__(self, config: ContainerSecurityConfig):
        self.config = config
        self.scan_cache: Dict[str, Dict[str, Any]] = {}
        self.vulnerability_db = None
        self._init_vulnerability_database()

    def _init_vulnerability_database(self):
        """Initialize vulnerability database"""
        try:
            # Try to use local vulnerability database
            db_path = Path("/var/lib/trivy/db/trivy.db")
            if db_path.exists():
                self.vulnerability_db = str(db_path)
                logger.info("Using local Trivy vulnerability database")
            else:
                logger.info("No local vulnerability database found, will use remote")
        except Exception as e:
            logger.warning(f"Failed to initialize vulnerability database: {e}")

    async def scan_image_async(self, image_name: str) -> Dict[str, Any]:
        """Asynchronously scan container image for vulnerabilities"""
        try:
            # Check cache first
            cache_key = f"{image_name}_{hash(self.config.security_level)}"
            if cache_key in self.scan_cache:
                cached_result = self.scan_cache[cache_key]
                # 1 hour cache
                if time.time() - cached_result.get("timestamp", 0) < 3600:
                    return cached_result

            # Run multiple scanning engines in parallel
            scan_tasks = [
                self._scan_with_trivy(image_name),
                self._scan_with_clair(image_name),
                self._scan_with_docker_bench(image_name),
                self._analyze_image_layers(image_name),
            ]

            results = await asyncio.gather(*scan_tasks, return_exceptions=True)

            # Combine results
            combined_result = self._combine_scan_results(results)
            combined_result["timestamp"] = time.time()

            # Cache result
            self.scan_cache[cache_key] = combined_result

            return combined_result

        except Exception as e:
            logger.error(f"Failed to scan image {image_name}: {e}")
            return {"error": str(e), "image": image_name}

    async def _scan_with_trivy(self, image_name: str) -> Dict[str, Any]:
        """Scan image using Trivy"""
        try:
            cmd = [
                "trivy",
                "image",
                "--format",
                "json",
                "--quiet",
                "--timeout",
                str(self.config.scan_timeout),
            ]

            if self.vulnerability_db:
                cmd.extend(["--db-path", self.vulnerability_db])

            cmd.append(image_name)

            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.config.scan_timeout
            )

            if process.returncode == 0:
                result = json.loads(stdout.decode())
                return {
                    "scanner": "trivy",
                    "vulnerabilities": result.get("Vulnerabilities", []),
                    "success": True,
                }
            else:
                return {"scanner": "trivy", "error": stderr.decode(), "success": False}

        except Exception as e:
            return {"scanner": "trivy", "error": str(e), "success": False}

    async def _scan_with_clair(self, image_name: str) -> Dict[str, Any]:
        """Scan image using Clair"""
        try:
            # This would integrate with a Clair server
            # For now, return a placeholder
            return {
                "scanner": "clair",
                "vulnerabilities": [],
                "success": True,
                "note": "Clair integration not yet implemented",
            }
        except Exception as e:
            return {"scanner": "clair", "error": str(e), "success": False}

    async def _scan_with_docker_bench(self, image_name: str) -> Dict[str, Any]:
        """Run Docker Bench Security checks"""
        try:
            cmd = ["docker-bench-security", "--json", "--no-benchmark"]

            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)

            if process.returncode == 0:
                result = json.loads(stdout.decode())
                return {
                    "scanner": "docker-bench",
                    "checks": result.get("checks", []),
                    "success": True,
                }
            else:
                return {
                    "scanner": "docker-bench",
                    "error": stderr.decode(),
                    "success": False,
                }

        except Exception as e:
            return {"scanner": "docker-bench", "error": str(e), "success": False}

    async def _analyze_image_layers(self, image_name: str) -> Dict[str, Any]:
        """Analyze Docker image layers for security issues"""
        try:
            client = docker.from_env()
            image = client.images.get(image_name)

            analysis = {
                "scanner": "layer-analysis",
                "layers": [],
                "total_size": 0,
                "suspicious_files": [],
                "success": True,
            }

            for layer in image.history():
                layer_info = {
                    "id": layer.get("Id"),
                    "created": layer.get("Created"),
                    "size": layer.get("Size", 0),
                    "comment": layer.get("Comment", ""),
                    "created_by": layer.get("CreatedBy", ""),
                }
                analysis["layers"].append(layer_info)
                analysis["total_size"] += layer_info["size"]

                # Check for suspicious patterns in layer commands
                if any(
                    pattern in layer_info["created_by"].lower()
                    for pattern in ["curl", "wget", "chmod +x", "rm -rf"]
                ):
                    analysis["suspicious_files"].append(layer_info)

            return analysis

        except Exception as e:
            return {"scanner": "layer-analysis", "error": str(e), "success": False}

    def _combine_scan_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Combine results from multiple scanning engines"""
        combined = {
            "image_scanned": True,
            "scanners_used": [],
            "total_vulnerabilities": 0,
            "critical_vulnerabilities": 0,
            "high_vulnerabilities": 0,
            "medium_vulnerabilities": 0,
            "low_vulnerabilities": 0,
            "security_score": 100,
            "recommendations": [],
            "scan_details": {},
        }

        for result in results:
            if isinstance(result, Exception):
                combined["scan_details"]["error"] = str(result)
                continue

            if result.get("success"):
                combined["scanners_used"].append(result["scanner"])
                combined["scan_details"][result["scanner"]] = result

                # Count vulnerabilities
                if "vulnerabilities" in result:
                    for vuln in result["vulnerabilities"]:
                        severity = vuln.get("Severity", "UNKNOWN").upper()
                        if severity == "CRITICAL":
                            combined["critical_vulnerabilities"] += 1
                        elif severity == "HIGH":
                            combined["high_vulnerabilities"] += 1
                        elif severity == "MEDIUM":
                            combined["medium_vulnerabilities"] += 1
                        elif severity == "LOW":
                            combined["low_vulnerabilities"] += 1

                combined["total_vulnerabilities"] = (
                    combined["critical_vulnerabilities"]
                    + combined["high_vulnerabilities"]
                    + combined["medium_vulnerabilities"]
                    + combined["low_vulnerabilities"]
                )

        # Calculate security score
        combined["security_score"] = max(
            0,
            100
            - (
                combined["critical_vulnerabilities"] * 20
                + combined["high_vulnerabilities"] * 10
                + combined["medium_vulnerabilities"] * 5
                + combined["low_vulnerabilities"] * 1
            ),
        )

        # Generate recommendations
        if combined["critical_vulnerabilities"] > 0:
            combined["recommendations"].append(
                "Critical vulnerabilities detected. Do not deploy this image."
            )
        if combined["high_vulnerabilities"] > 5:
            combined["recommendations"].append(
                "High number of high-severity vulnerabilities. "
                "Consider updating base image."
            )
        if combined["total_vulnerabilities"] > 50:
            combined["recommendations"].append(
                "High total vulnerability count. "
                "Comprehensive security review recommended."
            )

        return combined


class SecurityProfileGenerator:
    """Generate security profiles for containers"""

    def __init__(self, config: ContainerSecurityConfig):
        self.config = config

    def generate_seccomp_profile(self, security_level: SecurityLevel) -> str:
        """Generate seccomp profile based on security level"""
        if security_level == SecurityLevel.LOW:
            return self._generate_basic_seccomp_profile()
        elif security_level == SecurityLevel.MEDIUM:
            return self._generate_medium_seccomp_profile()
        elif security_level == SecurityLevel.HIGH:
            return self._generate_high_seccomp_profile()
        else:  # PARANOID
            return self._generate_paranoid_seccomp_profile()

    def _generate_basic_seccomp_profile(self) -> str:
        """Generate basic seccomp profile"""
        return json.dumps(
            {
                "defaultAction": "SCMP_ACT_ERRNO",
                "architectures": [
                    "SCMP_ARCH_X86_64",
                    "SCMP_ARCH_X86",
                    "SCMP_ARCH_AARCH64",
                ],
                "syscalls": [
                    {
                        "names": ["read", "write", "exit", "exit_group"],
                        "action": "SCMP_ACT_ALLOW",
                    },
                    {
                        "names": ["open", "close", "fstat", "lstat"],
                        "action": "SCMP_ACT_ALLOW",
                    },
                    {
                        "names": ["mmap", "mprotect", "munmap"],
                        "action": "SCMP_ACT_ALLOW",
                    },
                    {
                        "names": ["brk", "rt_sigaction", "rt_sigprocmask"],
                        "action": "SCMP_ACT_ALLOW",
                    },
                    {"names": ["clone", "execve", "wait4"], "action": "SCMP_ACT_ALLOW"},
                ],
            },
            indent=2,
        )

    def _generate_medium_seccomp_profile(self) -> str:
        """Generate medium security seccomp profile"""
        profile = self._generate_basic_seccomp_profile()
        profile_data = json.loads(profile)

        # Add more restricted syscalls
        additional_syscalls = [
            {
                "names": ["socket", "connect", "bind", "listen"],
                "action": "SCMP_ACT_ALLOW",
            },
            {"names": ["accept", "accept4", "getsockname"], "action": "SCMP_ACT_ALLOW"},
            {"names": ["fcntl", "dup", "dup2", "dup3"], "action": "SCMP_ACT_ALLOW"},
        ]
        profile_data["syscalls"].extend(additional_syscalls)

        return json.dumps(profile_data, indent=2)

    def _generate_high_seccomp_profile(self) -> str:
        """Generate high security seccomp profile"""
        profile = self._generate_medium_seccomp_profile()
        profile_data = json.loads(profile)

        # Remove potentially dangerous syscalls
        dangerous_syscalls = ["ptrace", "personality", "setuid", "setgid"]
        profile_data["syscalls"] = [
            syscall
            for syscall in profile_data["syscalls"]
            if not any(dangerous in str(syscall) for dangerous in dangerous_syscalls)
        ]

        return json.dumps(profile_data, indent=2)

    def _generate_paranoid_seccomp_profile(self) -> str:
        """Generate paranoid security seccomp profile"""
        profile = self._generate_high_seccomp_profile()
        profile_data = json.loads(profile)

        # Only allow essential syscalls
        essential_syscalls = [
            {
                "names": ["read", "write", "exit", "exit_group"],
                "action": "SCMP_ACT_ALLOW",
            },
            {"names": ["open", "close"], "action": "SCMP_ACT_ALLOW"},
            {"names": ["mmap", "munmap"], "action": "SCMP_ACT_ALLOW"},
            {"names": ["brk", "rt_sigaction"], "action": "SCMP_ACT_ALLOW"},
        ]
        profile_data["syscalls"] = essential_syscalls

        return json.dumps(profile_data, indent=2)

    def generate_apparmor_profile(self, security_level: SecurityLevel) -> str:
        """Generate AppArmor profile"""
        if security_level == SecurityLevel.LOW:
            return self._generate_basic_apparmor_profile()
        else:
            return self._generate_restrictive_apparmor_profile()

    def _generate_basic_apparmor_profile(self) -> str:
        """Generate basic AppArmor profile"""
        return """
#include <tunables/global>

profile morphcloud-basic flags=(attach_disconnected,mediate_deleted) {
    #include <abstractions/base>
    #include <abstractions/python>
    
    # Allow basic file operations
    /tmp/** rw,
    /var/tmp/** rw,
    
    # Allow network access
    network inet tcp,
    network inet udp,
    
    # Deny dangerous operations
    deny /proc/sys/** wl,
    deny /sys/** wl,
    deny /dev/** wl,
}
"""

    def _generate_restrictive_apparmor_profile(self) -> str:
        """Generate restrictive AppArmor profile"""
        return """
#include <tunables/global>

profile morphcloud-restrictive flags=(attach_disconnected,mediate_deleted) {
    #include <abstractions/base>
    
    # Very limited file access
    /tmp/morphcloud-*/** rw,
    
    # Limited network access
    network inet tcp,
    
    # Deny most operations
    deny /proc/** rwl,
    deny /sys/** rwl,
    deny /dev/** rwl,
    deny /home/** rwl,
    deny /root/** rwl,
    deny /etc/** rwl,
    deny /var/** rwl,
    deny /usr/** rwl,
    deny /bin/** rwl,
    deny /sbin/** rwl,
}
"""


class ResourceMonitor:
    """Monitor container resource usage and enforce limits"""

    def __init__(self, config: ContainerSecurityConfig):
        self.config = config
        self.active_containers: Dict[str, Dict[str, Any]] = {}

    def start_monitoring(self, container_id: str, limits: ResourceLimits):
        """Start monitoring a container"""
        self.active_containers[container_id] = {
            "limits": limits,
            "start_time": time.time(),
            "violations": [],
            "current_usage": {},
        }
        logger.info(f"Started monitoring container: {container_id}")

    def stop_monitoring(self, container_id: str):
        """Stop monitoring a container"""
        if container_id in self.active_containers:
            del self.active_containers[container_id]
            logger.info(f"Stopped monitoring container: {container_id}")

    def check_resource_usage(self, container_id: str) -> Dict[str, Any]:
        """Check current resource usage for a container"""
        if container_id not in self.active_containers:
            return {"error": "Container not being monitored"}

        try:
            # Get container stats from Docker
            client = docker.from_env()
            container = client.containers.get(container_id)
            stats = container.stats(stream=False)

            # Parse stats
            cpu_usage = self._parse_cpu_stats(stats)
            memory_usage = self._parse_memory_stats(stats)
            network_usage = self._parse_network_stats(stats)

            # Check against limits
            violations = self._check_limits(
                container_id, cpu_usage, memory_usage, network_usage
            )

            # Update current usage
            self.active_containers[container_id]["current_usage"] = {
                "cpu": cpu_usage,
                "memory": memory_usage,
                "network": network_usage,
            }

            return {
                "container_id": container_id,
                "usage": {
                    "cpu": cpu_usage,
                    "memory": memory_usage,
                    "network": network_usage,
                },
                "violations": violations,
                "within_limits": len(violations) == 0,
            }

        except Exception as e:
            logger.error(f"Failed to check resource usage: {e}")
            return {"error": str(e)}

    def _parse_cpu_stats(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        """Parse CPU statistics"""
        cpu_stats = stats.get("cpu_stats", {})
        precpu_stats = stats.get("precpu_stats", {})

        cpu_delta = cpu_stats.get("cpu_usage", {}).get(
            "total_usage", 0
        ) - precpu_stats.get("cpu_usage", {}).get("total_usage", 0)
        system_delta = cpu_stats.get("system_cpu_usage", 0) - precpu_stats.get(
            "system_cpu_usage", 0
        )

        cpu_percent = 0.0
        if system_delta > 0:
            cpu_percent = (cpu_delta / system_delta) * 100.0

        return {
            "usage_percent": cpu_percent,
            "total_usage": cpu_stats.get("cpu_usage", {}).get("total_usage", 0),
        }

    def _parse_memory_stats(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        """Parse memory statistics"""
        memory_stats = stats.get("memory_stats", {})

        return {
            "usage_bytes": memory_stats.get("usage", 0),
            "max_usage_bytes": memory_stats.get("max_usage", 0),
            "limit_bytes": memory_stats.get("limit", 0),
        }

    def _parse_network_stats(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        """Parse network statistics"""
        networks = stats.get("networks", {})

        total_rx = sum(net.get("rx_bytes", 0) for net in networks.values())
        total_tx = sum(net.get("tx_bytes", 0) for net in networks.values())

        return {
            "rx_bytes": total_rx,
            "tx_bytes": total_tx,
            "rx_packets": sum(net.get("rx_packets", 0) for net in networks.values()),
            "tx_packets": sum(net.get("tx_packets", 0) for net in networks.values()),
        }

    def _check_limits(
        self,
        container_id: str,
        cpu_usage: Dict[str, Any],
        memory_usage: Dict[str, Any],
        network_usage: Dict[str, Any],
    ) -> List[str]:
        """Check resource usage against limits"""
        violations = []
        container_info = self.active_containers[container_id]
        limits = container_info["limits"]

        # Check CPU usage
        if cpu_usage["usage_percent"] > (limits.cpu_quota / limits.cpu_period * 100):
            violations.append("CPU usage exceeds limit")

        # Check memory usage
        if memory_usage["usage_bytes"] > (limits.memory_mb * 1024 * 1024):
            violations.append("Memory usage exceeds limit")

        # Check network bandwidth (simplified)
        # This would need more sophisticated monitoring for real-time bandwidth

        # Record violations
        if violations:
            container_info["violations"].extend(violations)
            logger.warning(
                f"Container {container_id} resource violations: {violations}"
            )

        return violations


class RuntimeProtection:
    """Runtime protection and monitoring for containers"""

    def __init__(self, config: ContainerSecurityConfig):
        self.config = config
        self.active_containers: Dict[str, Dict[str, Any]] = {}
        self.threat_events: List[Dict[str, Any]] = []
        self.monitoring_thread = None
        self.stop_monitoring = False

    def start_protection(self, container_id: str):
        """Start runtime protection for a container"""
        if container_id in self.active_containers:
            logger.warning(f"Protection already active for container {container_id}")
            return

        self.active_containers[container_id] = {
            "start_time": time.time(),
            "threats_detected": [],
            "resource_violations": [],
            "network_activity": [],
            "file_activity": [],
            "process_activity": [],
        }

        logger.info(f"Started runtime protection for container {container_id}")

        # Start monitoring if not already running
        if not self.monitoring_thread or not self.monitoring_thread.is_alive():
            self._start_monitoring()

    def stop_protection(self, container_id: str):
        """Stop runtime protection for a container"""
        if container_id in self.active_containers:
            del self.active_containers[container_id]
            logger.info(f"Stopped runtime protection for container {container_id}")

    def _start_monitoring(self):
        """Start background monitoring thread"""
        self.stop_monitoring = False
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()

    def _monitoring_loop(self):
        """Main monitoring loop"""
        while not self.stop_monitoring:
            try:
                for container_id in list(self.active_containers.keys()):
                    self._check_container_security(container_id)
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(10)

    def _check_container_security(self, container_id: str):
        """Check security status of a specific container"""
        try:
            client = docker.from_env()
            container = client.containers.get(container_id)

            # Check process activity
            self._check_process_activity(container_id, container)

            # Check network activity
            self._check_network_activity(container_id, container)

            # Check file activity
            self._check_file_activity(container_id, container)

            # Check resource usage
            self._check_resource_usage(container_id, container)

        except Exception as e:
            logger.error(f"Failed to check container {container_id}: {e}")

    def _check_process_activity(self, container_id: str, container):
        """Check for suspicious process activity"""
        try:
            # Get container processes
            processes = container.top()

            for proc in processes.get("Processes", []):
                if len(proc) >= 8:
                    cmd = proc[7]

                    # Check for suspicious patterns
                    for pattern in self.config.threat_detection.suspicious_patterns:
                        if pattern.lower() in cmd.lower():
                            threat_event = {
                                "container_id": container_id,
                                "type": "suspicious_process",
                                "severity": ThreatLevel.HIGH,
                                "details": {
                                    "command": cmd,
                                    "pattern": pattern,
                                    "timestamp": time.time(),
                                },
                            }
                            self._record_threat_event(threat_event)

        except Exception as e:
            logger.debug(f"Failed to check process activity: {e}")

    def _check_network_activity(self, container_id: str, container):
        """Check for suspicious network activity"""
        try:
            # Get container network stats
            stats = container.stats(stream=False)
            networks = stats.get("networks", {})

            for network_name, network_stats in networks.items():
                # Check for unusual network activity
                rx_bytes = network_stats.get("rx_bytes", 0)
                tx_bytes = network_stats.get("tx_bytes", 0)

                # Record network activity
                self.active_containers[container_id]["network_activity"].append(
                    {
                        "timestamp": time.time(),
                        "network": network_name,
                        "rx_bytes": rx_bytes,
                        "tx_bytes": tx_bytes,
                    }
                )

                # Keep only last 100 entries
                if len(self.active_containers[container_id]["network_activity"]) > 100:
                    self.active_containers[container_id]["network_activity"] = (
                        self.active_containers[container_id]["network_activity"][-100:]
                    )

        except Exception as e:
            logger.debug(f"Failed to check network activity: {e}")

    def _check_file_activity(self, container_id: str, container):
        """Check for suspicious file activity"""
        try:
            # This would require more sophisticated file system monitoring
            # For now, we'll implement basic checks
            pass
        except Exception as e:
            logger.debug(f"Failed to check file activity: {e}")

    def _check_resource_usage(self, container_id: str, container):
        """Check resource usage for violations"""
        try:
            stats = container.stats(stream=False)

            # Check memory usage
            memory_stats = stats.get("memory_stats", {})
            memory_usage = memory_stats.get("usage", 0)
            memory_limit = memory_stats.get("limit", 0)

            if memory_limit > 0:
                memory_percent = (memory_usage / memory_limit) * 100
                if memory_percent > 90:
                    violation = {
                        "type": "memory_usage",
                        "current": memory_percent,
                        "limit": 90,
                        "timestamp": time.time(),
                    }
                    self.active_containers[container_id]["resource_violations"].append(
                        violation
                    )

        except Exception as e:
            logger.debug(f"Failed to check resource usage: {e}")

    def _record_threat_event(self, threat_event: Dict[str, Any]):
        """Record a threat event"""
        self.threat_events.append(threat_event)

        # Log the threat
        logger.warning(
            f"Threat detected in container {threat_event['container_id']}: "
            f"{threat_event['type']} - {threat_event['details']}"
        )

        # Keep only last 1000 events
        if len(self.threat_events) > 1000:
            self.threat_events = self.threat_events[-1000:]

    def get_security_status(self, container_id: str) -> Dict[str, Any]:
        """Get security status of a container"""
        if container_id not in self.active_containers:
            return {"error": "Container not being monitored"}

        container_info = self.active_containers[container_id]

        return {
            "container_id": container_id,
            "protection_active": True,
            "start_time": container_info["start_time"],
            "threats_detected": len(container_info["threats_detected"]),
            "resource_violations": len(container_info["resource_violations"]),
            "network_activity_count": len(container_info["network_activity"]),
            "file_activity_count": len(container_info["file_activity"]),
            "process_activity_count": len(container_info["process_activity"]),
            "uptime_seconds": time.time() - container_info["start_time"],
        }

    def get_threat_summary(self) -> Dict[str, Any]:
        """Get summary of all threat events"""
        threat_counts = {}
        for event in self.threat_events:
            event_type = event["type"]
            threat_counts[event_type] = threat_counts.get(event_type, 0) + 1

        return {
            "total_threats": len(self.threat_events),
            "threats_by_type": threat_counts,
            "recent_threats": self.threat_events[-10:] if self.threat_events else [],
        }

    def cleanup(self):
        """Clean up monitoring resources"""
        self.stop_monitoring = True
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5)


class ContainerSecurityManager:
    """Main container security manager"""

    def __init__(self, config: ContainerSecurityConfig):
        self.config = config
        self.scanner = AdvancedContainerScanner(config)
        self.profile_generator = SecurityProfileGenerator(config)
        self.resource_monitor = ResourceMonitor(config)
        self.runtime_protection = RuntimeProtection(config)
        self.docker_client = None
        self._init_docker_client()

    def _init_docker_client(self):
        """Initialize Docker client"""
        try:
            self.docker_client = docker.from_env()
        except DockerException as e:
            logger.warning(f"Failed to initialize Docker client: {e}")

    async def secure_container(
        self, image_name: str, container_name: str = None
    ) -> Dict[str, Any]:
        """Create a secure container with all security measures"""
        if not self.docker_client:
            return {"error": "Docker client not available"}

        try:
            # Scan image for vulnerabilities
            scan_result = await self.scanner.scan_image_async(image_name)
            if scan_result.get("error"):
                return scan_result

            # Check if image meets security requirements
            if scan_result.get("security_score", 0) < 70:
                return {
                    "error": "Image security score too low",
                    "score": scan_result.get("security_score"),
                    "recommendations": scan_result.get("recommendations", []),
                }

            # Generate security profiles
            seccomp_profile = self.profile_generator.generate_seccomp_profile(
                self.config.security_level
            )
            apparmor_profile = self.profile_generator.generate_apparmor_profile(
                self.config.security_level
            )

            # Create secure container
            container = self._create_secure_container(
                image_name, container_name, seccomp_profile, apparmor_profile
            )

            # Start resource monitoring
            self.resource_monitor.start_monitoring(
                container.id, self.config.resource_limits
            )

            # Start runtime protection
            self.runtime_protection.start_protection(container.id)

            return {
                "container_id": container.id,
                "container_name": container.name,
                "security_level": self.config.security_level.value,
                "scan_result": scan_result,
                "status": "created",
            }

        except Exception as e:
            logger.error(f"Failed to create secure container: {e}")
            return {"error": str(e)}

    def _create_secure_container(
        self,
        image_name: str,
        container_name: str,
        seccomp_profile: str,
        apparmor_profile: str,
    ):
        """Create container with security configurations"""
        # Write seccomp profile to temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(seccomp_profile)
            seccomp_file = f.name

        try:
            # Create container with security options
            container = self.docker_client.containers.run(
                image_name,
                name=container_name,
                detach=True,
                security_opt=[
                    f"seccomp={seccomp_file}",
                    f"apparmor={apparmor_profile}" if apparmor_profile else "",
                ],
                cap_drop=self.config.security_profile.capabilities,
                read_only=self.config.security_profile.read_only_root,
                security_opt=(
                    ["no-new-privileges"]
                    if self.config.security_profile.no_new_privileges
                    else []
                ),
                mem_limit=f"{self.config.resource_limits.memory_mb}m",
                cpu_quota=self.config.resource_limits.cpu_quota,
                cpu_period=self.config.resource_limits.cpu_period,
                pids_limit=self.config.resource_limits.max_processes,
                ulimits=[
                    docker.types.Ulimit(
                        name="nofile",
                        soft=self.config.resource_limits.max_open_files,
                        hard=self.config.resource_limits.max_open_files,
                    )
                ],
            )

            return container

        finally:
            # Clean up temporary file
            try:
                os.unlink(seccomp_file)
            except OSError:
                pass

    def get_container_security_status(self, container_id: str) -> Dict[str, Any]:
        """Get security status of a running container"""
        try:
            container = self.docker_client.containers.get(container_id)

            # Get resource usage
            resource_status = self.resource_monitor.check_resource_usage(container_id)

            # Get container info
            container_info = container.attrs

            return {
                "container_id": container_id,
                "status": container.status,
                "security_config": {
                    "security_level": self.config.security_level.value,
                    "isolation_type": self.config.isolation_type.value,
                },
                "resource_status": resource_status,
                "created": container_info.get("Created", ""),
                "image": container_info.get("Image", ""),
                "security_opt": container_info.get("HostConfig", {}).get(
                    "SecurityOpt", []
                ),
            }

        except Exception as e:
            logger.error(f"Failed to get container security status: {e}")
            return {"error": str(e)}

    def stop_container(self, container_id: str) -> Dict[str, Any]:
        """Stop and clean up a secure container"""
        try:
            # Stop resource monitoring
            self.resource_monitor.stop_monitoring(container_id)
            self.runtime_protection.stop_protection(container_id)

            # Stop container
            container = self.docker_client.containers.get(container_id)
            container.stop(timeout=30)
            container.remove()

            return {
                "container_id": container_id,
                "status": "stopped",
                "message": "Container stopped and removed successfully",
            }

        except Exception as e:
            logger.error(f"Failed to stop container {container_id}: {e}")
            return {"error": str(e)}


# Utility functions
def get_container_security_manager(
    config: ContainerSecurityConfig = None,
) -> ContainerSecurityManager:
    """Get container security manager instance"""
    if config is None:
        config = ContainerSecurityConfig()
    return ContainerSecurityManager(config)


def scan_image_security(image_name: str) -> Dict[str, Any]:
    """Quick function to scan image security"""
    config = ContainerSecurityConfig()
    scanner = AdvancedContainerScanner(config)
    return scanner.scan_image_async(image_name)


def create_secure_container(
    image_name: str,
    container_name: str = None,
    security_level: SecurityLevel = SecurityLevel.HIGH,
) -> Dict[str, Any]:
    """Quick function to create secure container"""
    config = ContainerSecurityConfig(security_level=security_level)
    manager = ContainerSecurityManager(config)
    return manager.secure_container(image_name, container_name)
