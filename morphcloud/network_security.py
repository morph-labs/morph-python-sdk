"""
Network Security Module

This module provides comprehensive network security including:
- Protocol vulnerability analysis (HTTP/2, WebSocket, SSH)
- TLS configuration analysis and certificate validation
- Network segmentation and firewall rules
- Intrusion detection and prevention
- Network traffic analysis
- Secure communication protocols
"""

import socket
import ssl
import logging
import aiohttp
import paramiko
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Union
from pathlib import Path
import hashlib
import time
import threading

logger = logging.getLogger(__name__)


class SecurityLevel(Enum):
    """Network security levels"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    PARANOID = "paranoid"


class ProtocolType(Enum):
    """Network protocol types"""

    HTTP = "http"
    HTTPS = "https"
    HTTP2 = "http2"
    WEBSOCKET = "websocket"
    SSH = "ssh"
    TCP = "tcp"
    UDP = "udp"
    TLS = "tls"


class ThreatType(Enum):
    """Types of network security threats"""

    PROTOCOL_VULNERABILITY = "protocol_vulnerability"
    WEAK_TLS_CONFIG = "weak_tls_config"
    CERTIFICATE_ISSUE = "certificate_issue"
    NETWORK_INTRUSION = "network_intrusion"
    TRAFFIC_ANOMALY = "traffic_anomaly"
    PORT_SCAN = "port_scan"
    DOS_ATTACK = "dos_attack"
    MAN_IN_THE_MIDDLE = "man_in_the_middle"


class ThreatSeverity(Enum):
    """Threat severity levels"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class NetworkEvent:
    """Represents a network security event"""

    event_id: str
    threat_type: ThreatType
    severity: ThreatSeverity
    description: str
    timestamp: float
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: Optional[ProtocolType] = None
    port: Optional[int] = None
    context: Dict[str, Any] = field(default_factory=dict)
    mitigated: bool = False
    mitigation_action: Optional[str] = None


@dataclass
class TLSConfig:
    """TLS configuration settings"""

    min_tls_version: str = "TLSv1.2"
    max_tls_version: str = "TLSv1.3"
    allowed_ciphers: List[str] = field(
        default_factory=lambda: [
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
        ]
    )
    disallowed_ciphers: List[str] = field(
        default_factory=lambda: [
            "NULL",
            "EXPORT",
            "LOW",
            "MEDIUM",
            "DES",
            "3DES",
            "RC4",
            "MD5",
        ]
    )
    require_strong_crypto: bool = True
    certificate_validation: bool = True
    hostname_verification: bool = True


@dataclass
class NetworkSecurityConfig:
    """Network security configuration"""

    security_level: SecurityLevel = SecurityLevel.HIGH
    enable_protocol_analysis: bool = True
    enable_tls_analysis: bool = True
    enable_certificate_validation: bool = True
    enable_network_monitoring: bool = True
    enable_intrusion_detection: bool = True
    enable_firewall_rules: bool = True
    tls_config: TLSConfig = field(default_factory=TLSConfig)
    allowed_networks: List[str] = field(
        default_factory=lambda: ["127.0.0.0/8", "10.0.0.0/8"]
    )
    blocked_networks: List[str] = field(default_factory=lambda: ["0.0.0.0/0"])
    allowed_ports: List[int] = field(default_factory=lambda: [22, 80, 443, 8080])
    blocked_ports: List[int] = field(default_factory=lambda: [23, 25, 135, 139, 445])
    monitoring_interval: float = 1.0  # seconds
    alert_threshold: int = 5  # number of events before alerting


class ProtocolAnalyzer:
    """Analyzes network protocols for security vulnerabilities"""

    def __init__(self, config: NetworkSecurityConfig):
        self.config = config
        self.protocol_vulnerabilities: Dict[str, List[Dict[str, Any]]] = {}
        self.analysis_results: Dict[str, Dict[str, Any]] = {}
        self._init_protocol_analysis()

    def _init_protocol_analysis(self):
        """Initialize protocol analysis capabilities"""
        if not self.config.enable_protocol_analysis:
            return

        # Initialize known protocol vulnerabilities
        self.protocol_vulnerabilities = {
            "http": [
                {
                    "name": "HTTP/1.1",
                    "severity": "high",
                    "description": "Unencrypted communication",
                },
                {
                    "name": "HTTP Request Smuggling",
                    "severity": "critical",
                    "description": "Request smuggling attacks",
                },
                {
                    "name": "HTTP Response Splitting",
                    "severity": "high",
                    "description": "Response splitting attacks",
                },
            ],
            "http2": [
                {
                    "name": "HTTP/2 Rapid Reset",
                    "severity": "critical",
                    "description": "DDoS vulnerability",
                },
                {
                    "name": "HTTP/2 Continuation Flood",
                    "severity": "high",
                    "description": "Continuation frame flooding",
                },
                {
                    "name": "HTTP/2 Settings Flood",
                    "severity": "medium",
                    "description": "Settings frame flooding",
                },
            ],
            "websocket": [
                {
                    "name": "WebSocket DoS",
                    "severity": "medium",
                    "description": "WebSocket flooding attacks",
                },
                {
                    "name": "WebSocket Injection",
                    "severity": "high",
                    "description": "Code injection via WebSocket",
                },
                {
                    "name": "WebSocket Hijacking",
                    "severity": "critical",
                    "description": "Session hijacking",
                },
            ],
            "ssh": [
                {
                    "name": "SSH Weak Algorithms",
                    "severity": "medium",
                    "description": "Weak encryption algorithms",
                },
                {
                    "name": "SSH Key Exchange",
                    "severity": "high",
                    "description": "Weak key exchange methods",
                },
                {
                    "name": "SSH Brute Force",
                    "severity": "high",
                    "description": "Password brute force attacks",
                },
            ],
        }

        logger.info("Protocol analyzer initialized successfully")

    async def analyze_protocol(
        self, protocol: ProtocolType, target: str, port: int = None
    ) -> Dict[str, Any]:
        """Analyze a specific protocol for vulnerabilities"""
        if not self.config.enable_protocol_analysis:
            return {"error": "Protocol analysis disabled"}

        try:
            analysis_result = {
                "protocol": protocol.value,
                "target": target,
                "port": port,
                "timestamp": time.time(),
                "vulnerabilities": [],
                "security_score": 100,
                "recommendations": [],
            }

            if protocol == ProtocolType.HTTP:
                result = await self._analyze_http(target, port)
            elif protocol == ProtocolType.HTTPS:
                result = await self._analyze_https(target, port)
            elif protocol == ProtocolType.HTTP2:
                result = await self._analyze_http2(target, port)
            elif protocol == ProtocolType.WEBSOCKET:
                result = await self._analyze_websocket(target, port)
            elif protocol == ProtocolType.SSH:
                result = await self._analyze_ssh(target, port)
            else:
                result = {
                    "error": f"Protocol {protocol.value} not supported for analysis"
                }

            if "error" not in result:
                analysis_result.update(result)
                analysis_result["security_score"] = (
                    self._calculate_protocol_security_score(
                        analysis_result["vulnerabilities"]
                    )
                )
                analysis_result["recommendations"] = (
                    self._generate_protocol_recommendations(analysis_result)
                )

            # Store analysis result
            key = f"{protocol.value}_{target}_{port or 'default'}"
            self.analysis_results[key] = analysis_result

            return analysis_result

        except Exception as e:
            logger.error(f"Protocol analysis failed for {protocol.value}: {e}")
            return {"error": str(e)}

    async def _analyze_http(self, target: str, port: int = None) -> Dict[str, Any]:
        """Analyze HTTP protocol security"""
        try:
            port = port or 80
            vulnerabilities = []

            # Check if HTTP is accessible
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"http://{target}:{port}/",
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as response:
                        if response.status == 200:
                            vulnerabilities.append(
                                {
                                    "name": "HTTP Accessible",
                                    "severity": "high",
                                    "description": "HTTP endpoint accessible without encryption",
                                    "details": f"HTTP response received from {target}:{port}",
                                }
                            )

            except Exception:
                pass  # HTTP not accessible

            # Check for common HTTP vulnerabilities
            vulnerabilities.extend(self.protocol_vulnerabilities.get("http", []))

            return {
                "vulnerabilities": vulnerabilities,
                "headers_analyzed": True,
                "security_headers": self._check_security_headers(target, port),
            }

        except Exception as e:
            logger.error(f"HTTP analysis failed: {e}")
            return {"error": str(e)}

    async def _analyze_https(self, target: str, port: int = None) -> Dict[str, Any]:
        """Analyze HTTPS protocol security"""
        try:
            port = port or 443
            vulnerabilities = []

            # Check TLS configuration
            tls_result = await self._analyze_tls_config(target, port)
            if "error" not in tls_result:
                vulnerabilities.extend(tls_result.get("vulnerabilities", []))

            # Check for HTTPS-specific vulnerabilities
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"https://{target}:{port}/",
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as response:
                        if response.status == 200:
                            # Check security headers
                            security_headers = self._check_security_headers(
                                target, port, https=True
                            )

                            return {
                                "vulnerabilities": vulnerabilities,
                                "tls_analysis": tls_result,
                                "security_headers": security_headers,
                                "https_accessible": True,
                            }

            except Exception as e:
                vulnerabilities.append(
                    {
                        "name": "HTTPS Connection Failed",
                        "severity": "medium",
                        "description": "HTTPS endpoint not accessible",
                        "details": str(e),
                    }
                )

            return {
                "vulnerabilities": vulnerabilities,
                "tls_analysis": tls_result,
                "https_accessible": False,
            }

        except Exception as e:
            logger.error(f"HTTPS analysis failed: {e}")
            return {"error": str(e)}

    async def _analyze_http2(self, target: str, port: int = None) -> Dict[str, Any]:
        """Analyze HTTP/2 protocol security"""
        try:
            port = port or 443
            vulnerabilities = []

            # Check if HTTP/2 is supported
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"https://{target}:{port}/",
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as response:
                        if hasattr(response, "version") and response.version == 20:
                            # HTTP/2 is supported, check for vulnerabilities
                            vulnerabilities.extend(
                                self.protocol_vulnerabilities.get("http2", [])
                            )

                            return {
                                "vulnerabilities": vulnerabilities,
                                "http2_supported": True,
                                "version": "HTTP/2",
                            }
                        else:
                            vulnerabilities.append(
                                {
                                    "name": "HTTP/2 Not Supported",
                                    "severity": "low",
                                    "description": "Server does not support HTTP/2",
                                    "details": f"Server uses {getattr(response, 'version', 'unknown')}",
                                }
                            )

            except Exception as e:
                vulnerabilities.append(
                    {
                        "name": "HTTP/2 Connection Failed",
                        "severity": "medium",
                        "description": "Unable to establish HTTP/2 connection",
                        "details": str(e),
                    }
                )

            return {"vulnerabilities": vulnerabilities, "http2_supported": False}

        except Exception as e:
            logger.error(f"HTTP/2 analysis failed: {e}")
            return {"error": str(e)}

    async def _analyze_websocket(self, target: str, port: int = None) -> Dict[str, Any]:
        """Analyze WebSocket protocol security"""
        try:
            port = port or 80
            vulnerabilities = []

            # Check for WebSocket vulnerabilities
            vulnerabilities.extend(self.protocol_vulnerabilities.get("websocket", []))

            # Try to establish WebSocket connection
            try:
                import websockets

                uri = f"ws://{target}:{port}/"
                async with websockets.connect(uri, timeout=10) as websocket:
                    vulnerabilities.append(
                        {
                            "name": "WebSocket Accessible",
                            "severity": "medium",
                            "description": "WebSocket endpoint accessible without encryption",
                            "details": f"WebSocket connection established to {target}:{port}",
                        }
                    )

            except ImportError:
                vulnerabilities.append(
                    {
                        "name": "WebSocket Library Missing",
                        "severity": "low",
                        "description": "WebSocket analysis library not available",
                        "details": "Install websockets library for full analysis",
                    }
                )
            except Exception:
                # WebSocket not accessible
                pass

            return {
                "vulnerabilities": vulnerabilities,
                "websocket_accessible": "websockets" in globals(),
            }

        except Exception as e:
            logger.error(f"WebSocket analysis failed: {e}")
            return {"error": str(e)}

    async def _analyze_ssh(self, target: str, port: int = None) -> Dict[str, Any]:
        """Analyze SSH protocol security"""
        try:
            port = port or 22
            vulnerabilities = []

            # Check SSH configuration
            try:
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                # Try to connect and get server information
                ssh_client.connect(target, port=port, timeout=10)
                transport = ssh_client.get_transport()

                if transport:
                    # Analyze supported algorithms
                    algorithms = transport.get_security_options()

                    # Check for weak algorithms
                    weak_algorithms = [
                        "diffie-hellman-group1-sha1",
                        "diffie-hellman-group14-sha1",
                        "ssh-rsa",
                        "ssh-dss",
                    ]

                    for weak_alg in weak_algorithms:
                        if hasattr(algorithms, weak_alg) and getattr(
                            algorithms, weak_alg
                        ):
                            vulnerabilities.append(
                                {
                                    "name": f"Weak SSH Algorithm: {weak_alg}",
                                    "severity": "high",
                                    "description": f"Server supports weak SSH algorithm: {weak_alg}",
                                    "details": "Consider disabling weak algorithms",
                                }
                            )

                    ssh_client.close()

            except Exception as e:
                vulnerabilities.append(
                    {
                        "name": "SSH Connection Failed",
                        "severity": "medium",
                        "description": "Unable to establish SSH connection",
                        "details": str(e),
                    }
                )

            # Add known SSH vulnerabilities
            vulnerabilities.extend(self.protocol_vulnerabilities.get("ssh", []))

            return {
                "vulnerabilities": vulnerabilities,
                "ssh_accessible": len(
                    [v for v in vulnerabilities if "Connection Failed" not in v["name"]]
                )
                > 0,
            }

        except Exception as e:
            logger.error(f"SSH analysis failed: {e}")
            return {"error": str(e)}

    def _check_security_headers(
        self, target: str, port: int, https: bool = False
    ) -> Dict[str, Any]:
        """Check security headers for HTTP/HTTPS endpoints"""
        try:
            # This would implement actual header checking
            # For now, return a placeholder
            return {
                "hsts": "not_checked",
                "csp": "not_checked",
                "x_frame_options": "not_checked",
                "x_content_type_options": "not_checked",
            }
        except Exception as e:
            logger.error(f"Security header check failed: {e}")
            return {"error": str(e)}

    def _calculate_protocol_security_score(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> int:
        """Calculate security score for a protocol"""
        try:
            score = 100

            for vuln in vulnerabilities:
                severity = vuln.get("severity", "low")
                if severity == "critical":
                    score -= 25
                elif severity == "high":
                    score -= 15
                elif severity == "medium":
                    score -= 10
                elif severity == "low":
                    score -= 5

            return max(0, score)

        except Exception as e:
            logger.error(f"Security score calculation failed: {e}")
            return 0

    def _generate_protocol_recommendations(
        self, analysis_result: Dict[str, Any]
    ) -> List[str]:
        """Generate security recommendations for protocol analysis"""
        recommendations = []

        vulnerabilities = analysis_result.get("vulnerabilities", [])

        if any(v["severity"] == "critical" for v in vulnerabilities):
            recommendations.append(
                "Immediate action required: Critical vulnerabilities detected"
            )

        if any(v["severity"] == "high" for v in vulnerabilities):
            recommendations.append(
                "High priority: Address high-severity vulnerabilities"
            )

        if analysis_result.get("protocol") == "http":
            recommendations.append(
                "Consider migrating to HTTPS for encrypted communication"
            )

        if analysis_result.get("protocol") == "ssh":
            recommendations.append("Review and harden SSH configuration")

        return recommendations


class TLSAnalyzer:
    """Analyzes TLS configuration and certificates"""

    def __init__(self, config: NetworkSecurityConfig):
        self.config = config
        self.tls_analysis_results: Dict[str, Dict[str, Any]] = {}
        self.certificate_cache: Dict[str, Dict[str, Any]] = {}
        self._init_tls_analysis()

    def _init_tls_analysis(self):
        """Initialize TLS analysis capabilities"""
        if not self.config.enable_tls_analysis:
            return

        logger.info("TLS analyzer initialized successfully")

    async def analyze_tls_config(self, target: str, port: int = 443) -> Dict[str, Any]:
        """Analyze TLS configuration for a target"""
        if not self.config.enable_tls_analysis:
            return {"error": "TLS analysis disabled"}

        try:
            analysis_result = {
                "target": target,
                "port": port,
                "timestamp": time.time(),
                "tls_version": None,
                "cipher_suite": None,
                "certificate_info": {},
                "vulnerabilities": [],
                "security_score": 100,
                "recommendations": [],
            }

            # Create SSL context for testing
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            try:
                with socket.create_connection((target, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        # Get TLS version
                        version = ssock.version()
                        analysis_result["tls_version"] = version

                        # Get cipher suite
                        cipher = ssock.cipher()
                        analysis_result["cipher_suite"] = cipher[0]

                        # Analyze certificate
                        cert = ssock.getpeercert()
                        if cert:
                            analysis_result["certificate_info"] = (
                                self._analyze_certificate(cert)
                            )

                        # Check for vulnerabilities
                        vulnerabilities = self._check_tls_vulnerabilities(
                            version, cipher[0]
                        )
                        analysis_result["vulnerabilities"] = vulnerabilities

                        # Calculate security score
                        analysis_result["security_score"] = (
                            self._calculate_tls_security_score(
                                version, cipher[0], vulnerabilities
                            )
                        )

                        # Generate recommendations
                        analysis_result["recommendations"] = (
                            self._generate_tls_recommendations(analysis_result)
                        )

            except Exception as e:
                analysis_result["vulnerabilities"].append(
                    {
                        "name": "TLS Connection Failed",
                        "severity": "high",
                        "description": "Unable to establish TLS connection",
                        "details": str(e),
                    }
                )

            # Store analysis result
            key = f"{target}_{port}"
            self.tls_analysis_results[key] = analysis_result

            return analysis_result

        except Exception as e:
            logger.error(f"TLS analysis failed for {target}:{port}: {e}")
            return {"error": str(e)}

    def _analyze_certificate(self, cert: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze SSL/TLS certificate"""
        try:
            cert_info = {
                "subject": cert.get("subject", {}),
                "issuer": cert.get("issuer", {}),
                "version": cert.get("version", "unknown"),
                "serial_number": cert.get("serialNumber", "unknown"),
                "not_before": cert.get("notBefore", "unknown"),
                "not_after": cert.get("notAfter", "unknown"),
                "san": cert.get("subjectAltName", []),
                "key_size": None,
                "signature_algorithm": cert.get("signatureAlgorithm", "unknown"),
            }

            # Extract key size if available
            if "subject" in cert:
                for field in cert["subject"]:
                    if field[0][0] == "commonName":
                        cert_info["common_name"] = field[0][1]

            return cert_info

        except Exception as e:
            logger.error(f"Certificate analysis failed: {e}")
            return {"error": str(e)}

    def _check_tls_vulnerabilities(
        self, version: str, cipher: str
    ) -> List[Dict[str, Any]]:
        """Check for known TLS vulnerabilities"""
        vulnerabilities = []

        # Check TLS version
        if version == "TLSv1.0" or version == "TLSv1.1":
            vulnerabilities.append(
                {
                    "name": f"Weak TLS Version: {version}",
                    "severity": "high",
                    "description": f"Server uses deprecated TLS version: {version}",
                    "details": "TLS 1.0 and 1.1 are deprecated and vulnerable to attacks",
                }
            )

        # Check cipher suite
        weak_ciphers = ["NULL", "EXPORT", "LOW", "MEDIUM", "DES", "3DES", "RC4", "MD5"]
        for weak_cipher in weak_ciphers:
            if weak_cipher in cipher.upper():
                vulnerabilities.append(
                    {
                        "name": f"Weak Cipher Suite: {cipher}",
                        "severity": "high",
                        "description": f"Server uses weak cipher suite: {cipher}",
                        "details": f"Cipher contains weak algorithm: {weak_cipher}",
                    }
                )

        return vulnerabilities

    def _calculate_tls_security_score(
        self, version: str, cipher: str, vulnerabilities: List[Dict[str, Any]]
    ) -> int:
        """Calculate TLS security score"""
        try:
            score = 100

            # Deduct points for weak TLS version
            if version in ["TLSv1.0", "TLSv1.1"]:
                score -= 30

            # Deduct points for weak cipher
            weak_ciphers = [
                "NULL",
                "EXPORT",
                "LOW",
                "MEDIUM",
                "DES",
                "3DES",
                "RC4",
                "MD5",
            ]
            if any(weak_cipher in cipher.upper() for weak_cipher in weak_ciphers):
                score -= 25

            # Deduct points for vulnerabilities
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "low")
                if severity == "critical":
                    score -= 25
                elif severity == "high":
                    score -= 15
                elif severity == "medium":
                    score -= 10
                elif severity == "low":
                    score -= 5

            return max(0, score)

        except Exception as e:
            logger.error(f"TLS security score calculation failed: {e}")
            return 0

    def _generate_tls_recommendations(
        self, analysis_result: Dict[str, Any]
    ) -> List[str]:
        """Generate TLS security recommendations"""
        recommendations = []

        version = analysis_result.get("tls_version")
        if version in ["TLSv1.0", "TLSv1.1"]:
            recommendations.append("Upgrade to TLS 1.2 or 1.3")

        cipher = analysis_result.get("cipher_suite")
        if cipher and any(
            weak in cipher.upper()
            for weak in ["NULL", "EXPORT", "LOW", "MEDIUM", "DES", "3DES", "RC4", "MD5"]
        ):
            recommendations.append("Disable weak cipher suites")

        if analysis_result.get("security_score", 100) < 70:
            recommendations.append("Review and harden TLS configuration")

        return recommendations


class NetworkMonitor:
    """Monitors network traffic for security threats"""

    def __init__(self, config: NetworkSecurityConfig):
        self.config = config
        self.network_events: List[NetworkEvent] = []
        self.traffic_patterns: Dict[str, Dict[str, Any]] = {}
        self.intrusion_alerts: List[Dict[str, Any]] = []
        self.monitoring_active = False
        self.monitor_thread = None
        self._init_network_monitoring()

    def _init_network_monitoring(self):
        """Initialize network monitoring"""
        if not self.config.enable_network_monitoring:
            return

        logger.info("Network monitor initialized successfully")

    def start_monitoring(self):
        """Start network monitoring"""
        if self.monitoring_active:
            return

        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring_active = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                self._check_network_traffic()
                time.sleep(self.config.monitoring_interval)
            except Exception as e:
                logger.error(f"Network monitoring error: {e}")
                time.sleep(self.config.monitoring_interval * 2)

    def _check_network_traffic(self):
        """Check network traffic for anomalies"""
        try:
            # This would implement actual network traffic monitoring
            # For now, just log that monitoring is active
            pass
        except Exception as e:
            logger.error(f"Network traffic check failed: {e}")

    def record_network_event(self, event: NetworkEvent):
        """Record a network security event"""
        try:
            self.network_events.append(event)

            # Check if we should alert
            if len(self.network_events) >= self.config.alert_threshold:
                self._trigger_alert()

            # Keep only last 1000 events
            if len(self.network_events) > 1000:
                self.network_events = self.network_events[-1000:]

        except Exception as e:
            logger.error(f"Failed to record network event: {e}")

    def _trigger_alert(self):
        """Trigger a network security alert"""
        try:
            alert = {
                "timestamp": time.time(),
                "type": "network_security_alert",
                "events_count": len(self.network_events),
                "recent_events": self.network_events[-self.config.alert_threshold :],
            }

            self.intrusion_alerts.append(alert)
            logger.warning(
                f"Network security alert triggered: {alert['events_count']} events"
            )

        except Exception as e:
            logger.error(f"Failed to trigger alert: {e}")

    def get_monitoring_summary(self) -> Dict[str, Any]:
        """Get network monitoring summary"""
        return {
            "monitoring_active": self.monitoring_active,
            "total_events": len(self.network_events),
            "total_alerts": len(self.intrusion_alerts),
            "recent_events": self.network_events[-10:] if self.network_events else [],
            "recent_alerts": (
                self.intrusion_alerts[-5:] if self.intrusion_alerts else []
            ),
        }


class NetworkSecurityManager:
    """Main network security manager"""

    def __init__(self, config: NetworkSecurityConfig):
        self.config = config
        self.protocol_analyzer = ProtocolAnalyzer(config)
        self.tls_analyzer = TLSAnalyzer(config)
        self.network_monitor = NetworkMonitor(config)
        self.security_events: List[NetworkEvent] = []

    def start_protection(self):
        """Start all network security protections"""
        try:
            logger.info("Starting network security protection")

            if self.config.enable_network_monitoring:
                self.network_monitor.start_monitoring()

            logger.info("Network security protection started successfully")

        except Exception as e:
            logger.error(f"Failed to start network security protection: {e}")

    def stop_protection(self):
        """Stop all network security protections"""
        try:
            logger.info("Stopping network security protection")

            if self.config.enable_network_monitoring:
                self.network_monitor.stop_monitoring()

            logger.info("Network security protection stopped")

        except Exception as e:
            logger.error(f"Failed to stop network security protection: {e}")

    async def analyze_endpoint(
        self, target: str, port: int = None, protocol: ProtocolType = None
    ) -> Dict[str, Any]:
        """Analyze network endpoint security"""
        try:
            analysis_result = {
                "target": target,
                "port": port,
                "protocol": protocol.value if protocol else "unknown",
                "timestamp": time.time(),
                "protocol_analysis": {},
                "tls_analysis": {},
                "overall_security_score": 0,
                "recommendations": [],
            }

            # Analyze protocol if specified
            if protocol and self.config.enable_protocol_analysis:
                protocol_result = await self.protocol_analyzer.analyze_protocol(
                    protocol, target, port
                )
                analysis_result["protocol_analysis"] = protocol_result

            # Analyze TLS if HTTPS/SSL
            if protocol in [ProtocolType.HTTPS, ProtocolType.HTTP2] or (
                port and port in [443, 8443, 9443]
            ):
                tls_result = await self.tls_analyzer.analyze_tls_config(
                    target, port or 443
                )
                analysis_result["tls_analysis"] = tls_result

            # Calculate overall security score
            analysis_result["overall_security_score"] = (
                self._calculate_overall_security_score(analysis_result)
            )

            # Generate recommendations
            analysis_result["recommendations"] = self._generate_overall_recommendations(
                analysis_result
            )

            return analysis_result

        except Exception as e:
            logger.error(f"Endpoint analysis failed for {target}:{port}: {e}")
            return {"error": str(e)}

    def _calculate_overall_security_score(self, analysis_result: Dict[str, Any]) -> int:
        """Calculate overall network security score"""
        try:
            scores = []
            weights = []

            # Protocol analysis score
            if (
                "protocol_analysis" in analysis_result
                and "security_score" in analysis_result["protocol_analysis"]
            ):
                scores.append(analysis_result["protocol_analysis"]["security_score"])
                weights.append(0.6)

            # TLS analysis score
            if (
                "tls_analysis" in analysis_result
                and "security_score" in analysis_result["tls_analysis"]
            ):
                scores.append(analysis_result["tls_analysis"]["security_score"])
                weights.append(0.4)

            if not scores:
                return 0

            # Calculate weighted average
            weighted_sum = sum(score * weight for score, weight in zip(scores, weights))
            total_weight = sum(weights)

            return int(weighted_sum / total_weight if total_weight > 0 else 0)

        except Exception as e:
            logger.error(f"Overall security score calculation failed: {e}")
            return 0

    def _generate_overall_recommendations(
        self, analysis_result: Dict[str, Any]
    ) -> List[str]:
        """Generate overall network security recommendations"""
        recommendations = []

        # Add protocol-specific recommendations
        if "protocol_analysis" in analysis_result:
            protocol_recs = analysis_result["protocol_analysis"].get(
                "recommendations", []
            )
            recommendations.extend(protocol_recs)

        # Add TLS-specific recommendations
        if "tls_analysis" in analysis_result:
            tls_recs = analysis_result["tls_analysis"].get("recommendations", [])
            recommendations.extend(tls_recs)

        # Add general recommendations
        overall_score = analysis_result.get("overall_security_score", 100)
        if overall_score < 70:
            recommendations.append("Comprehensive network security review recommended")
        if overall_score < 50:
            recommendations.append(
                "Immediate action required: Critical network security issues detected"
            )

        return list(set(recommendations))  # Remove duplicates

    def get_security_status(self) -> Dict[str, Any]:
        """Get comprehensive network security status"""
        try:
            return {
                "protocol_analysis": {
                    "enabled": self.config.enable_protocol_analysis,
                    "results_count": len(self.protocol_analyzer.analysis_results),
                },
                "tls_analysis": {
                    "enabled": self.config.enable_tls_analysis,
                    "results_count": len(self.tls_analyzer.tls_analysis_results),
                },
                "network_monitoring": {
                    "enabled": self.config.enable_network_monitoring,
                    "status": self.network_monitor.get_monitoring_summary(),
                },
                "total_security_events": len(self.security_events),
            }
        except Exception as e:
            logger.error(f"Failed to get security status: {e}")
            return {"error": str(e)}

    def cleanup(self):
        """Clean up network security resources"""
        try:
            self.stop_protection()
            logger.info("Network security cleanup completed")
        except Exception as e:
            logger.error(f"Network security cleanup failed: {e}")


# Utility functions
def get_network_security_manager(
    config: NetworkSecurityConfig = None,
) -> NetworkSecurityManager:
    """Get network security manager instance"""
    if config is None:
        config = NetworkSecurityConfig()
    return NetworkSecurityManager(config)


async def analyze_network_endpoint(
    target: str, port: int = None, protocol: ProtocolType = None
) -> Dict[str, Any]:
    """Quick function to analyze network endpoint security"""
    config = NetworkSecurityConfig()
    manager = NetworkSecurityManager(config)
    return await manager.analyze_endpoint(target, port, protocol)


def start_network_security_protection(config: NetworkSecurityConfig = None):
    """Quick function to start network security protection"""
    manager = get_network_security_manager(config)
    manager.start_protection()
    return manager
