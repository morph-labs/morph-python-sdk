"""
Command & Control Detection Module

This module provides comprehensive detection capabilities for:
- Command & control (C2) communications
- Malware behavior patterns
- Suspicious network traffic
- Data exfiltration attempts
- Advanced persistent threat indicators
"""

import time
import logging
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime
import re
from collections import defaultdict

logger = logging.getLogger(__name__)


class ThreatType(Enum):
    """Types of threats detected"""

    C2_COMMUNICATION = "c2_communication"
    DATA_EXFILTRATION = "data_exfiltration"
    MALWARE_BEHAVIOR = "malware_behavior"
    SUSPICIOUS_NETWORK = "suspicious_network"
    APT_INDICATOR = "apt_indicator"
    RANSOMWARE = "ransomware"
    KEYLOGGER = "keylogger"
    BACKDOOR = "backdoor"


class ThreatSeverity(Enum):
    """Threat severity levels"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionStatus(Enum):
    """Detection status"""

    DETECTED = "detected"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    MITIGATED = "mitigated"


@dataclass
class ThreatEvent:
    """Individual threat detection event"""

    event_id: str
    threat_type: ThreatType
    severity: ThreatSeverity
    status: DetectionStatus
    description: str
    timestamp: float = field(default_factory=time.time)
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    payload: Optional[str] = None
    indicators: List[str] = field(default_factory=list)
    confidence: float = 0.0
    false_positive: bool = False
    mitigation_action: Optional[str] = None


@dataclass
class C2DetectionConfig:
    """C2 detection configuration"""

    # Network monitoring
    enable_network_monitoring: bool = True
    enable_dns_monitoring: bool = True
    enable_http_monitoring: bool = True
    enable_https_monitoring: bool = True
    enable_ssl_monitoring: bool = True

    # Behavioral analysis
    enable_behavioral_analysis: bool = True
    enable_process_monitoring: bool = True
    enable_file_monitoring: bool = True
    enable_registry_monitoring: bool = True

    # Thresholds
    suspicious_domain_threshold: int = 3
    suspicious_ip_threshold: int = 5
    data_exfiltration_threshold_mb: int = 100
    connection_frequency_threshold: int = 10

    # Detection patterns
    enable_dga_detection: bool = True
    enable_encrypted_traffic_analysis: bool = True
    enable_timing_analysis: bool = True
    enable_payload_analysis: bool = True

    # Response actions
    enable_automatic_blocking: bool = False
    enable_quarantine: bool = True
    enable_alerting: bool = True
    enable_logging: bool = True


class C2PatternDetector:
    """Detects command & control communication patterns"""

    def __init__(self, config: C2DetectionConfig):
        self.config = config
        self.suspicious_domains: Dict[str, int] = defaultdict(int)
        self.suspicious_ips: Dict[str, int] = defaultdict(int)
        self.connection_patterns: Dict[str, List[float]] = defaultdict(list)
        self.detected_threats: List[ThreatEvent] = []

        # Load threat intelligence
        self.threat_indicators = self._load_threat_indicators()
        self.dga_patterns = self._load_dga_patterns()

    def _load_threat_indicators(self) -> Dict[str, List[str]]:
        """Load known threat indicators"""
        return {
            "malicious_domains": [
                "malware.example.com",
                "c2.evil.org",
                "botnet.xyz",
                "command.control.net",
            ],
            "malicious_ips": ["192.168.1.100", "10.0.0.50", "172.16.0.25"],
            "suspicious_user_agents": [
                "Mozilla/5.0 (compatible; EvilBot/1.0)",
                "Python-urllib/2.7",
                "curl/7.68.0",
            ],
            "suspicious_headers": ["X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"],
        }

    def _load_dga_patterns(self) -> List[re.Pattern]:
        """Load domain generation algorithm patterns"""
        return [
            re.compile(r"[a-z]{8,16}\.[a-z]{2,4}"),  # Random subdomain patterns
            re.compile(r"[a-z]{4,8}[0-9]{4,8}\.[a-z]{2,4}"),  # Alphanumeric patterns
            re.compile(
                r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
            ),  # IP patterns
        ]

    def analyze_network_connection(
        self,
        source_ip: str,
        dest_ip: str,
        source_port: int,
        dest_port: int,
        protocol: str,
        payload: Optional[str] = None,
    ) -> Optional[ThreatEvent]:
        """Analyze network connection for C2 indicators"""
        indicators = []
        confidence = 0.0

        # Check for known malicious IPs
        if dest_ip in self.threat_indicators["malicious_ips"]:
            indicators.append(f"Known malicious IP: {dest_ip}")
            confidence += 0.8

        # Check for suspicious port usage
        if dest_port in [4444, 8080, 1337, 31337]:  # Common C2 ports
            indicators.append(f"Suspicious destination port: {dest_port}")
            confidence += 0.6

        # Check for unusual protocols
        if protocol.lower() in ["dns", "icmp"] and payload:
            indicators.append(f"Potential data exfiltration via {protocol.upper()}")
            confidence += 0.7

        # Check for encrypted traffic patterns
        if self.config.enable_encrypted_traffic_analysis:
            encrypted_indicators = self._analyze_encrypted_traffic(payload)
            indicators.extend(encrypted_indicators)
            confidence += len(encrypted_indicators) * 0.3

        # Check for timing patterns
        if self.config.enable_timing_analysis:
            timing_indicators = self._analyze_timing_patterns(source_ip, dest_ip)
            indicators.extend(timing_indicators)
            confidence += len(timing_indicators) * 0.2

        # Check for payload patterns
        if self.config.enable_payload_analysis and payload:
            payload_indicators = self._analyze_payload(payload)
            indicators.extend(payload_indicators)
            confidence += len(payload_indicators) * 0.4

        # Update connection patterns
        self._update_connection_patterns(source_ip, dest_ip)

        # Check for frequency-based anomalies
        frequency_indicators = self._check_frequency_anomalies(source_ip, dest_ip)
        indicators.extend(frequency_indicators)
        confidence += len(frequency_indicators) * 0.3

        # Determine if this constitutes a threat
        if confidence > 0.5 and indicators:
            return self._create_threat_event(
                ThreatType.C2_COMMUNICATION,
                source_ip,
                dest_ip,
                source_port,
                dest_port,
                protocol,
                payload,
                indicators,
                confidence,
            )

        return None

    def analyze_dns_query(
        self, domain: str, query_type: str, source_ip: str
    ) -> Optional[ThreatEvent]:
        """Analyze DNS queries for C2 indicators"""
        indicators = []
        confidence = 0.0

        # Check for known malicious domains
        if domain in self.threat_indicators["malicious_domains"]:
            indicators.append(f"Known malicious domain: {domain}")
            confidence += 0.9

        # Check for DGA patterns
        if self.config.enable_dga_detection:
            dga_indicators = self._detect_dga_patterns(domain)
            indicators.extend(dga_indicators)
            confidence += len(dga_indicators) * 0.6

        # Check for suspicious TLDs
        suspicious_tlds = [".xyz", ".top", ".club", ".online", ".site"]
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            indicators.append(f"Suspicious TLD: {domain}")
            confidence += 0.4

        # Check for numeric domains
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
            indicators.append(f"Numeric domain: {domain}")
            confidence += 0.5

        # Check for very long domains
        if len(domain) > 50:
            indicators.append(f"Unusually long domain: {domain}")
            confidence += 0.3

        # Update suspicious domain tracking
        self.suspicious_domains[domain] += 1

        # Check if domain exceeds threshold
        if self.suspicious_domains[domain] >= self.config.suspicious_domain_threshold:
            indicators.append(f"Domain query frequency threshold exceeded: {domain}")
            confidence += 0.7

        # Determine if this constitutes a threat
        if confidence > 0.5 and indicators:
            return self._create_threat_event(
                ThreatType.C2_COMMUNICATION,
                source_ip,
                None,
                None,
                None,
                "DNS",
                domain,
                indicators,
                confidence,
            )

        return None

    def analyze_http_request(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        payload: Optional[str],
        source_ip: str,
    ) -> Optional[ThreatEvent]:
        """Analyze HTTP requests for C2 indicators"""
        indicators = []
        confidence = 0.0

        # Check for suspicious user agents
        user_agent = headers.get("User-Agent", "")
        for suspicious_ua in self.threat_indicators["suspicious_user_agents"]:
            if suspicious_ua.lower() in user_agent.lower():
                indicators.append(f"Suspicious User-Agent: {user_agent}")
                confidence += 0.6

        # Check for suspicious headers
        for header_name in headers:
            if header_name.lower() in [
                h.lower() for h in self.threat_indicators["suspicious_headers"]
            ]:
                indicators.append(f"Suspicious header: {header_name}")
                confidence += 0.4

        # Check for beaconing patterns
        if method == "GET" and not payload:
            # Check for timing-based beaconing
            timing_indicators = self._analyze_timing_patterns(source_ip, url)
            indicators.extend(timing_indicators)
            confidence += len(timing_indicators) * 0.3

        # Check for data exfiltration
        if method == "POST" and payload:
            exfiltration_indicators = self._analyze_data_exfiltration(payload)
            indicators.extend(exfiltration_indicators)
            confidence += len(exfiltration_indicators) * 0.5

        # Check for encoded payloads
        if payload:
            encoding_indicators = self._analyze_encoded_payloads(payload)
            indicators.extend(encoding_indicators)
            confidence += len(encoding_indicators) * 0.4

        # Determine if this constitutes a threat
        if confidence > 0.5 and indicators:
            return self._create_threat_event(
                ThreatType.C2_COMMUNICATION,
                source_ip,
                None,
                None,
                None,
                "HTTP",
                payload,
                indicators,
                confidence,
            )

        return None

    def _analyze_encrypted_traffic(self, payload: Optional[str]) -> List[str]:
        """Analyze encrypted traffic for suspicious patterns"""
        indicators = []

        if not payload:
            return indicators

        # Check for SSL/TLS handshake patterns
        if payload.startswith(b"\x16\x03"):  # TLS handshake
            indicators.append("TLS handshake detected")

        # Check for certificate patterns
        if "BEGIN CERTIFICATE" in payload:
            indicators.append("SSL certificate in payload")

        # Check for encrypted data patterns
        if len(payload) > 1000 and self._is_random_data(payload):
            indicators.append("Large encrypted payload detected")

        return indicators

    def _analyze_timing_patterns(self, source_ip: str, dest: str) -> List[str]:
        """Analyze timing patterns for beaconing behavior"""
        indicators = []

        # Get connection history
        key = f"{source_ip}:{dest}"
        if key in self.connection_patterns:
            timestamps = self.connection_patterns[key]

            # Check for regular intervals (beaconing)
            if len(timestamps) >= 3:
                intervals = [
                    timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))
                ]
                avg_interval = sum(intervals) / len(intervals)

                # Check if intervals are regular (within 10% variance)
                variance = sum(
                    abs(interval - avg_interval) for interval in intervals
                ) / len(intervals)
                if variance < avg_interval * 0.1:
                    indicators.append(
                        f"Regular connection pattern detected (avg interval: {avg_interval:.2f}s)"
                    )

        return indicators

    def _analyze_payload(self, payload: str) -> List[str]:
        """Analyze payload for suspicious content"""
        indicators = []

        # Check for encoded data
        if self._is_base64_encoded(payload):
            indicators.append("Base64 encoded payload detected")

        # Check for compressed data
        if self._is_compressed_data(payload):
            indicators.append("Compressed payload detected")

        # Check for suspicious strings
        suspicious_strings = [
            "cmd.exe",
            "powershell",
            "wget",
            "curl",
            "nc",
            "netcat",
            "reverse shell",
            "backdoor",
            "keylogger",
            "ransomware",
        ]

        for suspicious in suspicious_strings:
            if suspicious.lower() in payload.lower():
                indicators.append(f"Suspicious string detected: {suspicious}")

        # Check for large payloads
        if len(payload) > 1024 * 1024:  # 1MB
            indicators.append("Large payload detected")

        return indicators

    def _analyze_data_exfiltration(self, payload: str) -> List[str]:
        """Analyze payload for data exfiltration indicators"""
        indicators = []

        # Check for sensitive data patterns
        sensitive_patterns = [
            r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",  # Credit card
            r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",  # IP address
        ]

        for pattern in sensitive_patterns:
            if re.search(pattern, payload):
                indicators.append("Sensitive data pattern detected")

        # Check for file content
        if "Content-Type: application/" in payload:
            indicators.append("File upload detected")

        # Check for database dumps
        if any(
            db_indicator in payload.lower()
            for db_indicator in ["select", "insert", "update", "delete"]
        ):
            indicators.append("Database query detected")

        return indicators

    def _analyze_encoded_payloads(self, payload: str) -> List[str]:
        """Analyze payload for encoded content"""
        indicators = []

        # Check for base64 encoding
        if self._is_base64_encoded(payload):
            indicators.append("Base64 encoded content")

        # Check for URL encoding
        if "%" in payload and len(payload) > 100:
            url_encoded_chars = payload.count("%")
            if url_encoded_chars > len(payload) * 0.1:
                indicators.append("Heavily URL encoded content")

        # Check for hex encoding
        if re.match(r"^[0-9a-fA-F\s]+$", payload) and len(payload) > 50:
            indicators.append("Hex encoded content")

        return indicators

    def _detect_dga_patterns(self, domain: str) -> List[str]:
        """Detect domain generation algorithm patterns"""
        indicators = []

        for pattern in self.dga_patterns:
            if pattern.match(domain):
                indicators.append(f"DGA pattern detected: {domain}")
                break

        # Check for random character distribution
        if len(domain) > 10:
            char_counts = defaultdict(int)
            for char in domain:
                char_counts[char] += 1

            # Calculate entropy
            total_chars = len(domain)
            entropy = 0
            for count in char_counts.values():
                p = count / total_chars
                if p > 0:
                    entropy -= p * (p.bit_length() - 1)

            # High entropy suggests randomness
            if entropy > 3.5:
                indicators.append(f"High entropy domain (entropy: {entropy:.2f})")

        return indicators

    def _check_frequency_anomalies(self, source_ip: str, dest: str) -> List[str]:
        """Check for frequency-based anomalies"""
        indicators = []

        # Check IP-based frequency
        if source_ip in self.suspicious_ips:
            if self.suspicious_ips[source_ip] >= self.config.suspicious_ip_threshold:
                indicators.append(
                    f"Source IP frequency threshold exceeded: {source_ip}"
                )

        # Check connection frequency
        key = f"{source_ip}:{dest}"
        if key in self.connection_patterns:
            recent_connections = [
                ts
                for ts in self.connection_patterns[key]
                if time.time() - ts < 3600  # Last hour
            ]

            if len(recent_connections) >= self.config.connection_frequency_threshold:
                indicators.append(
                    f"Connection frequency threshold exceeded: {len(recent_connections)} connections/hour"
                )

        return indicators

    def _update_connection_patterns(self, source_ip: str, dest: str):
        """Update connection pattern tracking"""
        key = f"{source_ip}:{dest}"
        current_time = time.time()

        # Add current timestamp
        self.connection_patterns[key].append(current_time)

        # Keep only recent connections (last 24 hours)
        cutoff_time = current_time - 86400
        self.connection_patterns[key] = [
            ts for ts in self.connection_patterns[key] if ts > cutoff_time
        ]

        # Update suspicious IP counter
        self.suspicious_ips[source_ip] += 1

    def _create_threat_event(
        self,
        threat_type: ThreatType,
        source_ip: str,
        dest_ip: Optional[str],
        source_port: Optional[int],
        dest_port: Optional[int],
        protocol: Optional[str],
        payload: Optional[str],
        indicators: List[str],
        confidence: float,
    ) -> ThreatEvent:
        """Create a threat event"""
        # Determine severity based on confidence and indicators
        if confidence >= 0.8:
            severity = ThreatSeverity.CRITICAL
        elif confidence >= 0.6:
            severity = ThreatSeverity.HIGH
        elif confidence >= 0.4:
            severity = ThreatSeverity.MEDIUM
        else:
            severity = ThreatSeverity.LOW

        event = ThreatEvent(
            event_id=f"threat_{int(time.time())}_{hash(source_ip) % 10000}",
            threat_type=threat_type,
            severity=severity,
            status=DetectionStatus.DETECTED,
            description=f"{threat_type.value.replace('_', ' ').title()} detected",
            source_ip=source_ip,
            destination_ip=dest_ip,
            source_port=source_port,
            destination_port=dest_port,
            protocol=protocol,
            payload=payload,
            indicators=indicators,
            confidence=confidence,
        )

        self.detected_threats.append(event)
        return event

    def _is_random_data(self, data: str) -> bool:
        """Check if data appears to be random/encrypted"""
        if not data:
            return False

        # Simple entropy check
        char_counts = defaultdict(int)
        for char in data:
            char_counts[char] += 1

        total_chars = len(data)
        entropy = 0
        for count in char_counts.values():
            p = count / total_chars
            if p > 0:
                entropy -= p * (p.bit_length() - 1)

        return entropy > 4.0

    def _is_base64_encoded(self, data: str) -> bool:
        """Check if data is base64 encoded"""
        if not data:
            return False

        # Check for base64 pattern
        base64_pattern = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
        return bool(base64_pattern.match(data))

    def _is_compressed_data(self, data: str) -> bool:
        """Check if data appears to be compressed"""
        if not data:
            return False

        # Check for common compression signatures
        compression_signatures = [
            b"\x1f\x8b",  # gzip
            b"\x50\x4b\x03\x04",  # zip
            b"\x37\x7a\xbc\xaf",  # 7z
        ]

        data_bytes = data.encode("utf-8") if isinstance(data, str) else data
        return any(data_bytes.startswith(sig) for sig in compression_signatures)


class BehavioralAnalyzer:
    """Analyzes system behavior for malware indicators"""

    def __init__(self, config: C2DetectionConfig):
        self.config = config
        self.process_activities: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.file_activities: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.registry_activities: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.detected_threats: List[ThreatEvent] = []

    def analyze_process_creation(
        self,
        process_name: str,
        process_id: int,
        parent_process: str,
        command_line: str,
        source_ip: str,
    ) -> Optional[ThreatEvent]:
        """Analyze process creation for suspicious behavior"""
        indicators = []
        confidence = 0.0

        # Check for suspicious process names
        suspicious_processes = [
            "cmd.exe",
            "powershell.exe",
            "wscript.exe",
            "cscript.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "mshta.exe",
            "powershell_ise.exe",
        ]

        if process_name.lower() in [p.lower() for p in suspicious_processes]:
            indicators.append(f"Suspicious process: {process_name}")
            confidence += 0.5

        # Check for suspicious parent processes
        suspicious_parents = [
            "iexplore.exe",
            "chrome.exe",
            "firefox.exe",
            "outlook.exe",
            "winword.exe",
            "excel.exe",
            "powerpnt.exe",
        ]

        if parent_process.lower() in [p.lower() for p in suspicious_parents]:
            indicators.append(f"Suspicious parent process: {parent_process}")
            confidence += 0.6

        # Check command line for suspicious patterns
        command_indicators = self._analyze_command_line(command_line)
        indicators.extend(command_indicators)
        confidence += len(command_indicators) * 0.4

        # Record process activity
        self.process_activities[process_name].append(
            {
                "timestamp": time.time(),
                "process_id": process_id,
                "parent_process": parent_process,
                "command_line": command_line,
                "source_ip": source_ip,
            }
        )

        # Check for process chain anomalies
        chain_indicators = self._analyze_process_chain(process_name, parent_process)
        indicators.extend(chain_indicators)
        confidence += len(chain_indicators) * 0.3

        # Determine if this constitutes a threat
        if confidence > 0.5 and indicators:
            return self._create_threat_event(
                ThreatType.MALWARE_BEHAVIOR,
                source_ip,
                None,
                None,
                None,
                "PROCESS",
                command_line,
                indicators,
                confidence,
            )

        return None

    def analyze_file_activity(
        self, file_path: str, operation: str, process_name: str, source_ip: str
    ) -> Optional[ThreatEvent]:
        """Analyze file activity for suspicious behavior"""
        indicators = []
        confidence = 0.0

        # Check for suspicious file operations
        suspicious_operations = ["create", "write", "modify"]
        if operation.lower() in suspicious_operations:
            # Check for suspicious file extensions
            suspicious_extensions = [
                ".exe",
                ".dll",
                ".bat",
                ".cmd",
                ".ps1",
                ".vbs",
                ".js",
            ]
            if any(file_path.lower().endswith(ext) for ext in suspicious_extensions):
                indicators.append(
                    f"Suspicious file operation: {operation} on {file_path}"
                )
                confidence += 0.6

            # Check for temporary directory activity
            temp_dirs = ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\"]
            if any(temp_dir in file_path.lower() for temp_dir in temp_dirs):
                indicators.append(f"File activity in temporary directory: {file_path}")
                confidence += 0.4

        # Check for system file modifications
        system_dirs = ["\\windows\\", "\\system32\\", "\\syswow64\\"]
        if any(system_dir in file_path.lower() for system_dir in system_dirs):
            indicators.append(f"System file modification: {file_path}")
            confidence += 0.7

        # Record file activity
        self.file_activities[file_path].append(
            {
                "timestamp": time.time(),
                "operation": operation,
                "process_name": process_name,
                "source_ip": source_ip,
            }
        )

        # Check for file activity patterns
        pattern_indicators = self._analyze_file_patterns(file_path)
        indicators.extend(pattern_indicators)
        confidence += len(pattern_indicators) * 0.3

        # Determine if this constitutes a threat
        if confidence > 0.5 and indicators:
            return self._create_threat_event(
                ThreatType.MALWARE_BEHAVIOR,
                source_ip,
                None,
                None,
                None,
                "FILE",
                f"{operation}:{file_path}",
                indicators,
                confidence,
            )

        return None

    def _analyze_command_line(self, command_line: str) -> List[str]:
        """Analyze command line for suspicious patterns"""
        indicators = []

        # Check for encoded commands
        if "powershell" in command_line.lower() and (
            "-enc" in command_line or "-encodedcommand" in command_line
        ):
            indicators.append("Encoded PowerShell command detected")

        # Check for suspicious commands
        suspicious_commands = [
            "net user",
            "net group",
            "net localgroup",
            "wmic",
            "schtasks",
            "at",
            "reg add",
            "reg delete",
            "reg import",
            "netsh",
            "ipconfig",
            "route",
        ]

        for cmd in suspicious_commands:
            if cmd.lower() in command_line.lower():
                indicators.append(f"Suspicious command: {cmd}")

        # Check for URL downloads
        if any(
            url_indicator in command_line.lower()
            for url_indicator in ["http://", "https://", "ftp://"]
        ):
            indicators.append("URL download detected")

        # Check for file execution from temp directories
        if "\\temp\\" in command_line.lower() or "\\tmp\\" in command_line.lower():
            indicators.append("Execution from temporary directory")

        return indicators

    def _analyze_process_chain(
        self, process_name: str, parent_process: str
    ) -> List[str]:
        """Analyze process chain for anomalies"""
        indicators = []

        # Check for unusual process chains
        unusual_chains = [
            ("iexplore.exe", "cmd.exe"),
            ("chrome.exe", "powershell.exe"),
            ("outlook.exe", "rundll32.exe"),
            ("winword.exe", "wscript.exe"),
        ]

        for unusual_parent, unusual_child in unusual_chains:
            if (
                parent_process.lower() == unusual_parent.lower()
                and process_name.lower() == unusual_child.lower()
            ):
                indicators.append(
                    f"Unusual process chain: {parent_process} -> {process_name}"
                )

        return indicators

    def _analyze_file_patterns(self, file_path: str) -> List[str]:
        """Analyze file patterns for suspicious activity"""
        indicators = []

        # Check for rapid file creation
        if file_path in self.file_activities:
            recent_activities = [
                activity
                for activity in self.file_activities[file_path]
                if time.time() - activity["timestamp"] < 60  # Last minute
            ]

            if len(recent_activities) > 5:
                indicators.append("Rapid file activity detected")

        # Check for file extension changes
        if file_path in self.file_activities:
            extensions = [
                activity.get("extension", "")
                for activity in self.file_activities[file_path]
            ]
            if len(set(extensions)) > 1:
                indicators.append("File extension changes detected")

        return indicators

    def _create_threat_event(
        self,
        threat_type: ThreatType,
        source_ip: str,
        dest_ip: Optional[str],
        source_port: Optional[int],
        dest_port: Optional[int],
        protocol: Optional[str],
        payload: Optional[str],
        indicators: List[str],
        confidence: float,
    ) -> ThreatEvent:
        """Create a threat event"""
        # Determine severity based on confidence and indicators
        if confidence >= 0.8:
            severity = ThreatSeverity.CRITICAL
        elif confidence >= 0.6:
            severity = ThreatSeverity.HIGH
        elif confidence >= 0.4:
            severity = ThreatSeverity.MEDIUM
        else:
            severity = ThreatSeverity.LOW

        event = ThreatEvent(
            event_id=f"threat_{int(time.time())}_{hash(source_ip) % 10000}",
            threat_type=threat_type,
            severity=severity,
            status=DetectionStatus.DETECTED,
            description=f"{threat_type.value.replace('_', ' ').title()} detected",
            source_ip=source_ip,
            destination_ip=dest_ip,
            source_port=source_port,
            destination_port=dest_port,
            protocol=protocol,
            payload=payload,
            indicators=indicators,
            confidence=confidence,
        )

        self.detected_threats.append(event)
        return event


class C2DetectionEngine:
    """Main C2 detection engine"""

    def __init__(self, config: C2DetectionConfig):
        self.config = config
        self.pattern_detector = C2PatternDetector(config)
        self.behavioral_analyzer = BehavioralAnalyzer(config)
        self.all_threats: List[ThreatEvent] = []
        self.monitoring_active = False
        self.monitoring_thread = None

    def start_monitoring(self):
        """Start continuous monitoring"""
        if self.monitoring_active:
            logger.warning("Monitoring already active")
            return

        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop, daemon=True
        )
        self.monitoring_thread.start()
        logger.info("C2 detection monitoring started")

    def stop_monitoring(self):
        """Stop continuous monitoring"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        logger.info("C2 detection monitoring stopped")

    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                # Process network events
                self._process_network_events()

                # Process system events
                self._process_system_events()

                # Analyze patterns
                self._analyze_patterns()

                # Sleep before next iteration
                time.sleep(1)

            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(5)

    def _process_network_events(self):
        """Process network events for analysis"""
        # This would integrate with network monitoring tools
        # For now, we'll simulate network events
        pass

    def _process_system_events(self):
        """Process system events for analysis"""
        # This would integrate with system monitoring tools
        # For now, we'll simulate system events
        pass

    def _analyze_patterns(self):
        """Analyze collected patterns for threats"""
        # This would analyze collected data for patterns
        # For now, we'll use the existing analyzers
        pass

    def get_threat_summary(self) -> Dict[str, Any]:
        """Get summary of detected threats"""
        # Combine threats from all detectors
        all_threats = (
            self.pattern_detector.detected_threats
            + self.behavioral_analyzer.detected_threats
        )

        # Group by threat type
        threats_by_type = defaultdict(list)
        for threat in all_threats:
            threats_by_type[threat.threat_type.value].append(threat)

        # Calculate statistics
        total_threats = len(all_threats)
        critical_threats = len(
            [t for t in all_threats if t.severity == ThreatSeverity.CRITICAL]
        )
        high_threats = len(
            [t for t in all_threats if t.severity == ThreatSeverity.HIGH]
        )

        return {
            "total_threats": total_threats,
            "critical_threats": critical_threats,
            "high_threats": high_threats,
            "threats_by_type": dict(threats_by_type),
            "monitoring_active": self.monitoring_active,
            "last_updated": datetime.utcnow().isoformat(),
        }

    def get_recent_threats(self, hours: int = 24) -> List[ThreatEvent]:
        """Get threats from the last N hours"""
        cutoff_time = time.time() - (hours * 3600)

        all_threats = (
            self.pattern_detector.detected_threats
            + self.behavioral_analyzer.detected_threats
        )

        return [threat for threat in all_threats if threat.timestamp > cutoff_time]


# Utility functions
def get_c2_detection_engine(config: C2DetectionConfig = None) -> C2DetectionEngine:
    """Get C2 detection engine instance"""
    if config is None:
        config = C2DetectionConfig()
    return C2DetectionEngine(config)


def start_c2_monitoring(config: C2DetectionConfig = None):
    """Start C2 detection monitoring"""
    engine = get_c2_detection_engine(config)
    engine.start_monitoring()
    return engine


def stop_c2_monitoring(engine: C2DetectionEngine):
    """Stop C2 detection monitoring"""
    engine.stop_monitoring()


def get_threat_summary(engine: C2DetectionEngine = None) -> Dict[str, Any]:
    """Get threat summary from detection engine"""
    if engine is None:
        engine = get_c2_detection_engine()
    return engine.get_threat_summary()
