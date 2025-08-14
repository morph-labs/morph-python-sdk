"""
Data Security Module

This module provides comprehensive data security including:
- Data leakage detection and prevention
- Encryption at rest for databases and file systems
- Data sanitization and input/output validation
- Sensitive data classification and handling
- Audit logging and compliance
- Data masking and anonymization
"""

import os
import re
import logging
import hashlib
import base64
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Union, Callable
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger(__name__)


class DataClassification(Enum):
    """Data classification levels"""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    SECRET = "secret"


class EncryptionType(Enum):
    """Encryption types"""

    SYMMETRIC = "symmetric"
    ASYMMETRIC = "asymmetric"
    HASH = "hash"
    HMAC = "hmac"


class DataThreatType(Enum):
    """Types of data security threats"""

    DATA_LEAKAGE = "data_leakage"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_TAMPERING = "data_tampering"
    INSECURE_STORAGE = "insecure_storage"
    WEAK_ENCRYPTION = "weak_encryption"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    INSUFFICIENT_LOGGING = "insufficient_logging"


class ThreatSeverity(Enum):
    """Threat severity levels"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DataSecurityEvent:
    """Represents a data security event"""

    event_id: str
    threat_type: DataThreatType
    severity: ThreatSeverity
    description: str
    timestamp: float
    data_classification: DataClassification
    affected_data: Optional[str] = None
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
    mitigated: bool = False
    mitigation_action: Optional[str] = None


@dataclass
class EncryptionConfig:
    """Encryption configuration settings"""

    encryption_type: EncryptionType = EncryptionType.SYMMETRIC
    key_size: int = 256
    algorithm: str = "AES"
    key_derivation_rounds: int = 100000
    salt_length: int = 32
    iv_length: int = 16
    enable_key_rotation: bool = True
    key_rotation_interval_days: int = 90
    master_key_path: Optional[str] = None


@dataclass
class DataSanitizationConfig:
    """Data sanitization configuration"""

    enable_input_validation: bool = True
    enable_output_sanitization: bool = True
    enable_sql_injection_protection: bool = True
    enable_xss_protection: bool = True
    enable_path_traversal_protection: bool = True
    enable_command_injection_protection: bool = True
    allowed_file_extensions: List[str] = field(
        default_factory=lambda: [".txt", ".pdf", ".doc", ".docx"]
    )
    max_file_size_mb: int = 10
    sanitization_patterns: Dict[str, str] = field(
        default_factory=lambda: {
            "sql_injection": r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
            "xss": r"(<script|javascript:|vbscript:|onload=|onerror=)",
            "path_traversal": r"(\.\.\/|\.\.\\)",
            "command_injection": r"(\b(cmd|powershell|bash|sh|exec|system)\b)",
        }
    )


@dataclass
class DataSecurityConfig:
    """Data security configuration"""

    security_level: str = "high"
    enable_encryption: bool = True
    enable_data_sanitization: bool = True
    enable_audit_logging: bool = True
    enable_data_classification: bool = True
    enable_data_masking: bool = True
    encryption_config: EncryptionConfig = field(default_factory=EncryptionConfig)
    sanitization_config: DataSanitizationConfig = field(
        default_factory=DataSanitizationConfig
    )
    sensitive_patterns: List[str] = field(
        default_factory=lambda: [
            r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",  # Credit card
            r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",  # IP address
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",  # Credit card patterns
        ]
    )
    audit_log_path: str = "logs/data_security.log"
    max_log_size_mb: int = 100
    log_retention_days: int = 365


class DataLeakageDetector:
    """Detects and prevents data leakage"""

    def __init__(self, config: DataSecurityConfig):
        self.config = config
        self.sensitive_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in config.sensitive_patterns
        ]
        self.detection_rules: Dict[str, Dict[str, Any]] = {}
        self.leakage_events: List[DataSecurityEvent] = []
        self._init_detection_rules()

    def _init_detection_rules(self):
        """Initialize data leakage detection rules"""
        self.detection_rules = {
            "log_files": {
                "enabled": True,
                "severity": ThreatSeverity.HIGH,
                "description": "Sensitive data in log files",
            },
            "error_messages": {
                "enabled": True,
                "severity": ThreatSeverity.MEDIUM,
                "description": "Sensitive data in error messages",
            },
            "debug_output": {
                "enabled": True,
                "severity": ThreatSeverity.HIGH,
                "description": "Sensitive data in debug output",
            },
            "api_responses": {
                "enabled": True,
                "severity": ThreatSeverity.CRITICAL,
                "description": "Sensitive data in API responses",
            },
            "file_content": {
                "enabled": True,
                "severity": ThreatSeverity.HIGH,
                "description": "Sensitive data in file content",
            },
        }

        logger.info("Data leakage detector initialized successfully")

    def scan_text(self, text: str, context: str = "unknown") -> Dict[str, Any]:
        """Scan text for sensitive data patterns"""
        try:
            scan_result = {
                "context": context,
                "timestamp": time.time(),
                "sensitive_data_found": [],
                "risk_level": "low",
                "recommendations": [],
            }

            if not text:
                return scan_result

            # Check for sensitive patterns
            for i, pattern in enumerate(self.sensitive_patterns):
                matches = pattern.findall(text)
                if matches:
                    scan_result["sensitive_data_found"].append(
                        {
                            "pattern_index": i,
                            "pattern": self.config.sensitive_patterns[i],
                            "matches": matches[:5],  # Limit to first 5 matches
                            "count": len(matches),
                        }
                    )

            # Determine risk level
            if scan_result["sensitive_data_found"]:
                total_matches = sum(
                    item["count"] for item in scan_result["sensitive_data_found"]
                )
                if total_matches > 10:
                    scan_result["risk_level"] = "critical"
                elif total_matches > 5:
                    scan_result["risk_level"] = "high"
                elif total_matches > 2:
                    scan_result["risk_level"] = "medium"
                else:
                    scan_result["risk_level"] = "low"

                # Generate recommendations
                scan_result["recommendations"] = self._generate_leakage_recommendations(
                    scan_result
                )

                # Record leakage event if high risk
                if scan_result["risk_level"] in ["high", "critical"]:
                    self._record_leakage_event(scan_result, context)

            return scan_result

        except Exception as e:
            logger.error(f"Text scanning failed: {e}")
            return {"error": str(e)}

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Scan file for sensitive data"""
        try:
            if not os.path.exists(file_path):
                return {"error": f"File not found: {file_path}"}

            file_size = os.path.getsize(file_path)
            if (
                file_size
                > self.config.sanitization_config.max_file_size_mb * 1024 * 1024
            ):
                return {"error": f"File too large: {file_size} bytes"}

            # Read file content
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Scan content
            scan_result = self.scan_text(content, f"file:{file_path}")
            scan_result["file_path"] = file_path
            scan_result["file_size"] = file_size

            return scan_result

        except Exception as e:
            logger.error(f"File scanning failed for {file_path}: {e}")
            return {"error": str(e)}

    def scan_directory(
        self, directory_path: str, file_patterns: List[str] = None
    ) -> Dict[str, Any]:
        """Scan directory for files containing sensitive data"""
        try:
            if not os.path.exists(directory_path):
                return {"error": f"Directory not found: {directory_path}"}

            if file_patterns is None:
                file_patterns = ["*.log", "*.txt", "*.json", "*.xml", "*.csv"]

            scan_results = {
                "directory": directory_path,
                "timestamp": time.time(),
                "files_scanned": 0,
                "files_with_sensitive_data": 0,
                "total_sensitive_patterns": 0,
                "scan_details": [],
            }

            for pattern in file_patterns:
                for file_path in Path(directory_path).rglob(pattern):
                    try:
                        file_result = self.scan_file(str(file_path))
                        if "error" not in file_result:
                            scan_results["files_scanned"] += 1

                            if file_result["sensitive_data_found"]:
                                scan_results["files_with_sensitive_data"] += 1
                                scan_results["total_sensitive_patterns"] += len(
                                    file_result["sensitive_data_found"]
                                )
                                scan_results["scan_details"].append(file_result)

                    except Exception as e:
                        logger.debug(f"Failed to scan file {file_path}: {e}")

            return scan_results

        except Exception as e:
            logger.error(f"Directory scanning failed for {directory_path}: {e}")
            return {"error": str(e)}

    def _generate_leakage_recommendations(
        self, scan_result: Dict[str, Any]
    ) -> List[str]:
        """Generate recommendations for data leakage"""
        recommendations = []

        if scan_result["risk_level"] == "critical":
            recommendations.append(
                "Immediate action required: Critical data leakage detected"
            )
            recommendations.append(
                "Review and remove all sensitive data from this context"
            )
        elif scan_result["risk_level"] == "high":
            recommendations.append(
                "High priority: Address data leakage issues immediately"
            )
            recommendations.append(
                "Implement data masking or removal for sensitive patterns"
            )

        if scan_result["sensitive_data_found"]:
            recommendations.append(
                "Consider implementing data classification and handling policies"
            )
            recommendations.append("Review logging and error handling practices")

        return recommendations

    def _record_leakage_event(self, scan_result: Dict[str, Any], context: str):
        """Record a data leakage event"""
        try:
            event = DataSecurityEvent(
                event_id=f"leakage_{int(time.time() * 1000000)}",
                threat_type=DataThreatType.DATA_LEAKAGE,
                severity=(
                    ThreatSeverity.HIGH
                    if scan_result["risk_level"] in ["high", "critical"]
                    else ThreatSeverity.MEDIUM
                ),
                description=f"Data leakage detected in {context}",
                timestamp=time.time(),
                data_classification=DataClassification.CONFIDENTIAL,
                context=scan_result,
            )

            self.leakage_events.append(event)
            logger.warning(f"Data leakage event recorded: {event.description}")

        except Exception as e:
            logger.error(f"Failed to record leakage event: {e}")

    def get_leakage_summary(self) -> Dict[str, Any]:
        """Get summary of data leakage events"""
        return {
            "total_events": len(self.leakage_events),
            "events_by_severity": {
                severity.value: len(
                    [e for e in self.leakage_events if e.severity == severity]
                )
                for severity in ThreatSeverity
            },
            "recent_events": self.leakage_events[-10:] if self.leakage_events else [],
        }


class DataEncryption:
    """Handles data encryption and decryption"""

    def __init__(self, config: DataSecurityConfig):
        self.config = config
        self.encryption_keys: Dict[str, Any] = {}
        self.key_metadata: Dict[str, Dict[str, Any]] = {}
        self._init_encryption()

    def _init_encryption(self):
        """Initialize encryption system"""
        if not self.config.enable_encryption:
            return

        try:
            # Generate or load master key
            self._setup_master_key()

            # Initialize encryption keys
            self._generate_encryption_keys()

            logger.info("Data encryption system initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize encryption: {e}")

    def _setup_master_key(self):
        """Setup master encryption key"""
        try:
            if self.config.encryption_config.master_key_path:
                master_key_path = Path(self.config.encryption_config.master_key_path)
                if master_key_path.exists():
                    with open(master_key_path, "rb") as f:
                        self.master_key = f.read()
                else:
                    # Generate new master key
                    self.master_key = Fernet.generate_key()
                    master_key_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(master_key_path, "wb") as f:
                        f.write(self.master_key)
            else:
                # Generate in-memory master key
                self.master_key = Fernet.generate_key()

        except Exception as e:
            logger.error(f"Failed to setup master key: {e}")
            raise

    def _generate_encryption_keys(self):
        """Generate encryption keys for different purposes"""
        try:
            # Generate symmetric key for general data encryption
            if (
                self.config.encryption_config.encryption_type
                == EncryptionType.SYMMETRIC
            ):
                salt = os.urandom(self.config.encryption_config.salt_length)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=self.config.encryption_config.key_size // 8,
                    salt=salt,
                    iterations=self.config.encryption_config.key_derivation_rounds,
                )
                key = base64.urlsafe_b64encode(kdf.derive(self.master_key))

                self.encryption_keys["symmetric"] = {
                    "key": key,
                    "salt": salt,
                    "created": time.time(),
                    "algorithm": "AES-256-GCM",
                }

            # Generate asymmetric key pair if needed
            if (
                self.config.encryption_config.encryption_type
                == EncryptionType.ASYMMETRIC
            ):
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=self.config.encryption_config.key_size,
                )
                public_key = private_key.public_key()

                self.encryption_keys["asymmetric"] = {
                    "private_key": private_key,
                    "public_key": public_key,
                    "created": time.time(),
                    "algorithm": f"RSA-{self.config.encryption_config.key_size}",
                }

        except Exception as e:
            logger.error(f"Failed to generate encryption keys: {e}")
            raise

    def encrypt_data(
        self, data: Union[str, bytes], key_id: str = "symmetric"
    ) -> Dict[str, Any]:
        """Encrypt data using specified encryption method"""
        try:
            if not self.config.enable_encryption:
                return {"error": "Encryption disabled"}

            if key_id not in self.encryption_keys:
                return {"error": f"Encryption key not found: {key_id}"}

            key_info = self.encryption_keys[key_id]

            if isinstance(data, str):
                data = data.encode("utf-8")

            if key_info["algorithm"].startswith("AES"):
                # Symmetric encryption
                iv = os.urandom(self.config.encryption_config.iv_length)
                cipher = Cipher(algorithms.AES(key_info["key"]), modes.GCM(iv))
                encryptor = cipher.encryptor()

                ciphertext = encryptor.update(data) + encryptor.finalize()

                encrypted_data = {
                    "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
                    "iv": base64.b64encode(iv).decode("utf-8"),
                    "tag": base64.b64encode(encryptor.tag).decode("utf-8"),
                    "algorithm": key_info["algorithm"],
                    "timestamp": time.time(),
                }

            elif key_info["algorithm"].startswith("RSA"):
                # Asymmetric encryption
                public_key = key_info["public_key"]
                ciphertext = public_key.encrypt(
                    data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )

                encrypted_data = {
                    "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
                    "algorithm": key_info["algorithm"],
                    "timestamp": time.time(),
                }

            else:
                return {
                    "error": f"Unsupported encryption algorithm: {key_info['algorithm']}"
                }

            return encrypted_data

        except Exception as e:
            logger.error(f"Data encryption failed: {e}")
            return {"error": str(e)}

    def decrypt_data(
        self, encrypted_data: Dict[str, Any], key_id: str = "symmetric"
    ) -> Union[str, bytes, Dict[str, Any]]:
        """Decrypt data using specified decryption method"""
        try:
            if not self.config.enable_encryption:
                return {"error": "Encryption disabled"}

            if key_id not in self.encryption_keys:
                return {"error": f"Decryption key not found: {key_id}"}

            key_info = self.encryption_keys[key_id]

            if key_info["algorithm"].startswith("AES"):
                # Symmetric decryption
                ciphertext = base64.b64decode(encrypted_data["ciphertext"])
                iv = base64.b64decode(encrypted_data["iv"])
                tag = base64.b64decode(encrypted_data["tag"])

                cipher = Cipher(algorithms.AES(key_info["key"]), modes.GCM(iv, tag))
                decryptor = cipher.decryptor()

                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                return plaintext

            elif key_info["algorithm"].startswith("RSA"):
                # Asymmetric decryption
                private_key = key_info["private_key"]
                ciphertext = base64.b64decode(encrypted_data["ciphertext"])

                plaintext = private_key.decrypt(
                    ciphertext,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
                return plaintext

            else:
                return {
                    "error": f"Unsupported decryption algorithm: {key_info['algorithm']}"
                }

        except Exception as e:
            logger.error(f"Data decryption failed: {e}")
            return {"error": str(e)}

    def encrypt_file(self, file_path: str, output_path: str = None) -> Dict[str, Any]:
        """Encrypt a file"""
        try:
            if not os.path.exists(file_path):
                return {"error": f"File not found: {file_path}"}

            if output_path is None:
                output_path = file_path + ".encrypted"

            # Read file content
            with open(file_path, "rb") as f:
                data = f.read()

            # Encrypt data
            encrypted_data = self.encrypt_data(data)
            if "error" in encrypted_data:
                return encrypted_data

            # Write encrypted data
            with open(output_path, "w") as f:
                json.dump(encrypted_data, f, indent=2)

            return {
                "original_file": file_path,
                "encrypted_file": output_path,
                "encryption_info": encrypted_data,
            }

        except Exception as e:
            logger.error(f"File encryption failed: {e}")
            return {"error": str(e)}

    def decrypt_file(
        self, encrypted_file_path: str, output_path: str = None
    ) -> Dict[str, Any]:
        """Decrypt a file"""
        try:
            if not os.path.exists(encrypted_file_path):
                return {"error": f"Encrypted file not found: {encrypted_file_path}"}

            if output_path is None:
                output_path = encrypted_file_path.replace(".encrypted", ".decrypted")

            # Read encrypted data
            with open(encrypted_file_path, "r") as f:
                encrypted_data = json.load(f)

            # Decrypt data
            decrypted_data = self.decrypt_data(encrypted_data)
            if isinstance(decrypted_data, dict) and "error" in decrypted_data:
                return decrypted_data

            # Write decrypted data
            with open(output_path, "wb") as f:
                f.write(decrypted_data)

            return {
                "encrypted_file": encrypted_file_path,
                "decrypted_file": output_path,
                "decryption_successful": True,
            }

        except Exception as e:
            logger.error(f"File decryption failed: {e}")
            return {"error": str(e)}


class DataSanitizer:
    """Handles data sanitization and validation"""

    def __init__(self, config: DataSecurityConfig):
        self.config = config
        self.sanitization_patterns = config.sanitization_config.sanitization_patterns
        self.validation_rules: Dict[str, Callable] = {}
        self._init_sanitization()

    def _init_sanitization(self):
        """Initialize data sanitization system"""
        if not self.config.enable_data_sanitization:
            return

        # Initialize validation rules
        self._setup_validation_rules()

        logger.info("Data sanitization system initialized successfully")

    def _setup_validation_rules(self):
        """Setup data validation rules"""
        self.validation_rules = {
            "email": lambda x: re.match(
                r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", x
            )
            is not None,
            "url": lambda x: re.match(r"^https?://[^\s/$.?#].[^\s]*$", x) is not None,
            "phone": lambda x: re.match(r"^\+?[\d\s\-\(\)]{10,}$", x) is not None,
            "integer": lambda x: str(x).isdigit(),
            "float": lambda x: str(x).replace(".", "").replace("-", "").isdigit(),
            "alphanumeric": lambda x: re.match(r"^[a-zA-Z0-9]+$", x) is not None,
            "safe_string": lambda x: not any(
                pattern in x.lower()
                for pattern in ["<script", "javascript:", "vbscript:"]
            ),
        }

    def sanitize_input(self, data: Any, data_type: str = "string") -> Dict[str, Any]:
        """Sanitize input data"""
        try:
            if not self.config.sanitization_config.enable_input_validation:
                return {"sanitized": data, "warnings": ["Input validation disabled"]}

            sanitization_result = {
                "original": data,
                "sanitized": data,
                "warnings": [],
                "errors": [],
                "sanitization_applied": [],
            }

            if data is None:
                return sanitization_result

            # Convert to string for processing
            if not isinstance(data, str):
                data = str(data)

            # Check for malicious patterns
            for pattern_name, pattern in self.sanitization_patterns.items():
                if re.search(pattern, data, re.IGNORECASE):
                    sanitization_result["warnings"].append(
                        f"Potential {pattern_name} detected"
                    )

                    if pattern_name == "sql_injection":
                        sanitization_result["sanitized"] = self._sanitize_sql_injection(
                            data
                        )
                        sanitization_result["sanitization_applied"].append(
                            "sql_injection_protection"
                        )
                    elif pattern_name == "xss":
                        sanitization_result["sanitized"] = self._sanitize_xss(data)
                        sanitization_result["sanitization_applied"].append(
                            "xss_protection"
                        )
                    elif pattern_name == "path_traversal":
                        sanitization_result["sanitized"] = (
                            self._sanitize_path_traversal(data)
                        )
                        sanitization_result["sanitization_applied"].append(
                            "path_traversal_protection"
                        )
                    elif pattern_name == "command_injection":
                        sanitization_result["sanitized"] = (
                            self._sanitize_command_injection(data)
                        )
                        sanitization_result["sanitization_applied"].append(
                            "command_injection_protection"
                        )

            # Apply type-specific validation
            if data_type in self.validation_rules:
                if not self.validation_rules[data_type](
                    sanitization_result["sanitized"]
                ):
                    sanitization_result["errors"].append(
                        f"Data does not match {data_type} format"
                    )
                    sanitization_result["sanitized"] = None

            return sanitization_result

        except Exception as e:
            logger.error(f"Input sanitization failed: {e}")
            return {"error": str(e)}

    def sanitize_output(self, data: Any, context: str = "general") -> Dict[str, Any]:
        """Sanitize output data"""
        try:
            if not self.config.sanitization_config.enable_output_sanitization:
                return {"sanitized": data, "warnings": ["Output sanitization disabled"]}

            sanitization_result = {
                "original": data,
                "sanitized": data,
                "context": context,
                "warnings": [],
                "sanitization_applied": [],
            }

            if data is None:
                return sanitization_result

            # Convert to string for processing
            if not isinstance(data, str):
                data = str(data)

            # Apply context-specific sanitization
            if context == "html":
                sanitization_result["sanitized"] = self._sanitize_html(data)
                sanitization_result["sanitization_applied"].append("html_sanitization")
            elif context == "json":
                sanitization_result["sanitized"] = self._sanitize_json(data)
                sanitization_result["sanitization_applied"].append("json_sanitization")
            elif context == "sql":
                sanitization_result["sanitized"] = self._sanitize_sql_output(data)
                sanitization_result["sanitization_applied"].append("sql_sanitization")
            else:
                # General sanitization
                sanitization_result["sanitized"] = self._sanitize_general(data)
                sanitization_result["sanitization_applied"].append(
                    "general_sanitization"
                )

            return sanitization_result

        except Exception as e:
            logger.error(f"Output sanitization failed: {e}")
            return {"error": str(e)}

    def _sanitize_sql_injection(self, data: str) -> str:
        """Sanitize SQL injection attempts"""
        # Remove or escape dangerous SQL patterns
        dangerous_patterns = [
            (
                r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
                "[SQL_KEYWORD]",
            ),
            (r"(--|#|/\*|\*/)", "[COMMENT]"),
            (r"(\b(OR|AND)\b\s+\d+\s*=\s*\d+)", "[LOGIC_EXPRESSION]"),
        ]

        sanitized = data
        for pattern, replacement in dangerous_patterns:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

        return sanitized

    def _sanitize_xss(self, data: str) -> str:
        """Sanitize XSS attempts"""
        # Remove or escape dangerous HTML/JavaScript patterns
        dangerous_patterns = [
            (r"<script[^>]*>.*?</script>", "[SCRIPT_TAG]"),
            (r"javascript:", "[JAVASCRIPT_PROTOCOL]"),
            (r"vbscript:", "[VBSCRIPT_PROTOCOL]"),
            (r"on\w+\s*=", "[EVENT_HANDLER]"),
            (r"<iframe[^>]*>", "[IFRAME_TAG]"),
        ]

        sanitized = data
        for pattern, replacement in dangerous_patterns:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

        return sanitized

    def _sanitize_path_traversal(self, data: str) -> str:
        """Sanitize path traversal attempts"""
        # Remove dangerous path patterns
        dangerous_patterns = [
            (r"\.\./", ""),
            (r"\.\.\\", ""),
            (r"/etc/", "[SYSTEM_PATH]"),
            (r"\\Windows\\", "[SYSTEM_PATH]"),
        ]

        sanitized = data
        for pattern, replacement in dangerous_patterns:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

        return sanitized

    def _sanitize_command_injection(self, data: str) -> str:
        """Sanitize command injection attempts"""
        # Remove dangerous command patterns
        dangerous_patterns = [
            (r"\b(cmd|powershell|bash|sh|exec|system)\b", "[COMMAND]"),
            (r"[;&|`$()]", "[SPECIAL_CHAR]"),
            (r"\b(rm|del|format|fdisk)\b", "[DANGEROUS_COMMAND]"),
        ]

        sanitized = data
        for pattern, replacement in dangerous_patterns:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

        return sanitized

    def _sanitize_html(self, data: str) -> str:
        """Sanitize HTML content"""
        # Basic HTML sanitization
        allowed_tags = ["p", "br", "strong", "em", "u", "ol", "ul", "li"]

        # Remove all HTML tags except allowed ones
        sanitized = re.sub(
            r"<(?!\/?(?:{})\b)[^>]+>".format("|".join(allowed_tags)), "", data
        )

        return sanitized

    def _sanitize_json(self, data: str) -> str:
        """Sanitize JSON content"""
        try:
            # Parse and re-serialize to ensure valid JSON
            parsed = json.loads(data)
            return json.dumps(parsed, ensure_ascii=False)
        except json.JSONDecodeError:
            # If not valid JSON, escape special characters
            return json.dumps(data, ensure_ascii=False)

    def _sanitize_sql_output(self, data: str) -> str:
        """Sanitize SQL output"""
        # Remove any remaining SQL patterns
        return self._sanitize_sql_injection(data)

    def _sanitize_general(self, data: str) -> str:
        """Apply general sanitization"""
        # Remove null bytes and control characters
        sanitized = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", data)

        # Normalize whitespace
        sanitized = re.sub(r"\s+", " ", sanitized).strip()

        return sanitized

    def validate_file_upload(
        self, file_path: str, allowed_extensions: List[str] = None
    ) -> Dict[str, Any]:
        """Validate file upload for security"""
        try:
            if not os.path.exists(file_path):
                return {"error": f"File not found: {file_path}"}

            validation_result = {
                "file_path": file_path,
                "file_size": os.path.getsize(file_path),
                "file_extension": Path(file_path).suffix.lower(),
                "is_valid": True,
                "warnings": [],
                "errors": [],
            }

            # Check file size
            max_size = self.config.sanitization_config.max_file_size_mb * 1024 * 1024
            if validation_result["file_size"] > max_size:
                validation_result["is_valid"] = False
                validation_result["errors"].append(
                    f"File size exceeds limit: {max_size} bytes"
                )

            # Check file extension
            if allowed_extensions is None:
                allowed_extensions = (
                    self.config.sanitization_config.allowed_file_extensions
                )

            if validation_result["file_extension"] not in allowed_extensions:
                validation_result["is_valid"] = False
                validation_result["errors"].append(
                    f"File extension not allowed: {validation_result['file_extension']}"
                )

            # Check for suspicious content
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(1024)  # Read first 1KB

                    # Check for suspicious patterns
                    for pattern_name, pattern in self.sanitization_patterns.items():
                        if re.search(pattern, content, re.IGNORECASE):
                            validation_result["warnings"].append(
                                f"Potential {pattern_name} detected in file content"
                            )
                            validation_result["is_valid"] = False

            except Exception:
                # Binary file or encoding issues
                validation_result["warnings"].append(
                    "Unable to read file content for pattern checking"
                )

            return validation_result

        except Exception as e:
            logger.error(f"File upload validation failed: {e}")
            return {"error": str(e)}


class DataSecurityManager:
    """Main data security manager"""

    def __init__(self, config: DataSecurityConfig):
        self.config = config
        self.leakage_detector = DataLeakageDetector(config)
        self.encryption = DataEncryption(config)
        self.sanitizer = DataSanitizer(config)
        self.security_events: List[DataSecurityEvent] = []

    def start_protection(self):
        """Start all data security protections"""
        try:
            logger.info("Starting data security protection")

            # Initialize all components
            if self.config.enable_encryption:
                self.encryption._init_encryption()

            if self.config.enable_data_sanitization:
                self.sanitizer._init_sanitization()

            logger.info("Data security protection started successfully")

        except Exception as e:
            logger.error(f"Failed to start data security protection: {e}")

    def scan_for_leakage(
        self, target: Union[str, Path], scan_type: str = "auto"
    ) -> Dict[str, Any]:
        """Scan for data leakage"""
        try:
            if scan_type == "auto":
                if os.path.isfile(target):
                    return self.leakage_detector.scan_file(target)
                elif os.path.isdir(target):
                    return self.leakage_detector.scan_directory(target)
                else:
                    return self.leakage_detector.scan_text(str(target))
            elif scan_type == "file":
                return self.leakage_detector.scan_file(target)
            elif scan_type == "directory":
                return self.leakage_detector.scan_directory(target)
            elif scan_type == "text":
                return self.leakage_detector.scan_text(str(target))
            else:
                return {"error": f"Unknown scan type: {scan_type}"}

        except Exception as e:
            logger.error(f"Leakage scan failed: {e}")
            return {"error": str(e)}

    def encrypt_data(
        self, data: Union[str, bytes], key_id: str = "symmetric"
    ) -> Dict[str, Any]:
        """Encrypt data"""
        return self.encryption.encrypt_data(data, key_id)

    def decrypt_data(
        self, encrypted_data: Dict[str, Any], key_id: str = "symmetric"
    ) -> Union[str, bytes, Dict[str, Any]]:
        """Decrypt data"""
        return self.encryption.decrypt_data(encrypted_data, key_id)

    def sanitize_input(self, data: Any, data_type: str = "string") -> Dict[str, Any]:
        """Sanitize input data"""
        return self.sanitizer.sanitize_input(data, data_type)

    def sanitize_output(self, data: Any, context: str = "general") -> Dict[str, Any]:
        """Sanitize output data"""
        return self.sanitizer.sanitize_output(data, context)

    def validate_file_upload(
        self, file_path: str, allowed_extensions: List[str] = None
    ) -> Dict[str, Any]:
        """Validate file upload"""
        return self.sanitizer.validate_file_upload(file_path, allowed_extensions)

    def get_security_status(self) -> Dict[str, Any]:
        """Get comprehensive data security status"""
        try:
            return {
                "encryption": {
                    "enabled": self.config.enable_encryption,
                    "keys_available": len(self.encryption.encryption_keys),
                },
                "sanitization": {
                    "enabled": self.config.enable_data_sanitization,
                    "patterns_loaded": len(self.sanitizer.sanitization_patterns),
                },
                "leakage_detection": {
                    "enabled": True,
                    "events_count": len(self.leakage_detector.leakage_events),
                },
                "total_security_events": len(self.security_events),
            }
        except Exception as e:
            logger.error(f"Failed to get security status: {e}")
            return {"error": str(e)}

    def cleanup(self):
        """Clean up data security resources"""
        try:
            # Clear sensitive data from memory
            if hasattr(self.encryption, "encryption_keys"):
                self.encryption.encryption_keys.clear()

            logger.info("Data security cleanup completed")
        except Exception as e:
            logger.error(f"Data security cleanup failed: {e}")


# Utility functions
def get_data_security_manager(config: DataSecurityConfig = None) -> DataSecurityManager:
    """Get data security manager instance"""
    if config is None:
        config = DataSecurityConfig()
    return DataSecurityManager(config)


def scan_for_data_leakage(
    target: Union[str, Path], scan_type: str = "auto"
) -> Dict[str, Any]:
    """Quick function to scan for data leakage"""
    config = DataSecurityConfig()
    manager = DataSecurityManager(config)
    return manager.scan_for_leakage(target, scan_type)


def encrypt_sensitive_data(data: Union[str, bytes]) -> Dict[str, Any]:
    """Quick function to encrypt sensitive data"""
    config = DataSecurityConfig()
    manager = DataSecurityManager(config)
    return manager.encrypt_data(data)


def sanitize_user_input(data: Any, data_type: str = "string") -> Dict[str, Any]:
    """Quick function to sanitize user input"""
    config = DataSecurityConfig()
    manager = DataSecurityManager(config)
    return manager.sanitize_input(data, data_type)
