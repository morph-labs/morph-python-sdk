"""
Security Configuration Module for MorphCloud SDK

This module implements secure by design principles and provides centralized
security controls for the entire SDK. It includes:

1. Security policy configuration
2. Input validation and sanitization
3. Secure defaults
4. Security event logging
5. Environment-based security controls
"""

import os
import logging
import tempfile
import shlex
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import hmac


class SecurityLevel(Enum):
    """Security levels for different deployment environments"""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class SecurityPolicy(Enum):
    """Available security policies"""

    PERMISSIVE = "permissive"  # Development only
    STANDARD = "standard"  # Default
    STRICT = "strict"  # Production recommended
    PARANOID = "paranoid"  # High security environments


@dataclass
class SecurityConfig:
    """Centralized security configuration"""

    # Environment and policy
    security_level: SecurityLevel = SecurityLevel.PRODUCTION
    security_policy: SecurityPolicy = SecurityPolicy.STANDARD

    # SSH Security
    ssh_host_key_verification: bool = True
    ssh_known_hosts_file: Optional[str] = None
    ssh_connection_timeout: int = 30
    ssh_auth_timeout: int = 30

    # Command Execution Security
    command_sanitization: bool = True
    command_allowlist: List[str] = field(default_factory=list)
    command_blocklist: List[str] = field(default_factory=list)
    max_command_length: int = 1000

    # File Security
    secure_temp_dirs: bool = True
    temp_dir_permissions: int = 0o700
    max_file_size: int = 100 * 1024 * 1024  # 100MB

    # Network Security
    default_bind_host: str = "127.0.0.1"
    allow_external_binding: bool = False
    http_timeout_default: int = 30
    max_redirects: int = 5

    # Logging and Monitoring
    security_logging: bool = True
    log_sensitive_operations: bool = True
    audit_trail: bool = True

    def __post_init__(self):
        """Initialize security configuration based on environment"""
        self._load_environment_config()
        self._validate_config()

    def _load_environment_config(self):
        """Load configuration from environment variables"""
        # Security level
        env_level = os.getenv("MORPHCLOUD_SECURITY_LEVEL", "").upper()
        if env_level in [e.name for e in SecurityLevel]:
            self.security_level = SecurityLevel(env_level)

        # Security policy
        env_policy = os.getenv("MORPHCLOUD_SECURITY_POLICY", "").upper()
        if env_policy in [e.name for e in SecurityPolicy]:
            self.security_policy = SecurityPolicy(env_policy)

        # SSH settings
        if os.getenv("MORPHCLOUD_SSH_HOST_KEY_VERIFICATION", "").lower() == "false":
            self.ssh_host_key_verification = False

        # Command security
        if os.getenv("MORPHCLOUD_COMMAND_SANITIZATION", "").lower() == "false":
            self.command_sanitization = False

        # Network security
        if os.getenv("MORPHCLOUD_ALLOW_EXTERNAL_BINDING", "").lower() == "true":
            self.allow_external_binding = True

    def _validate_config(self):
        """Validate security configuration"""
        if self.security_level == SecurityLevel.PRODUCTION:
            if self.security_policy == SecurityPolicy.PERMISSIVE:
                raise ValueError("Cannot use permissive policy in production")
            if not self.ssh_host_key_verification:
                raise ValueError("SSH host key verification required in production")
            if not self.command_sanitization:
                raise ValueError("Command sanitization required in production")

        if self.security_policy == SecurityPolicy.PARANOID:
            if self.allow_external_binding:
                raise ValueError("External binding not allowed in paranoid mode")


class SecurityManager:
    """Manages security operations and enforcement"""

    def __init__(self, config: SecurityConfig):
        self.config = config
        self.logger = logging.getLogger("morphcloud.security")
        self._setup_logging()

    def _setup_logging(self):
        """Setup security logging"""
        if self.config.security_logging:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def log_security_event(
        self, event_type: str, details: Dict[str, Any], level: str = "INFO"
    ):
        """Log security events"""
        if not self.config.security_logging:
            return

        log_entry = {
            "event_type": event_type,
            "details": details,
            "timestamp": logging.Formatter().formatTime(
                logging.LogRecord("", 0, "", 0, "", (), None)
            ),
            "security_level": self.config.security_level.value,
            "security_policy": self.config.security_policy.value,
        }

        if level.upper() == "WARNING":
            self.logger.warning("Security event: %s", log_entry)
        elif level.upper() == "ERROR":
            self.logger.error("Security event: %s", log_entry)
        else:
            self.logger.info("Security event: %s", log_entry)

    def sanitize_command(self, command: str) -> str:
        """Sanitize command input to prevent injection attacks"""
        if not self.config.command_sanitization:
            return command

        # Check command length
        if len(command) > self.config.max_command_length:
            self.log_security_event(
                "command_too_long",
                {
                    "command_length": len(command),
                    "max_length": self.config.max_command_length,
                },
                "WARNING",
            )
            raise ValueError(
                f"Command too long: {len(command)} > {self.config.max_command_length}"
            )

        # Check blocklist
        for blocked in self.config.command_blocklist:
            if blocked.lower() in command.lower():
                self.log_security_event(
                    "blocked_command",
                    {"command": command, "blocked_pattern": blocked},
                    "ERROR",
                )
                raise ValueError(f"Command blocked: contains '{blocked}'")

        # Apply allowlist if configured
        if self.config.command_allowlist:
            allowed = False
            for pattern in self.config.command_allowlist:
                if pattern.lower() in command.lower():
                    allowed = True
                    break
            if not allowed:
                self.log_security_event(
                    "command_not_allowed",
                    {
                        "command": command,
                        "allowed_patterns": self.config.command_allowlist,
                    },
                    "ERROR",
                )
                raise ValueError(f"Command not allowed: {command}")

        # Use shlex.quote for shell escaping
        sanitized = shlex.quote(command)

        self.log_security_event(
            "command_sanitized", {"original": command, "sanitized": sanitized}, "INFO"
        )

        return sanitized

    def create_secure_temp_dir(self, prefix: str = "morphcloud-") -> str:
        """Create a secure temporary directory"""
        if self.config.secure_temp_dirs:
            temp_dir = tempfile.mkdtemp(prefix=prefix)
            os.chmod(temp_dir, self.config.temp_dir_permissions)

            self.log_security_event(
                "temp_dir_created",
                {
                    "path": temp_dir,
                    "permissions": oct(self.config.temp_dir_permissions),
                },
                "INFO",
            )

            return temp_dir
        else:
            # Fallback to system default (less secure)
            return tempfile.mkdtemp(prefix=prefix)

    def validate_file_path(self, file_path: str) -> str:
        """Validate and sanitize file paths"""
        # Prevent directory traversal
        if ".." in file_path or file_path.startswith("/"):
            self.log_security_event(
                "suspicious_file_path", {"file_path": file_path}, "WARNING"
            )
            raise ValueError(f"Suspicious file path: {file_path}")

        # Normalize path
        normalized = os.path.normpath(file_path)

        self.log_security_event(
            "file_path_validated",
            {"original": file_path, "normalized": normalized},
            "INFO",
        )

        return normalized

    def get_secure_bind_host(self, requested_host: Optional[str] = None) -> str:
        """Get secure binding host address"""
        if requested_host:
            if requested_host == "0.0.0.0" and not self.config.allow_external_binding:
                self.log_security_event(
                    "external_binding_denied",
                    {"requested_host": requested_host},
                    "WARNING",
                )
                return self.config.default_bind_host
            return requested_host

        return self.config.default_bind_host

    def validate_http_timeout(self, timeout: Optional[int]) -> int:
        """Validate and return secure HTTP timeout"""
        if timeout is None:
            return self.config.http_timeout_default

        # Ensure reasonable timeout values
        if timeout < 1:
            self.log_security_event(
                "invalid_timeout", {"timeout": timeout, "min_timeout": 1}, "WARNING"
            )
            return 1
        elif timeout > 300:  # 5 minutes max
            self.log_security_event(
                "timeout_too_long", {"timeout": timeout, "max_timeout": 300}, "WARNING"
            )
            return 300

        return timeout


# Global security configuration
_security_config = SecurityConfig()
_security_manager = SecurityManager(_security_config)


def get_security_config() -> SecurityConfig:
    """Get the global security configuration"""
    return _security_config


def get_security_manager() -> SecurityManager:
    """Get the global security manager"""
    return _security_manager


def update_security_config(**kwargs) -> None:
    """Update security configuration (use with caution)"""
    global _security_config, _security_manager

    for key, value in kwargs.items():
        if hasattr(_security_config, key):
            setattr(_security_config, key, value)

    # Recreate security manager with new config
    _security_manager = SecurityManager(_security_config)


def log_security_event(
    event_type: str, details: Dict[str, Any], level: str = "INFO"
) -> None:
    """Log a security event using the global security manager"""
    _security_manager.log_security_event(event_type, details, level)


def sanitize_command(command: str) -> str:
    """Sanitize a command using the global security manager"""
    return _security_manager.sanitize_command(command)


def create_secure_temp_dir(prefix: str = "morphcloud-") -> str:
    """Create a secure temporary directory using the global security manager"""
    return _security_manager.create_secure_temp_dir(prefix)


def validate_file_path(file_path: str) -> str:
    """Validate a file path using the global security manager"""
    return _security_manager.validate_file_path(file_path)


def get_secure_bind_host(requested_host: Optional[str] = None) -> str:
    """Get a secure binding host using the global security manager"""
    return _security_manager.get_secure_bind_host(requested_host)


def validate_http_timeout(timeout: Optional[int]) -> int:
    """Validate HTTP timeout using the global security manager"""
    return _security_manager.validate_http_timeout(timeout)
