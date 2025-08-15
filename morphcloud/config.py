"""
Configuration Management Module for MorphCloud SDK

This module provides:
- Centralized configuration management
- Environment-based configuration
- Configuration validation and defaults
- Secure configuration handling
"""

import os
import json
from typing import Any, Dict, Optional, Union, List
from dataclasses import dataclass, field
from enum import Enum
import logging
from pathlib import Path
import yaml


class Environment(Enum):
    """Deployment environments"""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TESTING = "testing"


class LogLevel(Enum):
    """Logging levels"""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass
class APIConfig:
    """API configuration settings"""

    base_url: str = "https://api.morphcloud.com"
    timeout: int = 30
    max_retries: int = 3
    retry_delay: float = 1.0
    api_key: Optional[str] = None
    user_agent: str = "MorphCloud-Python-SDK/1.0"

    def __post_init__(self):
        # Load from environment if not set
        if not self.api_key:
            self.api_key = os.getenv("MORPHCLOUD_API_KEY")
        if not self.base_url:
            self.base_url = os.getenv("MORPHCLOUD_BASE_URL", self.base_url)


@dataclass
class SecurityConfig:
    """Security configuration settings"""

    ssh_host_key_verification: bool = True
    command_sanitization: bool = True
    secure_temp_dirs: bool = True
    default_bind_host: str = "127.0.0.1"
    allow_external_binding: bool = False
    http_timeout_default: int = 30
    security_logging: bool = True

    def __post_init__(self):
        # Load from environment
        self.ssh_host_key_verification = (
            os.getenv(
                "MORPHCLOUD_SSH_HOST_KEY_VERIFICATION",
                str(self.ssh_host_key_verification),
            ).lower()
            == "true"
        )

        self.command_sanitization = (
            os.getenv(
                "MORPHCLOUD_COMMAND_SANITIZATION", str(self.command_sanitization)
            ).lower()
            == "true"
        )


@dataclass
class PerformanceConfig:
    """Performance configuration settings"""

    enable_caching: bool = True
    cache_ttl: int = 300
    max_cache_size: int = 1000
    enable_lazy_loading: bool = True
    batch_size: int = 10
    max_concurrent_requests: int = 10
    connection_pool_size: int = 10

    def __post_init__(self):
        # Load from environment
        self.enable_caching = (
            os.getenv("MORPHCLOUD_ENABLE_CACHING", str(self.enable_caching)).lower()
            == "true"
        )

        cache_ttl_env = os.getenv("MORPHCLOUD_CACHE_TTL")
        if cache_ttl_env:
            self.cache_ttl = int(cache_ttl_env)


@dataclass
class LoggingConfig:
    """Logging configuration settings"""

    level: LogLevel = LogLevel.INFO
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path: Optional[str] = None
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5
    enable_console: bool = True
    enable_file: bool = False

    def __post_init__(self):
        # Load from environment
        level_env = os.getenv("MORPHCLOUD_LOG_LEVEL")
        if level_env:
            try:
                self.level = LogLevel(level_env.upper())
            except ValueError:
                pass

        self.enable_console = (
            os.getenv(
                "MORPHCLOUD_ENABLE_CONSOLE_LOGGING", str(self.enable_console)
            ).lower()
            == "true"
        )

        self.enable_file = (
            os.getenv("MORPHCLOUD_ENABLE_FILE_LOGGING", str(self.enable_file)).lower()
            == "true"
        )


@dataclass
class Config:
    """Main configuration class"""

    environment: Environment = Environment.PRODUCTION
    api: APIConfig = field(default_factory=APIConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    # Additional settings
    debug_mode: bool = False
    config_file_path: Optional[str] = None

    def __post_init__(self):
        # Load from environment
        env_name = os.getenv("MORPHCLOUD_ENVIRONMENT", "production")
        try:
            self.environment = Environment(env_name.lower())
        except ValueError:
            self.environment = Environment.PRODUCTION

        self.debug_mode = (
            os.getenv("MORPHCLOUD_DEBUG_MODE", str(self.debug_mode)).lower() == "true"
        )

        # Load from config file if specified
        if self.config_file_path:
            self.load_from_file(self.config_file_path)
        else:
            # Try to find config file in common locations
            self._load_default_config()

    def _load_default_config(self):
        """Load configuration from default locations"""
        config_paths = [
            "morphcloud.yaml",
            "morphcloud.yml",
            "config/morphcloud.yaml",
            "config/morphcloud.yml",
            os.path.expanduser("~/.morphcloud/config.yaml"),
            os.path.expanduser("~/.morphcloud/config.yml"),
        ]

        for path in config_paths:
            if os.path.exists(path):
                self.load_from_file(path)
                break

    def load_from_file(self, file_path: str):
        """Load configuration from a file"""
        try:
            path = Path(file_path)
            if path.suffix.lower() in [".yaml", ".yml"]:
                with open(path, "r") as f:
                    config_data = yaml.safe_load(f)
            elif path.suffix.lower() == ".json":
                with open(path, "r") as f:
                    config_data = json.load(f)
            else:
                logging.warning(f"Unsupported config file format: {path.suffix}")
                return

            self._update_from_dict(config_data)
            logging.info(f"Configuration loaded from {file_path}")

        except Exception as e:
            logging.error(f"Failed to load configuration from {file_path}: {e}")

    def _update_from_dict(self, config_data: Dict[str, Any]):
        """Update configuration from dictionary"""
        if not isinstance(config_data, dict):
            return

        # Update main settings
        if "environment" in config_data:
            try:
                self.environment = Environment(config_data["environment"].lower())
            except ValueError:
                pass

        if "debug_mode" in config_data:
            self.debug_mode = config_data["debug_mode"]

        # Update sub-configs
        if "api" in config_data:
            self._update_api_config(config_data["api"])

        if "security" in config_data:
            self._update_security_config(config_data["security"])

        if "performance" in config_data:
            self._update_performance_config(config_data["performance"])

        if "logging" in config_data:
            self._update_logging_config(config_data["logging"])

    def _update_api_config(self, api_data: Dict[str, Any]):
        """Update API configuration"""
        for key, value in api_data.items():
            if hasattr(self.api, key):
                setattr(self.api, key, value)

    def _update_security_config(self, security_data: Dict[str, Any]):
        """Update security configuration"""
        for key, value in security_data.items():
            if hasattr(self.security, key):
                setattr(self.security, key, value)

    def _update_performance_config(self, performance_data: Dict[str, Any]):
        """Update performance configuration"""
        for key, value in performance_data.items():
            if hasattr(self.performance, key):
                setattr(self.performance, key, value)

    def _update_logging_config(self, logging_data: Dict[str, Any]):
        """Update logging configuration"""
        for key, value in logging_data.items():
            if hasattr(self.logging, key):
                if key == "level" and isinstance(value, str):
                    try:
                        value = LogLevel(value.upper())
                    except ValueError:
                        pass
                setattr(self.logging, key, value)

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            "environment": self.environment.value,
            "debug_mode": self.debug_mode,
            "api": {
                "base_url": self.api.base_url,
                "timeout": self.api.timeout,
                "max_retries": self.api.max_retries,
                "retry_delay": self.api.retry_delay,
                "user_agent": self.api.user_agent,
            },
            "security": {
                "ssh_host_key_verification": self.security.ssh_host_key_verification,
                "command_sanitization": self.security.command_sanitization,
                "secure_temp_dirs": self.security.secure_temp_dirs,
                "default_bind_host": self.security.default_bind_host,
                "allow_external_binding": self.security.allow_external_binding,
                "http_timeout_default": self.security.http_timeout_default,
                "security_logging": self.security.security_logging,
            },
            "performance": {
                "enable_caching": self.performance.enable_caching,
                "cache_ttl": self.performance.cache_ttl,
                "max_cache_size": self.performance.max_cache_size,
                "enable_lazy_loading": self.performance.enable_lazy_loading,
                "batch_size": self.performance.batch_size,
                "max_concurrent_requests": self.performance.max_concurrent_requests,
                "connection_pool_size": self.performance.connection_pool_size,
            },
            "logging": {
                "level": self.logging.level.value,
                "format": self.logging.format,
                "file_path": self.logging.file_path,
                "max_file_size": self.logging.max_file_size,
                "backup_count": self.logging.backup_count,
                "enable_console": self.logging.enable_console,
                "enable_file": self.logging.enable_file,
            },
        }

    def save_to_file(self, file_path: str, format: str = "yaml"):
        """Save configuration to a file"""
        try:
            config_data = self.to_dict()
            path = Path(file_path)

            if format.lower() == "yaml":
                with open(path, "w") as f:
                    yaml.dump(config_data, f, default_flow_style=False, indent=2)
            elif format.lower() == "json":
                with open(path, "w") as f:
                    json.dump(config_data, f, indent=2)
            else:
                raise ValueError(f"Unsupported format: {format}")

            logging.info(f"Configuration saved to {file_path}")

        except Exception as e:
            logging.error(f"Failed to save configuration to {file_path}: {e}")

    def validate(self) -> List[str]:
        """Validate configuration and return list of errors"""
        errors = []

        # Validate API config
        if not self.api.base_url:
            errors.append("API base URL is required")
        if self.api.timeout <= 0:
            errors.append("API timeout must be positive")
        if self.api.max_retries < 0:
            errors.append("API max retries must be non-negative")

        # Validate security config
        if self.security.http_timeout_default <= 0:
            errors.append("HTTP timeout must be positive")

        # Validate performance config
        if self.performance.cache_ttl <= 0:
            errors.append("Cache TTL must be positive")
        if self.performance.max_cache_size <= 0:
            errors.append("Max cache size must be positive")
        if self.performance.batch_size <= 0:
            errors.append("Batch size must be positive")

        # Validate logging config
        if self.logging.max_file_size <= 0:
            errors.append("Max file size must be positive")
        if self.logging.backup_count < 0:
            errors.append("Backup count must be non-negative")

        return errors


# Global configuration instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get the global configuration instance"""
    global _config
    if _config is None:
        _config = Config()
    return _config


def set_config(config: Config):
    """Set the global configuration instance"""
    global _config
    _config = config


def reload_config():
    """Reload configuration from sources"""
    global _config
    _config = Config()


def get_api_config() -> APIConfig:
    """Get API configuration"""
    return get_config().api


def get_security_config() -> SecurityConfig:
    """Get security configuration"""
    return get_config().security


def get_performance_config() -> PerformanceConfig:
    """Get performance configuration"""
    return get_config().performance


def get_logging_config() -> LoggingConfig:
    """Get logging configuration"""
    return get_config().logging
