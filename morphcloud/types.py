"""
Type Definitions Module for MorphCloud SDK

This module provides:
- Comprehensive type hints for all SDK components
- Type aliases for common patterns
- Type utilities and validation
- Protocol definitions for extensibility
"""

from typing import (
    Any,
    Dict,
    List,
    Optional,
    Union,
    TypeVar,
    Generic,
    Protocol,
    runtime_checkable,
    TypedDict,
    Literal,
    NewType,
    Iterator,
)
from pathlib import Path

# Type variables
T = TypeVar("T")
K = TypeVar("K")
V = TypeVar("V")
R = TypeVar("R")

# Basic type aliases
JSONValue = Union[
    str, int, float, bool, None, List["JSONValue"], Dict[str, "JSONValue"]
]
JSONDict = Dict[str, JSONValue]
JSONList = List[JSONValue]

# String type aliases
Hostname = NewType("Hostname", str)
Port = NewType("Port", int)
URL = NewType("URL", str)
APIKey = NewType("APIKey", str)
Token = NewType("Token", str)

# Numeric type aliases
Timeout = NewType("Timeout", float)
RetryCount = NewType("RetryCount", int)
BatchSize = NewType("BatchSize", int)
CacheSize = NewType("CacheSize", int)

# File and path type aliases
FilePath = Union[str, Path]
DirectoryPath = Union[str, Path]

# Network type aliases
IPAddress = NewType("IPAddress", str)
MACAddress = NewType("MACAddress", str)

# Security type aliases
SSHKey = NewType("SSHKey", str)
SSHFingerprint = NewType("SSHFingerprint", str)

# Performance type aliases
Duration = NewType("Duration", float)
MemorySize = NewType("MemorySize", int)
CPUCores = NewType("CPUCores", int)

# Configuration type aliases
ConfigValue = Union[str, int, float, bool, List[str], Dict[str, Any]]
ConfigDict = Dict[str, ConfigValue]

# Error type aliases
ErrorMessage = NewType("ErrorMessage", str)
ErrorCode = NewType("ErrorCode", str)

# API type aliases
APIResponse = Dict[str, Any]
APIRequest = Dict[str, Any]
APIEndpoint = NewType("APIEndpoint", str)

# SSH type aliases
SSHCommand = NewType("SSHCommand", str)
SSHOutput = NewType("SSHOutput", str)
SSHExitCode = NewType("SSHExitCode", int)

# Docker type aliases
DockerImage = NewType("DockerImage", str)
DockerTag = NewType("DockerTag", str)
DockerContainer = NewType("DockerContainer", str)

# Instance type aliases
InstanceID = NewType("InstanceID", str)
InstanceName = NewType("InstanceName", str)
InstanceType = NewType("InstanceType", str)
InstanceStatus = NewType("InstanceStatus", str)

# User type aliases
UserID = NewType("UserID", str)
Username = NewType("Username", str)
Email = NewType("Email", str)

# Project type aliases
ProjectID = NewType("ProjectID", str)
ProjectName = NewType("ProjectName", str)

# Resource type aliases
ResourceID = NewType("ResourceID", str)
ResourceType = NewType("ResourceType", str)
ResourceStatus = NewType("ResourceStatus", str)

# Logging type aliases
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
LogMessage = NewType("LogMessage", str)

# Environment type aliases
Environment = Literal["development", "staging", "production", "testing"]

# Security level type aliases
SecurityLevel = Literal["permissive", "standard", "strict", "paranoid"]

# Metric type aliases
MetricType = Literal["counter", "gauge", "histogram", "timer"]
MetricValue = Union[int, float]
MetricTags = Dict[str, str]

# Cache type aliases
CacheKey = NewType("CacheKey", str)
CacheValue = Any
CacheTTL = NewType("CacheTTL", int)

# Batch type aliases
BatchID = NewType("BatchID", str)
BatchData = List[Any]

# Connection type aliases
ConnectionID = NewType("ConnectionID", str)
ConnectionState = Literal["idle", "active", "closed", "error"]

# Task type aliases
TaskID = NewType("TaskID", str)
TaskStatus = Literal["pending", "running", "completed", "failed", "cancelled"]

# Event type aliases
EventType = NewType("EventType", str)
EventData = Dict[str, Any]
EventTimestamp = NewType("EventTimestamp", float)


# Protocol definitions for extensibility
@runtime_checkable
class Configurable(Protocol):
    """Protocol for configurable objects"""

    def get_config(self) -> ConfigDict:
        """Get current configuration"""
        ...

    def set_config(self, config: ConfigDict) -> None:
        """Set configuration"""
        ...

    def validate_config(self, config: ConfigDict) -> List[str]:
        """Validate configuration and return errors"""
        ...


@runtime_checkable
class Loggable(Protocol):
    """Protocol for loggable objects"""

    def log(self, level: LogLevel, message: LogMessage, **kwargs: Any) -> None:
        """Log a message"""
        ...

    def get_logger(self) -> Any:
        """Get the logger instance"""
        ...


@runtime_checkable
class Cacheable(Protocol):
    """Protocol for cacheable objects"""

    def get_cache_key(self) -> CacheKey:
        """Get cache key for this object"""
        ...

    def get_cache_ttl(self) -> CacheTTL:
        """Get cache TTL for this object"""
        ...

    def is_cacheable(self) -> bool:
        """Check if object is cacheable"""
        ...


@runtime_checkable
class Retryable(Protocol):
    """Protocol for retryable operations"""

    def should_retry(self, error: Exception) -> bool:
        """Check if operation should be retried"""
        ...

    def get_retry_delay(self, attempt: int) -> Duration:
        """Get delay before next retry attempt"""
        ...

    def get_max_retries(self) -> RetryCount:
        """Get maximum number of retries"""
        ...


@runtime_checkable
class AsyncOperation(Protocol):
    """Protocol for async operations"""

    async def execute(self, **kwargs: Any) -> Any:
        """Execute the async operation"""
        ...

    async def cancel(self) -> None:
        """Cancel the operation"""
        ...

    def is_running(self) -> bool:
        """Check if operation is running"""
        ...


@runtime_checkable
class ResourceManager(Protocol):
    """Protocol for resource managers"""

    def create_resource(self, resource_type: ResourceType, **kwargs: Any) -> ResourceID:
        """Create a new resource"""
        ...

    def delete_resource(self, resource_id: ResourceID) -> bool:
        """Delete a resource"""
        ...

    def get_resource(self, resource_id: ResourceID) -> Optional[Dict[str, Any]]:
        """Get resource information"""
        ...

    def list_resources(
        self, resource_type: Optional[ResourceType] = None
    ) -> List[ResourceID]:
        """List available resources"""
        ...


# TypedDict definitions for structured data
class InstanceConfig(TypedDict, total=False):
    """Instance configuration structure"""

    name: InstanceName
    type: InstanceType
    image: DockerImage
    tag: DockerTag
    cpu_cores: CPUCores
    memory_size: MemorySize
    disk_size: MemorySize
    environment: Environment
    security_level: SecurityLevel


class SSHConfig(TypedDict, total=False):
    """SSH configuration structure"""

    hostname: Hostname
    port: Port
    username: Username
    key_path: Optional[FilePath]
    password: Optional[str]
    timeout: Timeout
    host_key_verification: bool


class APIConfig(TypedDict, total=False):
    """API configuration structure"""

    base_url: URL
    api_key: APIKey
    timeout: Timeout
    max_retries: RetryCount
    retry_delay: Duration
    user_agent: str


class PerformanceConfig(TypedDict, total=False):
    """Performance configuration structure"""

    enable_caching: bool
    cache_ttl: CacheTTL
    max_cache_size: CacheSize
    enable_lazy_loading: bool
    batch_size: BatchSize
    max_concurrent_requests: RetryCount


class SecurityConfig(TypedDict, total=False):
    """Security configuration structure"""

    ssh_host_key_verification: bool
    command_sanitization: bool
    secure_temp_dirs: bool
    default_bind_host: IPAddress
    allow_external_binding: bool
    http_timeout_default: Timeout


class LoggingConfig(TypedDict, total=False):
    """Logging configuration structure"""

    level: LogLevel
    format: str
    file_path: Optional[FilePath]
    max_file_size: MemorySize
    backup_count: int
    enable_console: bool
    enable_file: bool


# Generic container types
class TypedList(Generic[T]):
    """Generic typed list"""

    def __init__(self, items: Optional[List[T]] = None):
        self._items = items or []

    def append(self, item: T) -> None:
        """Add item to list"""
        self._items.append(item)

    def extend(self, items: List[T]) -> None:
        """Extend list with items"""
        self._items.extend(items)

    def __getitem__(self, index: int) -> T:
        """Get item by index"""
        return self._items[index]

    def __len__(self) -> int:
        """Get list length"""
        return len(self._items)

    def __iter__(self) -> Iterator[T]:
        """Iterate over items"""
        return iter(self._items)


class TypedDict(Generic[K, V]):
    """Generic typed dictionary"""

    def __init__(self, items: Optional[Dict[K, V]] = None):
        self._items = items or {}

    def __getitem__(self, key: K) -> V:
        """Get value by key"""
        return self._items[key]

    def __setitem__(self, key: K, value: V) -> None:
        """Set value for key"""
        self._items[key] = value

    def __len__(self) -> int:
        """Get dictionary length"""
        return len(self._items)

    def __iter__(self) -> Iterator[K]:
        """Iterate over keys"""
        return iter(self._items)


# Type validation utilities
def is_valid_hostname(hostname: str) -> bool:
    """Validate hostname format"""
    if not hostname or len(hostname) > 253:
        return False
    if hostname.startswith(".") or hostname.endswith("."):
        return False
    return all(part.isalnum() or part == "-" for part in hostname.split("."))


def is_valid_port(port: int) -> bool:
    """Validate port number"""
    return 1 <= port <= 65535


def is_valid_ip_address(ip: str) -> bool:
    """Validate IP address format"""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def is_valid_url(url: str) -> bool:
    """Validate URL format"""
    return url.startswith(("http://", "https://", "ssh://"))


def is_valid_email(email: str) -> bool:
    """Validate email format"""
    import re

    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


# Type conversion utilities
def to_hostname(value: str) -> Hostname:
    """Convert string to Hostname type"""
    if not is_valid_hostname(value):
        raise ValueError(f"Invalid hostname: {value}")
    return Hostname(value)


def to_port(value: int) -> Port:
    """Convert int to Port type"""
    if not is_valid_port(value):
        raise ValueError(f"Invalid port: {value}")
    return Port(value)


def to_ip_address(value: str) -> IPAddress:
    """Convert string to IPAddress type"""
    if not is_valid_ip_address(value):
        raise ValueError(f"Invalid IP address: {value}")
    return IPAddress(value)


def to_url(value: str) -> URL:
    """Convert string to URL type"""
    if not is_valid_url(value):
        raise ValueError(f"Invalid URL: {value}")
    return URL(value)


def to_email(value: str) -> Email:
    """Convert string to Email type"""
    if not is_valid_email(value):
        raise ValueError(f"Invalid email: {value}")
    return Email(value)


# Type checking utilities
def ensure_type(value: Any, expected_type: type) -> Any:
    """Ensure value is of expected type"""
    if not isinstance(value, expected_type):
        raise TypeError(
            f"Expected {expected_type.__name__}, got {type(value).__name__}"
        )
    return value


def ensure_optional_type(value: Any, expected_type: type) -> Optional[Any]:
    """Ensure value is of expected type or None"""
    if value is not None and not isinstance(value, expected_type):
        raise TypeError(
            f"Expected {expected_type.__name__} or None, got {type(value).__name__}"
        )
    return value


def ensure_union_type(value: Any, expected_types: tuple) -> Any:
    """Ensure value is one of expected types"""
    if not isinstance(value, expected_types):
        type_names = [t.__name__ for t in expected_types]
        raise TypeError(f"Expected one of {type_names}, got {type(value).__name__}")
    return value
