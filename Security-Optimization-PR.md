# MorphCloud Python SDK - Security + Optimization Guide

## Table of Contents

1. [Quick Start](#quick-start)
2. [Security Architecture](#security-architecture)
3. [Performance Optimization](#performance-optimization)
4. [Advanced Features](#advanced-features)
5. [Configuration Management](#configuration-management)
6. [Error Handling](#error-handling)
7. [Monitoring & Observability](#monitoring--observability)
8. [Testing & Validation](#testing--validation)
9.  [Red Team Testing Framework](#red-team-testing-framework)
10. [Implementation Status](#implementation-status)
11. [Best Practices](#best-practices)
12. [Troubleshooting](#troubleshooting)

The MorphCloud Python SDK is a platform for creating, managing, and interacting with remote AI development environments called runtimes. This guide covers all the advanced security, performance, and optimization features implemented during the Red Team + Optimization Sweep.

## Quick Start

### 1. Basic Setup

```python
from morphcloud.config import get_config, set_config
from morphcloud.security import get_security_config
from morphcloud.performance import get_global_monitor
from morphcloud.monitoring import start_monitoring, get_health_status

# Initialize configuration
config = get_config()
print(f"Environment: {config.environment.value}")
print(f"Security Level: {config.security.security_level}")

# Start monitoring
start_monitoring()

# Check system health
health = get_health_status()
print(f"System Health: {health['overall_status']}")
```

### 2. Security Configuration

```python
from morphcloud.security import SecurityConfig, SecurityLevel, SecurityPolicy

# Create custom security configuration
security_config = SecurityConfig(
    security_level=SecurityLevel.PRODUCTION,
    security_policy=SecurityPolicy.STRICT,
    ssh_host_key_verification=True,
    command_sanitization=True,
    secure_temp_dirs=True,
    default_bind_host="127.0.0.1",
    allow_external_binding=False,
    http_timeout_default=30,
    security_logging=True
)

# Apply security configuration
from morphcloud.security import set_security_config
set_security_config(security_config)
```

## Security Architecture

### Security Levels

The SDK supports different security levels based on deployment environment:

- **DEVELOPMENT**: Permissive policies for development/testing
- **STAGING**: Standard security policies
- **PRODUCTION**: Strict security policies (default)
- **PARANOID**: Maximum security for high-risk environments

### Critical Security Fixes Implemented

#### 1. SSH Host Key Verification (HIGH RISK - FIXED)

**Vulnerability**: SSH clients were using `AutoAddPolicy()` which automatically trusted unknown host keys.

**Fix Implemented**:
```python
# Before (INSECURE)
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# After (SECURE)
client.set_missing_host_key_policy(paramiko.RejectPolicy())
known_hosts_file = os.path.expanduser("~/.ssh/known_hosts")
if os.path.exists(known_hosts_file):
    client.load_host_keys(known_hosts_file)
```

#### 2. Command Injection Prevention (MEDIUM RISK - FIXED)

**Vulnerability**: SSH command execution without proper input sanitization.

**Fix Implemented**:
```python
# Before (INSECURE)
channel.exec_command(command)

# After (SECURE)
import shlex
sanitized_command = shlex.quote(command)
channel.exec_command(sanitized_command)
```

#### 3. Secure Temporary File Usage (MEDIUM RISK - FIXED)

**Vulnerability**: Hardcoded `/tmp` paths could lead to path traversal.

**Fix Implemented**:
```python
# Before (INSECURE)
build_dir = build_context or "/tmp/docker-build"

# After (SECURE)
import tempfile
if build_context:
    build_dir = build_context
else:
    temp_base = tempfile.mkdtemp(prefix="docker-build-")
    build_dir = os.path.join(temp_base, "build")
```

### Container Security & Sandboxing

```python
from morphcloud.container_security import (
    ContainerSecurityConfig, SecurityLevel, get_container_security_manager
)

# Configure container security
config = ContainerSecurityConfig(
    security_level=SecurityLevel.HIGH,
    enable_scanning=True,
    enable_runtime_protection=True,
    enable_resource_monitoring=True
)

# Get security manager
manager = get_container_security_manager(config)

# Scan image for vulnerabilities
scan_result = manager.scanner.scan_image("python:3.9-slim")
print(f"Image security score: {scan_result['security_score']}")

# Create secure container
container_result = manager.secure_container(
    "python:3.9-slim", 
    container_name="secure-python-app"
)
```

### Zero-Trust Architecture

```python
from morphcloud.zero_trust import (
    ZeroTrustConfig, TrustLevel, get_zero_trust_manager
)

# Configure zero-trust system
config = ZeroTrustConfig(
    trust_level=TrustLevel.HIGH,
    authentication_method=AuthenticationMethod.MTLS,
    enable_service_mesh=True,
    enable_api_gateway=True,
    enable_secret_management=True
)

# Get zero-trust manager
manager = get_zero_trust_manager(config)

# Register a new service
service_result = manager.register_service(
    service_id="api-gateway",
    service_name="API Gateway Service",
    trust_level=TrustLevel.HIGH,
    capabilities=["read", "write", "admin"]
)
```

## Performance Optimization

### 1. Basic Performance Monitoring

```python
from morphcloud.performance import (
    PerformanceMonitor, 
    performance_monitor, 
    record_timing,
    get_performance_summary
)

# Create a performance monitor
monitor = PerformanceMonitor()

# Monitor function performance with decorator
@performance_monitor(monitor)
def expensive_operation():
    import time
    time.sleep(1)  # Simulate work
    return "result"

# Record custom metrics
record_timing("custom_operation", 0.5, {"operation_type": "data_processing"})

# Get performance summary
summary = get_performance_summary()
print(f"Total metrics: {summary['total_metrics']}")
print(f"Uptime: {summary['uptime']:.2f} seconds")
```

### 2. Lazy Loading

```python
from morphcloud.performance import LazyLoader, lazy_property

# Manual lazy loading
class DataProcessor:
    def __init__(self):
        self._data_loader = LazyLoader(
            factory=self._load_data,
            name="data_loader"
        )
    
    def _load_data(self):
        # Expensive data loading operation
        return {"large": "dataset"}
    
    @property
    def data(self):
        return self._data_loader.__get__(self)

# Automatic lazy loading with decorator
class CacheManager:
    @lazy_property
    def redis_client(self):
        import redis
        return redis.Redis(host='localhost', port=6379)
    
    @lazy_property
    def cache_stats(self):
        return {"hits": 0, "misses": 0}
```

### 3. Caching

```python
from morphcloud.performance import CacheManager

# Create cache manager
cache = CacheManager(max_size=1000, default_ttl=300)

# Cache operations
cache.set("user:123", {"name": "John", "email": "john@example.com"}, ttl=600)
user_data = cache.get("user:123")

# Get cache statistics
stats = cache.get_stats()
print(f"Cache hit rate: {stats['hit_rate']:.2%}")
```

### 4. GPU Acceleration

```python
from morphcloud.advanced_performance import (
    PerformanceConfig, GPUType, get_advanced_performance_manager
)

# Configure performance optimization
config = PerformanceConfig(
    gpu_type=GPUType.CUDA,
    enable_gpu_acceleration=True,
    enable_memory_mapping=True,
    enable_async_optimization=True
)

# Get performance manager
manager = get_advanced_performance_manager(config)

# Optimize computation with GPU
import numpy as np

# Large matrix for computation
data = np.random.random((1000, 1000)).astype(np.float32)

# GPU-accelerated matrix multiplication
result = manager.optimize_computation(data, "matrix_multiply")
print(f"Matrix multiplication completed: {result.shape}")

# GPU-accelerated FFT
fft_result = manager.optimize_computation(data, "fft")
print(f"FFT completed: {fft_result.shape}")
```

### 5. Request Batching

```python
from morphcloud.optimization import BatchProcessor, BatchRequest
import asyncio

# Create batch processor
batch_processor = BatchProcessor(batch_size=10, max_wait_time=0.1)

# Add requests to batch
for i in range(25):
    request = BatchRequest(
        id=f"req_{i}",
        data={"value": i},
        callback=lambda result: print(f"Processed: {result}")
    )
    batch_processor.add_request(request)

# Process batches
async def process_batches():
    while True:
        batch = batch_processor.get_batch()
        if not batch:
            break
        
        # Process batch
        results = await asyncio.gather(*[
            process_request(req.data) for req in batch
        ])
        
        # Call callbacks
        for req, result in zip(batch, results):
            if req.callback:
                req.callback(result)

async def process_request(data):
    # Simulate API call
    await asyncio.sleep(0.1)
    return f"processed_{data['value']}"

# Run batch processing
asyncio.run(process_batches())
```

## Advanced Features

### Supply Chain Security

```python
from morphcloud.supply_chain_security import (
    SupplyChainConfig, SecurityLevel, get_supply_chain_security_manager
)

# Configure supply chain security
config = SupplyChainConfig(
    security_level=SecurityLevel.HIGH,
    enable_dependency_scanning=True,
    enable_build_analysis=True,
    enable_package_verification=True,
    enable_typosquatting_detection=True
)

# Get security manager
manager = get_supply_chain_security_manager(config)

# Comprehensive security scan
scan_result = manager.comprehensive_scan(".")
print(f"Overall security score: {scan_result['overall_security_score']:.2f}")

# Check for critical issues
if scan_result['critical_issues']:
    print("Critical issues found:")
    for issue in scan_result['critical_issues']:
        print(f"  - {issue}")

# Review recommendations
print("Security recommendations:")
for rec in scan_result['recommendations']:
    print(f"  - {rec}")
```

### Runtime Security

```python
from morphcloud.runtime_security import (
    RuntimeSecurityConfig, SecurityLevel, get_runtime_security_manager
)

# Configure runtime security
config = RuntimeSecurityConfig(
    security_level=SecurityLevel.HIGH,
    enable_memory_protection=True,
    enable_race_detection=True,
    enable_resource_monitoring=True,
    enable_dos_protection=True
)

# Get security manager
manager = get_runtime_security_manager(config)

# Start runtime protection
manager.start_protection()

# Monitor for threats
threats = manager.get_active_threats()
if threats:
    print("Active threats detected:")
    for threat in threats:
        print(f"  - {threat['type']}: {threat['description']}")
```

## Configuration Management

### Environment-Based Configuration

```python
from morphcloud.config import (
    Config, Environment, APIConfig, SecurityConfig, 
    PerformanceConfig, LoggingConfig
)

# Create configuration for different environments
dev_config = Config(
    environment=Environment.DEVELOPMENT,
    debug_mode=True,
    api=APIConfig(
        base_url="https://dev-api.morphcloud.com",
        timeout=60,
        max_retries=5
    ),
    security=SecurityConfig(
        ssh_host_key_verification=False,  # Less strict in dev
        command_sanitization=True,
        secure_temp_dirs=True
    ),
    performance=PerformanceConfig(
        enable_caching=False,  # Disable caching in dev
        batch_size=5,
        max_concurrent_requests=5
    ),
    logging=LoggingConfig(
        level="DEBUG",
        enable_console=True,
        enable_file=False
    )
)

# Apply configuration
from morphcloud.config import set_config
set_config(dev_config)
```

### Configuration Files

Create `morphcloud.yaml`:

```yaml
environment: production
debug_mode: false

api:
  base_url: https://api.morphcloud.com
  timeout: 30
  max_retries: 3
  retry_delay: 1.0

security:
  ssh_host_key_verification: true
  command_sanitization: true
  secure_temp_dirs: true
  default_bind_host: "127.0.0.1"
  allow_external_binding: false
  http_timeout_default: 30

performance:
  enable_caching: true
  cache_ttl: 300
  max_cache_size: 1000
  enable_lazy_loading: true
  batch_size: 10
  max_concurrent_requests: 10

logging:
  level: INFO
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  enable_console: true
  enable_file: true
  file_path: "logs/morphcloud.log"
```

## Error Handling

### Custom Exceptions

```python
from morphcloud.errors import (
    MorphCloudError, NetworkError, ValidationError, 
    SecurityError, handle_error
)

# Create custom error
class CustomError(MorphCloudError):
    def __init__(self, message: str, **kwargs):
        super().__init__(
            message=message,
            category="custom",
            severity="medium",
            retryable=True,
            **kwargs
        )

# Handle errors
try:
    # Some operation that might fail
    raise CustomError("Operation failed", error_code="CUSTOM_001")
except CustomError as e:
    handle_error(e, log_error=True, raise_error=False)
    print(f"Handled error: {e.message}")
```

### Retry Logic

```python
from morphcloud.errors import RetryHandler, retry_operation

# Create retry handler
retry_handler = RetryHandler(
    max_retries=3,
    base_delay=1.0,
    max_delay=60.0,
    exponential_backoff=True
)

# Retry operation with exponential backoff
async def unreliable_operation():
    import random
    if random.random() < 0.7:  # 70% failure rate
        raise NetworkError("Network timeout")
    return "success"

# Use retry handler
try:
    result = await retry_handler.retry_operation(
        unreliable_operation,
        error_types=[NetworkError]
    )
    print(f"Operation succeeded: {result}")
except NetworkError as e:
    print(f"Operation failed after retries: {e}")
```

## Monitoring & Observability

### Health Checks

```python
from morphcloud.monitoring import (
    MonitoringDashboard, HealthChecker, HealthStatus
)

# Create custom health check
def check_database_connection():
    try:
        # Check database connection
        import psycopg2
        conn = psycopg2.connect("postgresql://localhost/testdb")
        conn.close()
        return HealthCheck(
            name="database_connection",
            status=HealthStatus.HEALTHY,
            message="Database connection successful"
        )
    except Exception as e:
        return HealthCheck(
            name="database_connection",
            status=HealthStatus.UNHEALTHY,
            message=f"Database connection failed: {e}"
        )

# Add health check to dashboard
dashboard = get_monitoring_dashboard()
dashboard.health_checker.add_health_check(check_database_connection)

# Run health checks
health_status = dashboard.get_health_status()
print(f"Overall health: {health_status['overall_status']}")
```

### System Monitoring

```python
from morphcloud.monitoring import (
    SystemMonitor, ApplicationMonitor, 
    increment_counter, set_gauge, record_timer
)

# Monitor application metrics
increment_counter("api_requests")
set_gauge("active_connections", 15)
record_timer("database_query", 0.125)

# Get system metrics
dashboard = get_monitoring_dashboard()
system_summary = dashboard.system_monitor.get_metrics_summary(minutes=60)
print(f"CPU usage (1h avg): {system_summary['cpu']['average']:.1f}%")
print(f"Memory usage (1h avg): {system_summary['memory']['average']:.1f}%")
```

## Testing & Validation

### Test Framework

```python
from morphcloud.testing import (
    TestRunner, TestCase, TestResult,
    get_test_runner, run_tests
)

# Create test cases
def test_api_connection():
    # Test API connection
    import requests
    response = requests.get("https://api.example.com/health", timeout=5)
    assert response.status_code == 200
    return "API connection successful"

def test_database_connection():
    # Test database connection
    import psycopg2
    conn = psycopg2.connect("postgresql://localhost/testdb")
    conn.close()
    return "Database connection successful"

# Create test runner
runner = get_test_runner()

# Add test cases
runner.add_test(TestCase(
    name="api_connection",
    description="Test API connectivity",
    test_func=test_api_connection,
    timeout=10.0
))

runner.add_test(TestCase(
    name="database_connection",
    description="Test database connectivity",
    test_func=test_database_connection,
    timeout=5.0,
    dependencies=["api_connection"]
))

# Run tests
results = run_tests()
summary = runner.get_test_summary()
print(f"Tests passed: {summary['passed']}/{summary['total_tests']}")
print(f"Success rate: {summary['success_rate']:.1f}%")
```

### Performance Testing

```python
from morphcloud.testing import (
    get_performance_tester, benchmark_function,
    benchmark_async_function
)

# Benchmark synchronous function
def expensive_calculation():
    import time
    time.sleep(0.01)  # Simulate work
    return sum(range(1000))

# Run benchmark
tester = get_performance_tester()
results = tester.benchmark_function(
    expensive_calculation,
    iterations=1000,
    warmup_iterations=100
)

print(f"Average time: {results['mean_time']:.6f} seconds")
print(f"Min time: {results['min_time']:.6f} seconds")
print(f"Max time: {results['max_time']:.6f} seconds")
print(f"Standard deviation: {results['std_dev']:.6f} seconds")
```

## Red Team Testing Framework

### Comprehensive Red Team Testing

```python
from morphcloud.red_team_testing import run_red_team_tests

# Test API endpoints for vulnerabilities
targets = {
    "api_endpoints": [
        {"url": "https://api.example.com/users", "method": "GET"},
        {"url": "https://api.example.com/login", "method": "POST"}
    ]
}

results = await run_red_team_tests(targets)

# Test credential stuffing attacks
social_targets = {
    "login_endpoints": [
        {"url": "https://login.example.com", "credentials_file": "test_creds.txt"}
    ]
}

social_results = await run_red_team_tests(social_targets)

# Simulate advanced persistent threats
apt_targets = {
    "target_systems": ["192.168.1.10", "192.168.1.20", "192.168.1.30"]
}

apt_results = await run_red_team_tests(apt_targets)
```

### Command & Control Detection

```python
from morphcloud.command_control_detection import start_c2_monitoring

# Start continuous threat monitoring
c2_engine = start_c2_monitoring()

# Get threat summary
threat_summary = c2_engine.get_threat_summary()

# Monitor for suspicious activities
suspicious_activities = c2_engine.get_suspicious_activities()
if suspicious_activities:
    print("Suspicious activities detected:")
    for activity in suspicious_activities:
        print(f"  - {activity['type']}: {activity['description']}")
```

### Debug Mode

Enable debug mode for detailed logging:

```python
import os
os.environ["MORPHCLOUD_DEBUG_MODE"] = "true"
os.environ["MORPHCLOUD_LOG_LEVEL"] = "DEBUG"
```

### Performance Profiling

Use the performance profiler for detailed analysis:

```python
from morphcloud.performance import PerformanceProfiler

with PerformanceProfiler("operation_name"):
    # Your code here
    pass
```

### System Health Check

```python
def system_health_check():
    """Comprehensive system health check"""
    
    health_status = {
        "container_security": "unknown",
        "zero_trust": "unknown",
        "performance": "unknown",
        "supply_chain": "unknown",
        "overall": "unknown"
    }
    
    try:
        # Container security health
        container_manager = get_container_security_manager()
        if container_manager.docker_client:
            health_status["container_security"] = "healthy"
        else:
            health_status["container_security"] = "unhealthy"
    except Exception as e:
        health_status["container_security"] = f"error: {str(e)}"
    
    try:
        # Zero-trust health
        zero_trust_manager = get_zero_trust_manager()
        if zero_trust_manager.service_mesh:
            health_status["zero_trust"] = "healthy"
        else:
            health_status["zero_trust"] = "unhealthy"
    except Exception as e:
        health_status["zero_trust"] = f"error: {str(e)}"
    
    try:
        # Performance health
        perf_manager = get_advanced_performance_manager()
        if perf_manager.gpu_accelerator or perf_manager.async_optimizer:
            health_status["performance"] = "healthy"
        else:
            health_status["performance"] = "unhealthy"
    except Exception as e:
        health_status["performance"] = f"error: {str(e)}"
    
    try:
        # Supply chain health
        supply_chain_manager = get_supply_chain_security_manager()
        if supply_chain_manager.dependency_scanner:
            health_status["supply_chain"] = "healthy"
        else:
            health_status["supply_chain"] = "unhealthy"
    except Exception as e:
        health_status["supply_chain"] = f"error: {str(e)}"
    
    # Overall health
    healthy_components = sum(1 for status in health_status.values() 
                           if status == "healthy")
    total_components = len(health_status) - 1  # Exclude overall
    
    if healthy_components == total_components:
        health_status["overall"] = "healthy"
    elif healthy_components > total_components // 2:
        health_status["overall"] = "degraded"
    else:
        health_status["overall"] = "unhealthy"
    
    return health_status

# Run health check
health = system_health_check()
print("System Health Status:")
for component, status in health.items():
    print(f"  {component}: {status}")
```

