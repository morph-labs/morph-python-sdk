# MorphCloud API Test Suite

This directory contains comprehensive API endpoint testing for the MorphCloud Python SDK. The tests are organized into three categories: basic endpoint testing, correctness validation, and stress testing.

## Test Architecture Overview

All tests follow a consistent pattern:
- **Performance Tracking**: Every operation is timed with `timed_operation()` and logged to `performance_log.jsonl`
- **Resource Cleanup**: All tests properly clean up snapshots and instances in `finally` blocks
- **Machine Configuration Matrix**: Tests can run across 12 configurations (2 base images × 6 machine sizes)
- **Async/Await Pattern**: All tests use `pytest.mark.asyncio` for async API calls

## Directory Structure

```
tests/api/
├── basic/          # Basic endpoint functionality tests
├── correctness/    # Deep correctness validation tests  
├── stress/         # Load and stress testing
├── utils/          # Shared utilities
└── conftest.py     # Test configuration and fixtures
```

## Test Categories

### 1. Basic Tests (`basic/`)

These tests verify that each API endpoint works correctly with standard inputs and returns expected responses.

#### `test_endpoints_instances.py` - Instance Management (12 endpoints)
Tests all core instance operations with comprehensive lifecycle management:

**`test_start_instance_from_snapshot()`** (Lines 78-167)
- **What it does**: Creates a snapshot, starts an instance from it, waits for readiness
- **Performance tracking**: Logs snapshot creation, instance start, readiness wait, and retrieval times
- **Matrix testing**: Supports all 12 machine configurations via `machine_config` parameter
- **Key code**:
```python
# Lines 109-114: Start instance with timing
instance, start_duration = await timed_operation(
    "instance_start_from_snapshot",
    lambda: client.instances.astart(snapshot.id)
)
```

**`test_instance_pause_resume_cycle()`** (Lines 184-244)
- **What it does**: Pauses a running instance, verifies status, then resumes it
- **Verification**: Checks instance status before/after pause/resume operations
- **Key code**:
```python
# Lines 204-208: Pause with performance tracking
_, pause_duration = await timed_operation(
    "instance_pause",
    lambda: instance.apause()
)
```

**`test_instance_command_execution()`** (Lines 298-348)
- **What it does**: Executes shell commands on running instances via `POST /instance/{id}/exec`
- **Verification**: Checks command exit codes and stdout content
- **Example command**: `echo 'Hello from API test'`

**`test_instance_branch()`** (Lines 402-474)
- **What it does**: Creates multiple instance copies from a single running instance
- **Complex cleanup**: Manages original instance + branch instances + snapshots
- **Key code**:
```python
# Lines 425-429: Branch instance into multiple copies
result, branch_duration = await timed_operation(
    "instance_branch", 
    lambda: instance.abranch(branch_count)
)
```

#### `test_endpoints_snapshots.py` - Snapshot Management (5 endpoints)
Tests snapshot creation, listing, retrieval, deletion, and metadata operations:

**`test_create_snapshot_basic()`** (Lines 100-156)
- **What it does**: Creates snapshot from base image, verifies properties, retrieves by ID
- **Matrix support**: Tests all 12 machine configurations with `adjust_config_for_image()`
- **Key validation**:
```python
# Lines 129-132: Verify snapshot properties
assert snapshot.id.startswith("snapshot_"), f"Snapshot ID should start with 'snapshot_'"
assert snapshot.refs.image_id == base_image.id
```

**`test_snapshot_metadata_operations()`** (Lines 247-290)
- **What it does**: Sets initial metadata, updates it, verifies changes persist
- **Metadata example**: `{"test_key": "initial_value", "environment": "api_test"}`

#### `test_endpoints_ssh.py` - SSH Key Management (2 endpoints)
Comprehensive SSH key rotation testing:

**`test_ssh_key_rotation()`** (Lines 137-224)
- **What it does**: Gets original key, rotates it, verifies new key is different
- **Validation**: Ensures new public/private keys have valid SSH formats
- **Uniqueness check**: Confirms rotated keys differ from originals
- **Key code**:
```python
# Lines 168-172: Rotate SSH key with timing
new_key, rotate_duration = await timed_operation(
    "ssh_key_rotate",
    lambda: instance.assh_key_rotate()
)
```

**`test_multiple_ssh_key_rotations()`** (Lines 227-310)
- **What it does**: Performs 3 consecutive rotations, ensures all keys are unique
- **Performance analysis**: Tracks min/max/average rotation times

#### `test_endpoints_networking.py` - Network Services (3 endpoints)
Tests HTTP service exposure and wake-on-demand functionality:

**`test_http_service_exposure()`** (Lines 71-100+)
- **What it does**: Sets up HTTP server inside instance, exposes it via API
- **Integration pattern**: Uses tmux sessions like real-world scenarios
- **Unique content**: Creates HTML with test UUID for verification

#### `test_endpoints_metadata.py` - Image Management (1 endpoint)  
**`test_list_base_images()`** (Lines 67-117)
- **What it does**: Lists available base images, validates their properties
- **Expected images**: Looks for `morphvm-minimal` and `morphvm-sandbox`

### 2. Correctness Tests (`correctness/`)

These tests perform deep validation of API behavior, edge cases, and integration scenarios.

#### `test_http_correctness.py` - HTTP Service Validation
**`http_ready_instance` fixture** (Lines 75-100+)
- **What it does**: Creates instances with larger resources (2GB RAM, 16GB disk) for HTTP testing
- **Setup**: Installs dependencies and prepares HTTP testing environment

#### `test_ttl_correctness.py` - TTL Behavior Validation
- **What it does**: Tests Time-To-Live functionality with different actions (stop/pause)
- **Expiration testing**: Validates TTL expiration behavior and automatic actions
- **TTL reset**: Tests TTL reset after resume operations

#### `test_ssh_correctness.py` - SSH Connection Validation
- **What it does**: Tests actual SSH connectivity, not just key rotation
- **Connection verification**: Ensures SSH works before and after key rotation

### 3. Stress Tests (`stress/`)

#### `test_basic_stress.py` - Load Testing
**`stress_ready_instance` fixture** (Lines 73-100+)
- **What it does**: Creates instances optimized for stress testing (2GB RAM, 16GB disk)
- **Stress tools**: Installs `stress-ng`, `htop`, and `python3`
- **Load patterns**: Tests CPU, memory, and disk stress scenarios

## Configuration & Fixtures

### `conftest.py` - Test Configuration
Key fixtures and utilities:

**Machine Configuration Matrix** (Lines 19-36)
```python
MACHINE_SIZES = {
    "nano": {"vcpus": 1, "memory": 1024, "disk_size": 8*1024},
    "micro": {"vcpus": 1, "memory": 2048, "disk_size": 16*1024},
    # ... up to xlarge
}

ALL_CONFIGS = [
    (base_image, size_name, size_config)
    for base_image in ["minimal", "sandbox"]  
    for size_name, size_config in MACHINE_SIZES.items()
]
```

**`adjust_config_for_image()` function** (Lines 176-195)
- **What it does**: Adjusts disk size requirements for different base images
- **Sandbox requirement**: Ensures minimum 10GB disk for sandbox images

### Performance Tracking System

All tests log detailed performance metrics to `performance_log.jsonl`:
```python
# Standard timing pattern used throughout
result, duration = await timed_operation(
    "operation_name",
    lambda: async_operation()
)
```

**Performance log format**:
```json
{
    "timestamp": "2024-01-15T10:30:45.123456",
    "operation": "instance_start_from_snapshot", 
    "duration_seconds": 45.67,
    "status": "success"
}
```

## Running the Tests

### Basic Usage
```bash
# Run all API tests
pytest tests/api/

# Run specific category
pytest tests/api/basic/
pytest tests/api/correctness/
pytest tests/api/stress/

# Run with specific base image
pytest tests/api/ --base-image=minimal
pytest tests/api/ --base-image=sandbox

# Run with both images (matrix testing)
pytest tests/api/ --test-both-images
```

### Machine Configuration Testing
```bash
# Test all 12 configurations for snapshots
pytest tests/api/basic/test_endpoints_snapshots.py::test_create_snapshot_basic -v

# Test all 12 configurations for instances  
pytest tests/api/basic/test_endpoints_instances.py::test_start_instance_from_snapshot -v
```

### Performance Analysis
```bash
# Monitor performance during test runs
tail -f performance_log.jsonl | jq '.'

# Analyze performance trends
cat performance_log.jsonl | jq '.duration_seconds' | sort -n
```

## Key Features

1. **Comprehensive Coverage**: Tests all 14 API endpoints systematically
2. **Performance Monitoring**: Every operation timed and logged for trend analysis
3. **Matrix Testing**: Validates 12 machine configurations (2 images × 6 sizes)  
4. **Proper Cleanup**: All resources cleaned up even when tests fail
5. **Real-world Scenarios**: Correctness tests simulate actual usage patterns
6. **Stress Testing**: Validates behavior under load conditions

## Understanding Test Results

- **Green tests**: Basic functionality works
- **Performance logs**: Check `performance_log.jsonl` for timing trends
- **Failed cleanups**: Look for "Error deleting" messages in logs
- **Matrix failures**: Check if specific image/size combinations have issues

This test suite provides comprehensive validation of the MorphCloud API, ensuring both functional correctness and performance characteristics across all supported configurations.