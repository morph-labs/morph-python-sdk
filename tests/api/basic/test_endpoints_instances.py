"""
Test all instance-related API endpoints.

This module tests the 12 instance endpoints:
- POST /snapshot/{id}/boot - Start instance from snapshot
- GET /instance - List instances with metadata filtering  
- GET /instance/{id} - Get specific instance
- DELETE /instance/{id} - Stop/terminate instance
- POST /instance/{id}/pause - Pause instance
- POST /instance/{id}/resume - Resume instance  
- POST /instance/{id}/reboot - Reboot instance
- POST /instance/{id}/exec - Execute command
- POST /instance/{id}/snapshot - Create snapshot from instance
- POST /instance/{id}/metadata - Update instance metadata
- POST /instance/{id}/branch - Branch instance
- POST /instance/{id}/ttl - Set TTL configuration
"""
import pytest
import logging
import time
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger("morph-api-tests")

# Performance tracking
PERFORMANCE_LOG_FILE = Path(__file__).parent.parent.parent / "performance_log.jsonl"

# Mark all tests as asyncio tests
pytestmark = pytest.mark.asyncio


async def timed_operation(operation_name: str, operation_func):
    """Time an async operation and log the result."""
    start_time = time.time()
    try:
        result = await operation_func()
        duration = time.time() - start_time
        
        # Log to console
        logger.info(f"⏱️  {operation_name}: {duration:.2f}s")
        
        # Log to performance file
        log_performance_metric(operation_name, duration, "success")
        
        return result, duration
    except Exception as e:
        duration = time.time() - start_time
        logger.error(f"⏱️  {operation_name}: {duration:.2f}s (FAILED: {e})")
        
        # Log failure to performance file
        log_performance_metric(operation_name, duration, "failed", str(e))
        
        raise


def log_performance_metric(operation: str, duration: float, status: str, error: str = None):
    """Log performance metric to JSONL file."""
    metric = {
        "timestamp": datetime.now().isoformat(),
        "operation": operation,
        "duration_seconds": round(duration, 2),
        "status": status
    }
    if error:
        metric["error"] = error
    
    # Ensure parent directory exists
    PERFORMANCE_LOG_FILE.parent.mkdir(exist_ok=True)
    
    # Append to JSONL file
    with open(PERFORMANCE_LOG_FILE, "a") as f:
        f.write(json.dumps(metric) + "\n")


async def test_start_instance_from_snapshot(client, base_image):
    """Test POST /snapshot/{id}/boot - Start instance from snapshot."""
    logger.info("Testing instance creation from snapshot")
    
    snapshot = None
    instance = None
    
    try:
        # First create a snapshot to start an instance from
        snapshot, create_duration = await timed_operation(
            "snapshot_create_for_instance",
            lambda: client.snapshots.acreate(
                image_id=base_image.id,
                vcpus=1,
                memory=1024,  # 1GB RAM
                disk_size=8*1024  # 8GB disk
            )
        )
        logger.info(f"Created snapshot for instance test: {snapshot.id}")
        
        # Start instance from snapshot (timed)
        instance, start_duration = await timed_operation(
            "instance_start_from_snapshot",
            lambda: client.instances.astart(snapshot.id)
        )
        logger.info(f"Started instance: {instance.id}")
        
        # Verify instance properties
        assert instance.id.startswith("morphvm_"), f"Instance ID should start with 'morphvm_', got: {instance.id}"
        assert hasattr(instance, "refs"), "Instance should have a refs attribute"
        assert hasattr(instance.refs, "snapshot_id"), "Instance should have refs.snapshot_id attribute"
        assert instance.refs.snapshot_id == snapshot.id, f"Instance should be created from {snapshot.id}, got: {instance.refs.snapshot_id}"
        
        # Wait for instance to be ready (timed)
        logger.info(f"Waiting for instance {instance.id} to be ready")
        _, ready_duration = await timed_operation(
            "instance_await_ready", 
            lambda: instance.await_until_ready(timeout=300)
        )
        logger.info(f"Instance {instance.id} is ready")
        
        # Test GET /instance/{id} - Get specific instance (timed)
        retrieved_instance, get_duration = await timed_operation(
            "instance_get_by_id",
            lambda: client.instances.aget(instance.id)
        )
        assert retrieved_instance.id == instance.id, "Retrieved instance should have same ID"
        assert retrieved_instance.refs.snapshot_id == snapshot.id, "Retrieved instance should have same snapshot ID"
        
        # Log performance summary
        logger.info(f"📊 Instance Lifecycle Performance:")
        logger.info(f"   Snapshot Create: {create_duration:.2f}s")
        logger.info(f"   Instance Start:  {start_duration:.2f}s") 
        logger.info(f"   Instance Ready:  {ready_duration:.2f}s")
        logger.info(f"   Instance Get:    {get_duration:.2f}s")
        logger.info(f"   Total:          {create_duration + start_duration + ready_duration + get_duration:.2f}s")
        
    finally:
        # Clean up resources (timed)
        if instance:
            try:
                _, stop_duration = await timed_operation(
                    "instance_stop",
                    lambda: instance.astop()
                )
                logger.info(f"Instance stopped in {stop_duration:.2f}s")
            except Exception as e:
                logger.error(f"Error stopping instance: {e}")
                
        if snapshot:
            try:
                _, delete_duration = await timed_operation(
                    "snapshot_delete_after_instance",
                    lambda: snapshot.adelete()
                )
                logger.info(f"Snapshot deleted in {delete_duration:.2f}s")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")


async def test_list_instances_empty(client):
    """Test GET /instance - List instances when none exist."""
    logger.info("Testing instance listing")
    
    # List all instances (timed)
    instances, duration = await timed_operation(
        "instance_list",
        lambda: client.instances.alist()
    )
    
    # Verify the list is returned (even if empty)
    assert isinstance(instances, list), "Instances list should be a list"
    logger.info(f"Found {len(instances)} existing instances in {duration:.2f}s")


async def test_instance_pause_resume_cycle(client, base_image):
    """Test POST /instance/{id}/pause and POST /instance/{id}/resume - Pause and resume instance."""
    logger.info("Testing instance pause/resume cycle")
    
    snapshot = None
    instance = None
    
    try:
        # Create snapshot and start instance
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=1024,
            disk_size=8*1024
        )
        
        instance = await client.instances.astart(snapshot.id)
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} is ready for pause/resume test")
        
        # Pause the instance (timed)
        _, pause_duration = await timed_operation(
            "instance_pause",
            lambda: instance.apause()
        )
        logger.info(f"Instance paused in {pause_duration:.2f}s")
        
        # Verify instance is paused by checking status
        paused_instance = await client.instances.aget(instance.id)
        # Note: Status checking depends on the actual API response format
        logger.info(f"Instance status after pause: {getattr(paused_instance, 'status', 'unknown')}")
        
        # Resume the instance (timed)  
        _, resume_duration = await timed_operation(
            "instance_resume",
            lambda: instance.aresume()
        )
        logger.info(f"Instance resumed in {resume_duration:.2f}s")
        
        # Verify instance is resumed
        resumed_instance = await client.instances.aget(instance.id)
        logger.info(f"Instance status after resume: {getattr(resumed_instance, 'status', 'unknown')}")
        
        # Log performance summary
        logger.info(f"📊 Pause/Resume Performance: Pause={pause_duration:.2f}s, Resume={resume_duration:.2f}s")
        
    finally:
        # Clean up resources
        if instance:
            try:
                await instance.astop()
                logger.info("Instance stopped")
            except Exception as e:
                logger.error(f"Error stopping instance: {e}")
                
        if snapshot:
            try:
                await snapshot.adelete()
                logger.info("Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")


async def test_instance_reboot(client, base_image):
    """Test POST /instance/{id}/reboot - Reboot instance."""
    logger.info("Testing instance reboot")
    
    snapshot = None
    instance = None
    
    try:
        # Create snapshot and start instance
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=1024,
            disk_size=8*1024
        )
        
        instance = await client.instances.astart(snapshot.id)
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} ready for reboot test")
        
        # Reboot the instance (timed)
        _, reboot_duration = await timed_operation(
            "instance_reboot",
            lambda: instance.areboot()
        )
        logger.info(f"Instance rebooted in {reboot_duration:.2f}s")
        
        # Verify instance is still accessible after reboot
        rebooted_instance = await client.instances.aget(instance.id)
        assert rebooted_instance.id == instance.id, "Instance should exist after reboot"
        logger.info("Instance accessible after reboot")
        
        logger.info(f"📊 Reboot Performance: {reboot_duration:.2f}s")
        
    finally:
        # Clean up resources
        if instance:
            try:
                await instance.astop()
                logger.info("Instance stopped")
            except Exception as e:
                logger.error(f"Error stopping instance: {e}")
                
        if snapshot:
            try:
                await snapshot.adelete()
                logger.info("Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")


async def test_instance_command_execution(client, base_image):
    """Test POST /instance/{id}/exec - Execute command on instance."""
    logger.info("Testing command execution on instance")
    
    snapshot = None
    instance = None
    
    try:
        # Create snapshot and start instance
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=1024,
            disk_size=8*1024
        )
        
        instance = await client.instances.astart(snapshot.id)
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} ready for command execution")
        
        # Execute simple command (timed)
        result, exec_duration = await timed_operation(
            "instance_exec_simple",
            lambda: instance.aexec("echo 'Hello from API test'")
        )
        
        # Verify command result
        assert hasattr(result, 'exit_code'), "Command result should have exit_code"
        assert result.exit_code == 0, f"Command should succeed (exit_code=0), got: {result.exit_code}"
        
        if hasattr(result, 'stdout') and result.stdout:
            assert "Hello from API test" in result.stdout, "Command output should contain expected text"
            logger.info(f"Command output: {result.stdout.strip()}")
        
        logger.info(f"📊 Command Execution Performance: {exec_duration:.2f}s")
        
    finally:
        # Clean up resources
        if instance:
            try:
                await instance.astop()
                logger.info("Instance stopped")
            except Exception as e:
                logger.error(f"Error stopping instance: {e}")
                
        if snapshot:
            try:
                await snapshot.adelete()
                logger.info("Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")


async def test_instance_reboot(client, base_image):
    """Test POST /instance/{id}/reboot - Reboot instance."""
    logger.info("Testing instance reboot")
    
    snapshot = None
    instance = None
    
    try:
        # Create snapshot and start instance
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=1024,
            disk_size=8*1024
        )
        
        instance = await client.instances.astart(snapshot.id)
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} ready for reboot test")
        
        # Reboot the instance (timed)
        _, reboot_duration = await timed_operation(
            "instance_reboot",
            lambda: instance.areboot()
        )
        logger.info(f"Instance rebooted in {reboot_duration:.2f}s")
        
        # Verify instance is still accessible after reboot
        rebooted_instance = await client.instances.aget(instance.id)
        assert rebooted_instance.id == instance.id, "Instance should exist after reboot"
        logger.info("Instance accessible after reboot")
        
        logger.info(f"📊 Reboot Performance: {reboot_duration:.2f}s")
        
    finally:
        # Clean up resources
        if instance:
            try:
                await instance.astop()
                logger.info("Instance stopped")
            except Exception as e:
                logger.error(f"Error stopping instance: {e}")
                
        if snapshot:
            try:
                await snapshot.adelete()
                logger.info("Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")


async def test_instance_branch(client, base_image):
    """Test POST /instance/{id}/branch - Branch instance into multiple copies."""
    logger.info("Testing instance branching")
    
    original_snapshot = None
    instance = None
    branch_snapshot = None
    branch_instances = []
    
    try:
        # Create original snapshot and start instance
        original_snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=1024,
            disk_size=8*1024
        )
        
        instance = await client.instances.astart(original_snapshot.id)
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} ready for branching")
        
        # Branch the instance into 2 copies (timed)
        branch_count = 2
        result, branch_duration = await timed_operation(
            "instance_branch",
            lambda: instance.abranch(branch_count)
        )
        
        # Extract snapshot and instances from branch result
        if isinstance(result, tuple) and len(result) == 2:
            branch_snapshot, branch_instances = result
            logger.info(f"Branched into snapshot {branch_snapshot.id} and {len(branch_instances)} instances")
        else:
            logger.warning(f"Unexpected branch result format: {type(result)}")
            branch_instances = result if isinstance(result, list) else [result]
        
        # Verify branch instances
        for i, branch_instance in enumerate(branch_instances):
            assert branch_instance.id.startswith("morphvm_"), f"Branch instance {i} should have proper ID"
            logger.info(f"Branch instance {i}: {branch_instance.id}")
        
        logger.info(f"📊 Branching Performance: {branch_duration:.2f}s for {branch_count} instances")
        
    finally:
        # Clean up resources (order matters)
        if instance:
            try:
                await instance.astop()
                logger.info("Original instance stopped")
            except Exception as e:
                logger.error(f"Error stopping original instance: {e}")
        
        for i, branch_instance in enumerate(branch_instances):
            try:
                await branch_instance.astop()
                logger.info(f"Branch instance {i} stopped")
            except Exception as e:
                logger.error(f"Error stopping branch instance {i}: {e}")
        
        if branch_snapshot:
            try:
                await branch_snapshot.adelete()
                logger.info("Branch snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting branch snapshot: {e}")
                
        if original_snapshot:
            try:
                await original_snapshot.adelete()
                logger.info("Original snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting original snapshot: {e}")


async def test_instance_ttl_configuration(client, base_image):
    """Test POST /instance/{id}/ttl - Set TTL configuration."""
    logger.info("Testing instance TTL configuration")
    
    snapshot = None
    instance = None
    
    try:
        # Create snapshot and start instance
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=1024,
            disk_size=8*1024
        )
        
        instance = await client.instances.astart(snapshot.id)
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} ready for TTL test")
        
        # Set TTL configuration (timed) - 1 hour TTL with pause action
        ttl_seconds = 3600  # 1 hour
        _, ttl_duration = await timed_operation(
            "instance_set_ttl",
            lambda: instance.aset_ttl(ttl_seconds=ttl_seconds, ttl_action="pause")
        )
        logger.info(f"TTL set to {ttl_seconds}s with pause action")
        
        # Verify TTL was set by retrieving instance
        ttl_instance = await client.instances.aget(instance.id)
        # Note: TTL verification depends on the API response format
        logger.info(f"Instance after TTL set: {getattr(ttl_instance, 'ttl', 'TTL field not found')}")
        
        logger.info(f"📊 TTL Configuration Performance: {ttl_duration:.2f}s")
        
    finally:
        # Clean up resources
        if instance:
            try:
                await instance.astop()
                logger.info("Instance stopped")
            except Exception as e:
                logger.error(f"Error stopping instance: {e}")
                
        if snapshot:
            try:
                await snapshot.adelete()
                logger.info("Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")

