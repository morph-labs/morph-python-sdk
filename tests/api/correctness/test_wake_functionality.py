"""
Test wake-on-SSH and wake-on-HTTP functionality correctness.

This module validates wake functionality:
- Wake-on-SSH triggers instance resume from pause
- Wake-on-HTTP triggers instance resume from pause  
- TTL behavior with pause action and wake functionality
- Wake configuration persistence across operations
"""
import pytest
import pytest_asyncio
import logging
import time
import json
import asyncio
import uuid
import httpx
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from morphcloud.api import InstanceStatus

logger = logging.getLogger("morph-api-tests")

# Performance tracking
PERFORMANCE_LOG_FILE = Path(__file__).parent.parent.parent / "performance_log.jsonl"

# Mark all tests as asyncio tests
pytestmark = pytest.mark.asyncio


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


@pytest_asyncio.fixture
async def wake_ready_instance(client, base_image):
    """Create an instance ready for wake functionality testing."""
    snapshot = None
    instance = None
    
    try:
        # Create snapshot with sufficient resources for wake testing
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=2048,  # Use more memory for better responsiveness
            disk_size=16*1024
        )
        logger.info(f"Created snapshot {snapshot.id} for wake testing")
        
        # Start instance  
        instance = await client.instances.astart(snapshot.id)
        logger.info(f"Started instance {instance.id}")
        
        # Wait until ready with longer timeout for wake setup
        await instance.await_until_ready(timeout=600)
        logger.info(f"Instance {instance.id} is ready for wake testing")
        
        yield {
            'instance': instance,
            'snapshot': snapshot
        }
        
    finally:
        # Clean up
        if instance:
            try:
                await instance.astop()
                logger.info("Wake test instance stopped")
            except Exception as e:
                logger.error(f"Error stopping wake test instance: {e}")
                
        if snapshot:
            try:
                await snapshot.adelete()
                logger.info("Wake test snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting wake test snapshot: {e}")


async def test_wake_on_ssh_functionality(client, wake_ready_instance):
    """
    Test wake-on-SSH functionality correctness.
    
    Validates:
    1. Instance can be configured with wake_on_ssh=True
    2. Paused instance wakes up on SSH connection attempt
    3. Instance becomes ready after SSH wake event
    4. Wake configuration persists across pause/resume cycles
    """
    logger.info("Testing wake-on-SSH functionality")
    
    instance_data = wake_ready_instance
    instance = instance_data['instance']
    
    try:
        # Configure wake-on-SSH
        logger.info("Configuring instance for wake-on-SSH")
        await instance.aset_wake_on(wake_on_ssh=True)
        
        # Verify wake configuration
        instance_details = await client.instances.aget(instance.id)
        assert hasattr(instance_details, 'wake_on'), "Instance should have wake_on configuration"
        assert instance_details.wake_on.wake_on_ssh is True, "wake_on_ssh should be enabled"
        logger.info("✓ Wake-on-SSH configuration verified")
        
        # Pause the instance manually
        logger.info("Pausing instance to test wake functionality")
        _, pause_duration = await timed_operation(
            "wake_ssh_pause_instance",
            lambda: instance.apause()
        )
        
        # Wait for pause to complete
        await asyncio.sleep(3)
        
        # Verify instance is paused
        paused_instance = await client.instances.aget(instance.id)
        assert paused_instance.status == InstanceStatus.PAUSED, f"Instance should be paused, got: {paused_instance.status}"
        logger.info(f"Instance paused successfully in {pause_duration:.2f}s")
        
        # Attempt SSH connection to trigger wake
        logger.info("Attempting SSH connection to trigger wake-up")
        ssh_wake_start = time.time()
        
        try:
            # Use the instance SSH method to connect and execute a command
            # This should trigger the wake-on-SSH functionality
            with instance.ssh() as ssh:
                result = ssh.run("echo 'SSH wake test successful'")
                ssh_wake_duration = time.time() - ssh_wake_start
                
                assert result.exit_code == 0, f"SSH command should succeed: {result.stderr}"
                assert "successful" in result.stdout, f"Expected output not found: {result.stdout}"
                
                logger.info(f"SSH wake connection successful in {ssh_wake_duration:.2f}s")
                log_performance_metric("wake_ssh_connection", ssh_wake_duration, "success")
                
        except Exception as e:
            ssh_wake_duration = time.time() - ssh_wake_start
            log_performance_metric("wake_ssh_connection", ssh_wake_duration, "failed", str(e))
            raise AssertionError(f"SSH wake connection failed: {e}")
        
        # Verify instance is ready after SSH wake
        logger.info("Verifying instance is ready after SSH wake")
        await instance.await_until_ready(timeout=120)
        
        ready_instance = await client.instances.aget(instance.id)
        assert ready_instance.status == InstanceStatus.READY, f"Instance should be ready after SSH wake, got: {ready_instance.status}"
        logger.info("✓ Instance is ready after SSH wake")
        
        # Verify wake configuration persisted
        assert ready_instance.wake_on.wake_on_ssh is True, "Wake-on-SSH configuration should persist"
        logger.info("✓ Wake-on-SSH configuration persisted through wake event")
        
        # Performance summary
        total_wake_time = pause_duration + ssh_wake_duration
        logger.info(f"📊 Wake-on-SSH Performance:")
        logger.info(f"   Pause Duration:     {pause_duration:.2f}s")
        logger.info(f"   SSH Wake Duration:  {ssh_wake_duration:.2f}s")
        logger.info(f"   Total Wake Cycle:   {total_wake_time:.2f}s")
        
    except Exception as e:
        logger.error(f"Wake-on-SSH test failed: {e}")
        raise


async def test_wake_on_http_functionality(client, wake_ready_instance):
    """
    Test wake-on-HTTP functionality correctness.
    
    Validates:
    1. Instance can run HTTP service and expose it
    2. Instance can be configured with wake_on_http=True
    3. Paused instance wakes up on HTTP request to exposed service
    4. Service remains accessible after wake event
    """
    logger.info("Testing wake-on-HTTP functionality")
    
    instance_data = wake_ready_instance
    instance = instance_data['instance']
    service_port = 8888
    
    try:
        # Start HTTP service in instance
        logger.info(f"Starting HTTP service on port {service_port}")
        server_command = f"python3 -m http.server {service_port} > /dev/null 2>&1 &"
        
        server_result, server_start_time = await timed_operation(
            "wake_http_start_server",
            lambda: instance.aexec(server_command)
        )
        
        assert server_result.exit_code == 0, f"Failed to start HTTP server: {server_result.stderr}"
        
        # Give server time to start
        await asyncio.sleep(3)
        logger.info(f"HTTP server started in {server_start_time:.2f}s")
        
        # Expose the HTTP service
        logger.info("Exposing HTTP service")
        service_url, expose_duration = await timed_operation(
            "wake_http_expose_service", 
            lambda: instance.aexpose_http_service(name="wake-test-server", port=service_port)
        )
        
        logger.info(f"Service exposed at URL: {service_url} (took {expose_duration:.2f}s)")
        
        # Verify service is accessible before wake test
        logger.info("Verifying service accessibility before wake test")
        async with httpx.AsyncClient() as http_client:
            pre_test_response = await http_client.get(service_url, timeout=30)
            assert pre_test_response.status_code == 200, f"Service should be accessible before wake test, got: {pre_test_response.status_code}"
            logger.info("✓ HTTP service is accessible before wake test")
        
        # Configure wake-on-HTTP
        logger.info("Configuring instance for wake-on-HTTP")
        await instance.aset_wake_on(wake_on_http=True)
        
        # Verify wake configuration
        instance_details = await client.instances.aget(instance.id)
        assert hasattr(instance_details, 'wake_on'), "Instance should have wake_on configuration"
        assert instance_details.wake_on.wake_on_http is True, "wake_on_http should be enabled"
        logger.info("✓ Wake-on-HTTP configuration verified")
        
        # Pause the instance
        logger.info("Pausing instance to test HTTP wake functionality")
        _, pause_duration = await timed_operation(
            "wake_http_pause_instance",
            lambda: instance.apause()
        )
        
        # Wait for pause to complete
        await asyncio.sleep(3)
        
        # Verify instance is paused
        paused_instance = await client.instances.aget(instance.id)
        assert paused_instance.status == InstanceStatus.PAUSED, f"Instance should be paused, got: {paused_instance.status}"
        logger.info(f"Instance paused successfully in {pause_duration:.2f}s")
        
        # Send HTTP request to trigger wake
        logger.info(f"Sending HTTP request to {service_url} to trigger wake-up")
        http_wake_start = time.time()
        
        async with httpx.AsyncClient() as http_client:
            try:
                # The request might time out as the instance wakes up, which is acceptable
                # We primarily need to trigger the wake event
                wake_response = await http_client.get(service_url, timeout=90)
                http_wake_duration = time.time() - http_wake_start
                
                logger.info(f"HTTP wake request completed with status: {wake_response.status_code} in {http_wake_duration:.2f}s")
                log_performance_metric("wake_http_request", http_wake_duration, "success")
                
            except (httpx.ReadTimeout, httpx.ConnectTimeout) as e:
                http_wake_duration = time.time() - http_wake_start
                logger.info(f"HTTP request timed out during wake-up (expected behavior): {e}")
                log_performance_metric("wake_http_request", http_wake_duration, "timeout_expected", str(e))
                
            except Exception as e:
                http_wake_duration = time.time() - http_wake_start
                logger.warning(f"HTTP wake request encountered error: {e}")
                log_performance_metric("wake_http_request", http_wake_duration, "error", str(e))
                # Don't fail immediately - wake might still have occurred
        
        # Wait for instance to become ready after HTTP wake
        logger.info("Waiting for instance to become ready after HTTP wake")
        await instance.await_until_ready(timeout=120)
        
        ready_instance = await client.instances.aget(instance.id)
        assert ready_instance.status == InstanceStatus.READY, f"Instance should be ready after HTTP wake, got: {ready_instance.status}"
        logger.info("✓ Instance is ready after HTTP wake")
        
        # Verify service is accessible after wake
        logger.info("Verifying service accessibility after wake")
        async with httpx.AsyncClient() as http_client:
            post_wake_response, post_wake_test_time = await timed_operation(
                "wake_http_post_wake_test",
                lambda: http_client.get(service_url, timeout=30)
            )
            
            assert post_wake_response.status_code == 200, f"Service should be accessible after wake, got: {post_wake_response.status_code}"
            logger.info(f"✓ HTTP service accessible after wake (response time: {post_wake_test_time:.2f}s)")
        
        # Verify wake configuration persisted
        assert ready_instance.wake_on.wake_on_http is True, "Wake-on-HTTP configuration should persist"
        logger.info("✓ Wake-on-HTTP configuration persisted through wake event")
        
        # Performance summary
        total_wake_time = pause_duration + http_wake_duration
        logger.info(f"📊 Wake-on-HTTP Performance:")
        logger.info(f"   Server Start:       {server_start_time:.2f}s")
        logger.info(f"   Service Expose:     {expose_duration:.2f}s")
        logger.info(f"   Pause Duration:     {pause_duration:.2f}s")
        logger.info(f"   HTTP Wake Duration: {http_wake_duration:.2f}s")
        logger.info(f"   Post-Wake Test:     {post_wake_test_time:.2f}s")
        logger.info(f"   Total Wake Cycle:   {total_wake_time:.2f}s")
        
    except Exception as e:
        logger.error(f"Wake-on-HTTP test failed: {e}")
        raise


async def test_combined_wake_functionality(client, wake_ready_instance):
    """
    Test combined wake-on-SSH and wake-on-HTTP functionality.
    
    Validates:
    1. Both wake methods can be enabled simultaneously
    2. Either wake method can resume a paused instance
    3. Wake configuration consistency across multiple pause/wake cycles
    """
    logger.info("Testing combined wake functionality")
    
    instance_data = wake_ready_instance
    instance = instance_data['instance']
    service_port = 8889  # Use different port to avoid conflicts
    
    try:
        # Configure both wake methods
        logger.info("Configuring instance for both wake-on-SSH and wake-on-HTTP")
        await instance.aset_wake_on(wake_on_ssh=True, wake_on_http=True)
        
        # Verify both configurations
        instance_details = await client.instances.aget(instance.id)
        assert instance_details.wake_on.wake_on_ssh is True, "wake_on_ssh should be enabled"
        assert instance_details.wake_on.wake_on_http is True, "wake_on_http should be enabled"
        logger.info("✓ Both wake methods configured successfully")
        
        # Set up HTTP service for HTTP wake testing
        server_command = f"python3 -m http.server {service_port} > /dev/null 2>&1 &"
        server_result = await instance.aexec(server_command)
        assert server_result.exit_code == 0, "Failed to start HTTP server for combined test"
        
        await asyncio.sleep(2)  # Give server time to start
        
        service_url = await instance.aexpose_http_service(name="combined-wake-test", port=service_port)
        logger.info(f"HTTP service ready at: {service_url}")
        
        # Test cycle 1: Pause and wake via SSH
        logger.info("=== Wake Cycle 1: SSH Wake ===")
        await instance.apause()
        await asyncio.sleep(3)
        
        paused_instance = await client.instances.aget(instance.id)
        assert paused_instance.status == InstanceStatus.PAUSED, "Instance should be paused for SSH wake test"
        
        # Wake via SSH
        ssh_wake_start = time.time()
        with instance.ssh() as ssh:
            ssh_result = ssh.run("echo 'Combined wake SSH test'")
            ssh_wake_time = time.time() - ssh_wake_start
            assert ssh_result.exit_code == 0, "SSH wake should succeed"
        
        await instance.await_until_ready(timeout=120)
        ready_instance = await client.instances.aget(instance.id)
        assert ready_instance.status == InstanceStatus.READY, "Instance should be ready after SSH wake"
        logger.info(f"✓ SSH wake successful ({ssh_wake_time:.2f}s)")
        
        # Test cycle 2: Pause and wake via HTTP
        logger.info("=== Wake Cycle 2: HTTP Wake ===")
        await instance.apause()
        await asyncio.sleep(3)
        
        paused_instance = await client.instances.aget(instance.id)
        assert paused_instance.status == InstanceStatus.PAUSED, "Instance should be paused for HTTP wake test"
        
        # Wake via HTTP
        http_wake_start = time.time()
        async with httpx.AsyncClient() as http_client:
            try:
                await http_client.get(service_url, timeout=60)
                http_wake_time = time.time() - http_wake_start
            except (httpx.ReadTimeout, httpx.ConnectTimeout):
                http_wake_time = time.time() - http_wake_start
                logger.info(f"HTTP wake request timed out (expected): {http_wake_time:.2f}s")
        
        await instance.await_until_ready(timeout=120)
        ready_instance = await client.instances.aget(instance.id)
        assert ready_instance.status == InstanceStatus.READY, "Instance should be ready after HTTP wake"
        logger.info(f"✓ HTTP wake successful ({http_wake_time:.2f}s)")
        
        # Verify both configurations still enabled
        final_instance = await client.instances.aget(instance.id)
        assert final_instance.wake_on.wake_on_ssh is True, "SSH wake should remain enabled"
        assert final_instance.wake_on.wake_on_http is True, "HTTP wake should remain enabled"
        logger.info("✓ Both wake configurations persisted through multiple cycles")
        
        # Performance summary
        logger.info(f"📊 Combined Wake Functionality Performance:")
        logger.info(f"   SSH Wake Time:      {ssh_wake_time:.2f}s")
        logger.info(f"   HTTP Wake Time:     {http_wake_time:.2f}s")
        logger.info(f"   Average Wake Time:  {(ssh_wake_time + http_wake_time) / 2:.2f}s")
        
    except Exception as e:
        logger.error(f"Combined wake functionality test failed: {e}")
        raise


async def test_wake_functionality_with_ttl(client, wake_ready_instance):
    """
    Test wake functionality integration with TTL pause action.
    
    Validates:
    1. Instance with TTL pause action can be configured for wake
    2. Instance pauses automatically when TTL expires
    3. Wake functionality works after TTL-triggered pause
    4. TTL resets appropriately after wake events
    """
    logger.info("Testing wake functionality with TTL integration")
    
    instance_data = wake_ready_instance
    instance = instance_data['instance']
    ttl_seconds = 15  # Short TTL for testing
    
    try:
        # Configure wake functionality and TTL
        logger.info(f"Configuring wake-on-SSH and TTL ({ttl_seconds}s, pause action)")
        await instance.aset_wake_on(wake_on_ssh=True)
        await instance.aset_ttl(ttl_seconds=ttl_seconds, ttl_action='pause')
        
        # Verify configurations
        instance_details = await client.instances.aget(instance.id)
        assert instance_details.wake_on.wake_on_ssh is True, "wake_on_ssh should be enabled"
        assert instance_details.ttl.ttl_expire_at is not None, "TTL should be set"
        logger.info("✓ Wake and TTL configurations verified")
        
        initial_expire_at = instance_details.ttl.ttl_expire_at
        logger.info(f"TTL will expire at: {datetime.fromtimestamp(initial_expire_at)}")
        
        # Wait for TTL to expire and instance to pause
        logger.info(f"Waiting {ttl_seconds + 5}s for TTL-triggered pause")
        await asyncio.sleep(ttl_seconds + 5)
        
        # Poll for paused status
        max_wait_for_pause = 60  # Maximum time to wait for pause
        pause_poll_start = time.time()
        
        while time.time() - pause_poll_start < max_wait_for_pause:
            current_instance = await client.instances.aget(instance.id)
            if current_instance.status == InstanceStatus.PAUSED:
                break
            await asyncio.sleep(3)
        
        ttl_pause_time = time.time() - pause_poll_start
        paused_instance = await client.instances.aget(instance.id)
        assert paused_instance.status == InstanceStatus.PAUSED, f"Instance should be paused by TTL, got: {paused_instance.status}"
        logger.info(f"✓ Instance paused by TTL after {ttl_pause_time:.2f}s")
        
        # Test wake functionality after TTL pause
        logger.info("Testing wake functionality after TTL-triggered pause")
        ssh_wake_start = time.time()
        
        with instance.ssh() as ssh:
            wake_result = ssh.run("echo 'Wake after TTL pause test'")
            ssh_wake_time = time.time() - ssh_wake_start
            
            assert wake_result.exit_code == 0, f"SSH wake after TTL should succeed: {wake_result.stderr}"
            assert "Wake after TTL pause test" in wake_result.stdout, "Wake command output incorrect"
        
        logger.info(f"SSH wake successful after TTL pause ({ssh_wake_time:.2f}s)")
        
        # Verify instance is ready and TTL reset
        await instance.await_until_ready(timeout=120)
        
        post_wake_instance = await client.instances.aget(instance.id)
        assert post_wake_instance.status == InstanceStatus.READY, "Instance should be ready after wake"
        
        # Check that TTL was reset
        new_expire_at = post_wake_instance.ttl.ttl_expire_at
        assert new_expire_at > initial_expire_at, "TTL should be reset to future time after wake"
        
        logger.info(f"✓ TTL reset after wake. New expiration: {datetime.fromtimestamp(new_expire_at)}")
        
        # Verify wake configuration persisted
        assert post_wake_instance.wake_on.wake_on_ssh is True, "Wake configuration should persist"
        logger.info("✓ Wake configuration persisted through TTL cycle")
        
        # Performance summary
        total_ttl_wake_cycle = ttl_seconds + ttl_pause_time + ssh_wake_time
        logger.info(f"📊 TTL + Wake Integration Performance:")
        logger.info(f"   TTL Duration:         {ttl_seconds}s")
        logger.info(f"   TTL Pause Detection:  {ttl_pause_time:.2f}s")
        logger.info(f"   SSH Wake Time:        {ssh_wake_time:.2f}s")
        logger.info(f"   Total Cycle Time:     {total_ttl_wake_cycle:.2f}s")
        
    except Exception as e:
        logger.error(f"TTL + Wake integration test failed: {e}")
        raise