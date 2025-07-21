"""
Test basic stress testing with workload tools.

This module tests system behavior under load:
- stress-ng execution on instances
- Multiple parallel instances
- Instance branching under load
- Resource cleanup under stress
"""
import pytest
import logging
import time
import json
import asyncio
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

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


@pytest.fixture
async def stress_ready_instance(client, base_image):
    """Create an instance ready for stress testing with larger resources."""
    snapshot = None
    instance = None
    
    try:
        # Create snapshot with larger configuration for better stress testing
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=2,  # More CPUs for better stress testing
            memory=4*1024,  # 4GB for stress testing
            disk_size=32*1024  # 32GB
        )
        logger.info(f"Created snapshot {snapshot.id} for stress testing")
        
        # Start instance
        instance = await client.instances.astart(snapshot.id)
        logger.info(f"Started instance {instance.id}")
        
        # Wait until ready with extended timeout
        await instance.await_until_ready(timeout=600)
        logger.info(f"Instance {instance.id} is ready for stress testing")
        
        # Install stress testing tools
        logger.info("Installing stress testing dependencies")
        install_result = await instance.aexec(
            "apt-get update && apt-get install -y stress-ng htop python3",
            timeout=300
        )
        
        if install_result.exit_code != 0:
            logger.warning(f"Some packages failed to install: {install_result.stderr}")
        else:
            logger.info("✓ Stress testing tools installed successfully")
        
        yield {
            'instance': instance,
            'snapshot': snapshot
        }
        
    finally:
        # Clean up
        if instance:
            try:
                await instance.astop()
                logger.info("Stress test instance stopped")
            except Exception as e:
                logger.error(f"Error stopping stress test instance: {e}")
                
        if snapshot:
            try:
                await snapshot.adelete()
                logger.info("Stress test snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting stress test snapshot: {e}")


async def test_stress_ng_cpu_load(stress_ready_instance):
    """Test stress-ng CPU load on instance."""
    logger.info("Testing stress-ng CPU load")
    
    instance_data = stress_ready_instance
    instance = instance_data['instance']
    
    # Check if stress-ng is available
    check_result = await instance.aexec("which stress-ng")
    if check_result.exit_code != 0:
        pytest.skip("stress-ng not available on instance")
    
    # Run CPU stress test for 30 seconds with 2 workers
    cpu_stress_cmd = "stress-ng --cpu 2 --timeout 30s --metrics-brief"
    
    logger.info("Starting CPU stress test (30 seconds)")
    cpu_result, cpu_stress_time = await timed_operation(
        "stress_ng_cpu_test",
        lambda: instance.aexec(cpu_stress_cmd, timeout=60)
    )
    
    # Verify stress test completed
    assert cpu_result.exit_code == 0, f"CPU stress test failed: {cpu_result.stderr}"
    logger.info(f"✓ CPU stress test completed in {cpu_stress_time:.2f}s")
    
    # Check for stress-ng metrics in output
    if "bogo ops" in cpu_result.stdout:
        logger.info("✓ stress-ng produced performance metrics")
        # Extract some basic metrics
        lines = cpu_result.stdout.split('\n')
        for line in lines:
            if "cpu" in line.lower() and "bogo ops" in line.lower():
                logger.info(f"CPU metrics: {line.strip()}")
                break
    
    # Run memory stress test
    memory_stress_cmd = "stress-ng --vm 2 --vm-bytes 512M --timeout 20s --metrics-brief"
    
    logger.info("Starting memory stress test (20 seconds)")
    memory_result, memory_stress_time = await timed_operation(
        "stress_ng_memory_test",
        lambda: instance.aexec(memory_stress_cmd, timeout=45)
    )
    
    assert memory_result.exit_code == 0, f"Memory stress test failed: {memory_result.stderr}"
    logger.info(f"✓ Memory stress test completed in {memory_stress_time:.2f}s")
    
    # Test I/O stress
    io_stress_cmd = "stress-ng --hdd 1 --hdd-bytes 256M --timeout 15s --metrics-brief"
    
    logger.info("Starting I/O stress test (15 seconds)")
    io_result, io_stress_time = await timed_operation(
        "stress_ng_io_test",
        lambda: instance.aexec(io_stress_cmd, timeout=30)
    )
    
    assert io_result.exit_code == 0, f"I/O stress test failed: {io_result.stderr}"
    logger.info(f"✓ I/O stress test completed in {io_stress_time:.2f}s")
    
    # Performance summary
    total_stress_time = cpu_stress_time + memory_stress_time + io_stress_time
    logger.info(f"📊 Stress-ng Performance:")
    logger.info(f"   CPU Test:    {cpu_stress_time:.2f}s")
    logger.info(f"   Memory Test: {memory_stress_time:.2f}s")
    logger.info(f"   I/O Test:    {io_stress_time:.2f}s")
    logger.info(f"   Total Time:  {total_stress_time:.2f}s")


async def test_multiple_parallel_instances(client, base_image):
    """Test creating and managing multiple parallel instances under load."""
    logger.info("Testing multiple parallel instances")
    
    # Configuration for parallel instances
    instance_count = 3
    snapshots = []
    instances = []
    
    try:
        # Phase 1: Create snapshots in parallel
        logger.info(f"Creating {instance_count} snapshots in parallel")
        
        async def create_snapshot(index: int):
            """Create a snapshot for parallel testing."""
            snapshot_start = time.time()
            
            snapshot = await client.snapshots.acreate(
                image_id=base_image.id,
                vcpus=1,
                memory=1024,
                disk_size=8*1024,
                metadata={"test": "parallel", "index": str(index)}
            )
            
            snapshot_time = time.time() - snapshot_start
            logger.info(f"✓ Snapshot {index+1} created in {snapshot_time:.2f}s: {snapshot.id}")
            return snapshot, snapshot_time
        
        # Create snapshots concurrently
        snapshot_tasks = [create_snapshot(i) for i in range(instance_count)]
        snapshot_results = await asyncio.gather(*snapshot_tasks)
        
        snapshots = [result[0] for result in snapshot_results]
        snapshot_times = [result[1] for result in snapshot_results]
        
        avg_snapshot_time = sum(snapshot_times) / len(snapshot_times)
        logger.info(f"📊 Parallel snapshot creation: avg {avg_snapshot_time:.2f}s, max {max(snapshot_times):.2f}s")
        
        # Phase 2: Start instances in parallel
        logger.info(f"Starting {instance_count} instances in parallel")
        
        async def start_instance(index: int, snapshot):
            """Start an instance for parallel testing."""
            instance_start = time.time()
            
            instance = await client.instances.astart(snapshot.id)
            await instance.await_until_ready(timeout=300)
            
            instance_time = time.time() - instance_start
            logger.info(f"✓ Instance {index+1} started in {instance_time:.2f}s: {instance.id}")
            return instance, instance_time
        
        # Start instances concurrently
        instance_tasks = [start_instance(i, snapshot) for i, snapshot in enumerate(snapshots)]
        instance_results = await asyncio.gather(*instance_tasks)
        
        instances = [result[0] for result in instance_results]
        instance_times = [result[1] for result in instance_results]
        
        avg_instance_time = sum(instance_times) / len(instance_times)
        logger.info(f"📊 Parallel instance startup: avg {avg_instance_time:.2f}s, max {max(instance_times):.2f}s")
        
        # Phase 3: Execute commands on all instances in parallel
        logger.info("Executing commands on all instances in parallel")
        
        async def execute_workload(index: int, instance):
            """Execute a workload on an instance."""
            workload_start = time.time()
            
            # Simple workload: system info + small computation
            commands = [
                "uname -a",
                "cat /proc/cpuinfo | grep processor | wc -l",
                "free -m", 
                "python3 -c 'print(sum(range(10000)))'"
            ]
            
            results = []
            for cmd in commands:
                result = await instance.aexec(cmd, timeout=30)
                results.append(result.exit_code == 0)
            
            workload_time = time.time() - workload_start
            success_rate = sum(results) / len(results)
            
            logger.info(f"✓ Instance {index+1} workload: {success_rate*100:.0f}% success in {workload_time:.2f}s")
            return success_rate, workload_time
        
        # Execute workloads concurrently
        workload_tasks = [execute_workload(i, instance) for i, instance in enumerate(instances)]
        workload_results = await asyncio.gather(*workload_tasks)
        
        success_rates = [result[0] for result in workload_results]
        workload_times = [result[1] for result in workload_results]
        
        overall_success_rate = sum(success_rates) / len(success_rates)
        avg_workload_time = sum(workload_times) / len(workload_times)
        
        # Verify acceptable performance
        assert overall_success_rate >= 0.8, f"Parallel workload success rate too low: {overall_success_rate*100:.1f}% (need ≥80%)"
        
        logger.info(f"📊 Parallel workload execution:")
        logger.info(f"   Success Rate: {overall_success_rate*100:.1f}%")
        logger.info(f"   Avg Time:     {avg_workload_time:.2f}s")
        logger.info(f"   Max Time:     {max(workload_times):.2f}s")
        
    finally:
        # Cleanup: Stop instances in parallel
        if instances:
            logger.info(f"Stopping {len(instances)} instances in parallel")
            
            async def stop_instance(index: int, instance):
                """Stop an instance."""
                try:
                    await instance.astop()
                    logger.info(f"✓ Instance {index+1} stopped")
                except Exception as e:
                    logger.error(f"✗ Instance {index+1} stop failed: {e}")
            
            stop_tasks = [stop_instance(i, instance) for i, instance in enumerate(instances)]
            await asyncio.gather(*stop_tasks, return_exceptions=True)
        
        # Cleanup: Delete snapshots in parallel
        if snapshots:
            logger.info(f"Deleting {len(snapshots)} snapshots in parallel")
            
            async def delete_snapshot(index: int, snapshot):
                """Delete a snapshot."""
                try:
                    await snapshot.adelete()
                    logger.info(f"✓ Snapshot {index+1} deleted")
                except Exception as e:
                    logger.error(f"✗ Snapshot {index+1} delete failed: {e}")
            
            delete_tasks = [delete_snapshot(i, snapshot) for i, snapshot in enumerate(snapshots)]
            await asyncio.gather(*delete_tasks, return_exceptions=True)


async def test_instance_branching_under_load(client, base_image):
    """Test instance branching while running workloads."""
    logger.info("Testing instance branching under load")
    
    snapshot = None
    original_instance = None
    branch_instances = []
    
    try:
        # Create base snapshot
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=2048,  # More memory for branching
            disk_size=16*1024
        )
        
        # Start original instance
        original_instance = await client.instances.astart(snapshot.id)
        await original_instance.await_until_ready(timeout=300)
        logger.info(f"Original instance {original_instance.id} ready")
        
        # Start background workload on original instance
        logger.info("Starting background workload")
        workload_cmd = "python3 -c 'import time; [print(f\"Background work {i}\") or time.sleep(1) for i in range(60)]' &"
        workload_result = await original_instance.aexec(workload_cmd)
        
        if workload_result.exit_code == 0:
            logger.info("✓ Background workload started")
        else:
            logger.warning(f"Background workload failed to start: {workload_result.stderr}")
        
        # Wait a moment for workload to begin
        await asyncio.sleep(3)
        
        # Branch the instance while workload is running
        branch_count = 2
        logger.info(f"Branching instance into {branch_count} copies while under load")
        
        branch_result, branch_time = await timed_operation(
            "instance_branch_under_load",
            lambda: original_instance.abranch(branch_count)
        )
        
        # Extract branch snapshot and instances
        if isinstance(branch_result, tuple) and len(branch_result) == 2:
            branch_snapshot, branch_instances = branch_result
            logger.info(f"✓ Branching successful: snapshot {branch_snapshot.id}, {len(branch_instances)} instances")
        else:
            logger.warning(f"Unexpected branch result format: {type(branch_result)}")
            branch_instances = branch_result if isinstance(branch_result, list) else [branch_result]
        
        # Verify branch instances are functional
        functional_branches = 0
        
        for i, branch_instance in enumerate(branch_instances):
            try:
                # Test basic functionality
                test_result = await branch_instance.aexec("echo 'Branch test' && date", timeout=30)
                
                if test_result.exit_code == 0:
                    functional_branches += 1
                    logger.info(f"✓ Branch instance {i+1} ({branch_instance.id}) functional")
                else:
                    logger.warning(f"⚠ Branch instance {i+1} not functional: {test_result.stderr}")
                    
            except Exception as e:
                logger.warning(f"⚠ Branch instance {i+1} test failed: {e}")
        
        branch_success_rate = functional_branches / len(branch_instances) if branch_instances else 0
        assert branch_success_rate >= 0.5, f"Branch success rate too low: {branch_success_rate*100:.1f}% (need ≥50%)"
        
        logger.info(f"📊 Branching Under Load Performance:")
        logger.info(f"   Branch Time:    {branch_time:.2f}s")
        logger.info(f"   Branches:       {len(branch_instances)}")
        logger.info(f"   Success Rate:   {branch_success_rate*100:.1f}%")
        
    finally:
        # Cleanup branch instances
        if branch_instances:
            logger.info(f"Cleaning up {len(branch_instances)} branch instances")
            
            for i, branch_instance in enumerate(branch_instances):
                try:
                    await branch_instance.astop()
                    logger.info(f"✓ Branch instance {i+1} stopped")
                except Exception as e:
                    logger.error(f"Error stopping branch instance {i+1}: {e}")
        
        # Cleanup original instance
        if original_instance:
            try:
                await original_instance.astop()
                logger.info("Original instance stopped")
            except Exception as e:
                logger.error(f"Error stopping original instance: {e}")
        
        # Cleanup snapshot
        if snapshot:
            try:
                await snapshot.adelete()
                logger.info("Base snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting base snapshot: {e}")


async def test_resource_cleanup_under_stress(client, base_image):
    """Test resource cleanup behavior under stress conditions."""
    logger.info("Testing resource cleanup under stress")
    
    # Create multiple resources rapidly and then clean them up
    test_id = uuid.uuid4().hex[:8]
    created_snapshots = []
    created_instances = []
    
    try:
        # Phase 1: Rapid resource creation
        resource_count = 2  # Keep reasonable for API limits
        logger.info(f"Rapidly creating {resource_count} snapshots and instances")
        
        for i in range(resource_count):
            # Create snapshot
            snapshot = await client.snapshots.acreate(
                image_id=base_image.id,
                vcpus=1,
                memory=1024,
                disk_size=8*1024,
                metadata={"cleanup_test": test_id, "index": str(i)}
            )
            created_snapshots.append(snapshot)
            logger.info(f"✓ Snapshot {i+1} created: {snapshot.id}")
            
            # Start instance from snapshot
            instance = await client.instances.astart(snapshot.id)
            created_instances.append(instance)
            logger.info(f"✓ Instance {i+1} started: {instance.id}")
            
            # Don't wait for ready - create stress by rapid allocation
        
        logger.info(f"Created {len(created_snapshots)} snapshots and {len(created_instances)} instances")
        
        # Phase 2: Rapid cleanup
        logger.info("Beginning rapid resource cleanup")
        
        cleanup_start = time.time()
        
        # Stop instances first
        instance_cleanup_tasks = []
        for i, instance in enumerate(created_instances):
            async def stop_instance(idx, inst):
                try:
                    await inst.astop()
                    logger.info(f"✓ Instance {idx+1} stopped")
                    return True
                except Exception as e:
                    logger.error(f"✗ Instance {idx+1} stop failed: {e}")
                    return False
            
            instance_cleanup_tasks.append(stop_instance(i, instance))
        
        # Execute instance stops in parallel
        instance_results = await asyncio.gather(*instance_cleanup_tasks, return_exceptions=True)
        successful_instance_stops = sum(1 for result in instance_results if result is True)
        
        # Delete snapshots in parallel
        snapshot_cleanup_tasks = []
        for i, snapshot in enumerate(created_snapshots):
            async def delete_snapshot(idx, snap):
                try:
                    await snap.adelete()
                    logger.info(f"✓ Snapshot {idx+1} deleted")
                    return True
                except Exception as e:
                    logger.error(f"✗ Snapshot {idx+1} delete failed: {e}")
                    return False
            
            snapshot_cleanup_tasks.append(delete_snapshot(i, snapshot))
        
        # Execute snapshot deletes in parallel
        snapshot_results = await asyncio.gather(*snapshot_cleanup_tasks, return_exceptions=True)
        successful_snapshot_deletes = sum(1 for result in snapshot_results if result is True)
        
        cleanup_duration = time.time() - cleanup_start
        
        # Calculate success rates
        instance_cleanup_rate = successful_instance_stops / len(created_instances) if created_instances else 1
        snapshot_cleanup_rate = successful_snapshot_deletes / len(created_snapshots) if created_snapshots else 1
        
        # Clear lists since we've cleaned them up
        created_instances.clear()
        created_snapshots.clear()
        
        # Verify acceptable cleanup performance
        assert instance_cleanup_rate >= 0.7, f"Instance cleanup rate too low: {instance_cleanup_rate*100:.1f}% (need ≥70%)"
        assert snapshot_cleanup_rate >= 0.7, f"Snapshot cleanup rate too low: {snapshot_cleanup_rate*100:.1f}% (need ≥70%)"
        
        logger.info(f"📊 Resource Cleanup Under Stress:")
        logger.info(f"   Total Resources:      {resource_count * 2}")
        logger.info(f"   Instance Cleanup:     {instance_cleanup_rate*100:.1f}% ({successful_instance_stops}/{len(instance_results)})")
        logger.info(f"   Snapshot Cleanup:     {snapshot_cleanup_rate*100:.1f}% ({successful_snapshot_deletes}/{len(snapshot_results)})")
        logger.info(f"   Cleanup Duration:     {cleanup_duration:.2f}s")
        
    finally:
        # Emergency cleanup - stop any remaining instances
        if created_instances:
            logger.info(f"Emergency cleanup: stopping {len(created_instances)} remaining instances")
            for instance in created_instances:
                try:
                    await instance.astop()
                except Exception as e:
                    logger.error(f"Emergency instance stop failed: {e}")
        
        # Emergency cleanup - delete any remaining snapshots
        if created_snapshots:
            logger.info(f"Emergency cleanup: deleting {len(created_snapshots)} remaining snapshots")
            for snapshot in created_snapshots:
                try:
                    await snapshot.adelete()
                except Exception as e:
                    logger.error(f"Emergency snapshot delete failed: {e}")