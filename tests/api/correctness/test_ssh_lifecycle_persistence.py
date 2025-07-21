"""
Test SSH access lifecycle persistence across all operations.

This module validates SSH access persistence across:
- Pause/resume cycles
- Reboot operations  
- Snapshot/restore operations (CRITICAL addition)
- SSH key rotation across lifecycle operations
- Direct SSH connections throughout lifecycle
"""
import pytest
import pytest_asyncio
import logging
import time
import json
import asyncio
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

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


async def test_ssh_direct_connection(instance, test_id: str) -> Tuple[bool, float, Dict[str, Any]]:
    """Test direct SSH connection and return detailed results."""
    start_time = time.time()
    
    try:
        ssh_client = instance.ssh()
        connection_time = time.time() - start_time
        
        try:
            # Test basic SSH command
            result = ssh_client.run(f"echo 'SSH test: {test_id}' && whoami && date", timeout=20)
            command_time = time.time() - start_time - connection_time
            
            success = result.returncode == 0 and test_id in result.stdout
            
            return success, time.time() - start_time, {
                'connection_time': connection_time,
                'command_time': command_time, 
                'exit_code': result.returncode,
                'output_length': len(result.stdout),
                'has_test_id': test_id in result.stdout,
                'stdout': result.stdout[:200],  # First 200 chars
                'stderr': result.stderr[:200] if result.stderr else ""
            }
            
        finally:
            ssh_client.close()
            
    except Exception as e:
        duration = time.time() - start_time
        logger.warning(f"Direct SSH connection failed: {e}")
        
        return False, duration, {
            'error': str(e),
            'connection_time': 0,
            'command_time': 0,
            'exit_code': -1,
            'output_length': 0,
            'has_test_id': False
        }


@pytest_asyncio.fixture
async def ssh_lifecycle_instance(client, base_image):
    """Create an instance ready for SSH lifecycle persistence testing."""
    snapshot = None
    instance = None
    
    try:
        # Create snapshot
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=2048,
            disk_size=16*1024
        )
        logger.info(f"Created snapshot {snapshot.id} for SSH lifecycle testing")
        
        # Start instance
        instance = await client.instances.astart(snapshot.id)
        logger.info(f"Started instance {instance.id}")
        
        # Wait until ready
        await instance.await_until_ready(timeout=600)
        logger.info(f"Instance {instance.id} is ready for SSH lifecycle testing")
        
        yield {
            'instance': instance,
            'snapshot': snapshot
        }
        
    finally:
        # Clean up
        if instance:
            try:
                await instance.astop()
                logger.info("SSH lifecycle test instance stopped")
            except Exception as e:
                logger.error(f"Error stopping SSH lifecycle test instance: {e}")
                
        if snapshot:
            try:
                await snapshot.adelete()
                logger.info("SSH lifecycle test snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting SSH lifecycle test snapshot: {e}")


async def test_ssh_persistence_pause_resume_reboot(ssh_lifecycle_instance):
    """Test SSH access persistence across pause/resume and reboot."""
    logger.info("Testing SSH access persistence across pause/resume/reboot lifecycle")
    
    instance_data = ssh_lifecycle_instance
    instance = instance_data['instance']
    
    test_id = uuid.uuid4().hex[:8]
    
    # Create test marker file that should persist
    marker_file = f"/tmp/ssh_lifecycle_test_{test_id}.txt"
    marker_content = f"SSH lifecycle test - {test_id} - {datetime.now().isoformat()}"
    
    # Test initial SSH access (both direct and API)
    logger.info("=== Testing INITIAL SSH access ===")
    
    # Direct SSH test
    initial_direct_success, initial_direct_time, initial_direct_details = await test_ssh_direct_connection(instance, test_id)
    assert initial_direct_success, f"Initial direct SSH access failed: {initial_direct_details}"
    logger.info(f"✅ Initial direct SSH access: {initial_direct_time:.2f}s")
    
    # API SSH test
    api_result, initial_api_time = await timed_operation(
        "initial_ssh_api_test",
        lambda: instance.aexec(f"echo '{marker_content}' > {marker_file} && cat {marker_file}")
    )
    
    assert api_result.exit_code == 0, f"Initial SSH API test failed: {api_result.stderr}"
    assert test_id in api_result.stdout, "Initial SSH API test output incorrect"
    logger.info(f"✅ Initial SSH API access: {initial_api_time:.2f}s")
    
    # Get initial SSH key for comparison
    initial_ssh_key = await instance.assh_key()
    
    lifecycle_results = {
        'initial': {
            'direct_success': initial_direct_success,
            'direct_time': initial_direct_time,
            'direct_details': initial_direct_details,
            'api_success': True,
            'api_time': initial_api_time,
            'ssh_key': initial_ssh_key
        }
    }
    
    try:
        # Test 1: Pause/Resume Cycle
        logger.info("=== Testing SSH persistence through PAUSE/RESUME ===")
        
        # Pause instance
        _, pause_time = await timed_operation(
            "ssh_lifecycle_pause",
            lambda: instance.apause()
        )
        logger.info(f"Instance paused ({pause_time:.2f}s)")
        
        # Resume instance
        _, resume_time = await timed_operation(
            "ssh_lifecycle_resume",
            lambda: instance.aresume()
        )
        logger.info(f"Instance resumed ({resume_time:.2f}s)")
        
        # Wait for instance to be fully ready
        await instance.await_until_ready(timeout=300)
        logger.info("Instance ready after resume")
        
        # Test SSH access after pause/resume
        logger.info("Testing SSH access after pause/resume...")
        
        # Direct SSH test
        resume_direct_success, resume_direct_time, resume_direct_details = await test_ssh_direct_connection(instance, test_id)
        
        # API SSH test - check if marker file survived
        resume_api_result, resume_api_time = await timed_operation(
            "resume_ssh_api_test",
            lambda: instance.aexec(f"cat {marker_file} && echo 'Post-resume test: {test_id}' && date")
        )
        
        resume_api_success = resume_api_result.exit_code == 0 and test_id in resume_api_result.stdout
        
        # Check if SSH key persisted
        resume_ssh_key = await instance.assh_key()
        ssh_key_persisted = (initial_ssh_key.private_key == resume_ssh_key.private_key and 
                           initial_ssh_key.public_key == resume_ssh_key.public_key)
        
        lifecycle_results['post_resume'] = {
            'direct_success': resume_direct_success,
            'direct_time': resume_direct_time,
            'direct_details': resume_direct_details,
            'api_success': resume_api_success,
            'api_time': resume_api_time,
            'ssh_key_persisted': ssh_key_persisted,
            'pause_time': pause_time,
            'resume_time': resume_time,
            'marker_file_survived': test_id in resume_api_result.stdout
        }
        
        logger.info(f"SSH after pause/resume:")
        logger.info(f"  Direct SSH:       {'✅' if resume_direct_success else '❌'} ({resume_direct_time:.2f}s)")
        logger.info(f"  API SSH:          {'✅' if resume_api_success else '❌'} ({resume_api_time:.2f}s)")
        logger.info(f"  SSH Key Persisted: {'✅' if ssh_key_persisted else '❌'}")
        logger.info(f"  Files Survived:    {'✅' if lifecycle_results['post_resume']['marker_file_survived'] else '❌'}")
        
        # Test 2: Reboot Cycle
        logger.info("=== Testing SSH persistence through REBOOT ===")
        
        # Reboot instance
        _, reboot_time = await timed_operation(
            "ssh_lifecycle_reboot",
            lambda: instance.areboot()
        )
        logger.info(f"Instance rebooted ({reboot_time:.2f}s)")
        
        # Wait for instance to be ready after reboot
        await instance.await_until_ready(timeout=300)
        logger.info("Instance ready after reboot")
        
        # Test SSH access after reboot
        logger.info("Testing SSH access after reboot...")
        
        # Direct SSH test
        reboot_direct_success, reboot_direct_time, reboot_direct_details = await test_ssh_direct_connection(instance, test_id)
        
        # API SSH test - check if marker file survived reboot
        reboot_api_result, reboot_api_time = await timed_operation(
            "reboot_ssh_api_test",
            lambda: instance.aexec(f"cat {marker_file} && echo 'Post-reboot test: {test_id}' && uptime")
        )
        
        reboot_api_success = reboot_api_result.exit_code == 0 and test_id in reboot_api_result.stdout
        
        # Check if SSH key persisted through reboot
        reboot_ssh_key = await instance.assh_key()
        ssh_key_persisted_reboot = (initial_ssh_key.private_key == reboot_ssh_key.private_key and 
                                   initial_ssh_key.public_key == reboot_ssh_key.public_key)
        
        lifecycle_results['post_reboot'] = {
            'direct_success': reboot_direct_success,
            'direct_time': reboot_direct_time,
            'direct_details': reboot_direct_details,
            'api_success': reboot_api_success,
            'api_time': reboot_api_time,
            'ssh_key_persisted': ssh_key_persisted_reboot,
            'reboot_time': reboot_time,
            'marker_file_survived': test_id in reboot_api_result.stdout
        }
        
        logger.info(f"SSH after reboot:")
        logger.info(f"  Direct SSH:       {'✅' if reboot_direct_success else '❌'} ({reboot_direct_time:.2f}s)")
        logger.info(f"  API SSH:          {'✅' if reboot_api_success else '❌'} ({reboot_api_time:.2f}s)")
        logger.info(f"  SSH Key Persisted: {'✅' if ssh_key_persisted_reboot else '❌'}")
        logger.info(f"  Files Survived:    {'✅' if lifecycle_results['post_reboot']['marker_file_survived'] else '❌'}")
        
        # Summary analysis
        logger.info("📊 SSH Access Lifecycle Persistence Results:")
        logger.info(f"   Initial Access:")
        logger.info(f"     Direct SSH:        ✅ ({lifecycle_results['initial']['direct_time']:.2f}s)")
        logger.info(f"     API SSH:           ✅ ({lifecycle_results['initial']['api_time']:.2f}s)")
        logger.info(f"   Post Pause/Resume:")
        logger.info(f"     Direct SSH:        {'✅' if lifecycle_results['post_resume']['direct_success'] else '❌'} ({lifecycle_results['post_resume']['direct_time']:.2f}s)")
        logger.info(f"     API SSH:           {'✅' if lifecycle_results['post_resume']['api_success'] else '❌'} ({lifecycle_results['post_resume']['api_time']:.2f}s)")
        logger.info(f"     SSH Key Persisted: {'✅' if lifecycle_results['post_resume']['ssh_key_persisted'] else '❌'}")
        logger.info(f"   Post Reboot:")
        logger.info(f"     Direct SSH:        {'✅' if lifecycle_results['post_reboot']['direct_success'] else '❌'} ({lifecycle_results['post_reboot']['direct_time']:.2f}s)")
        logger.info(f"     API SSH:           {'✅' if lifecycle_results['post_reboot']['api_success'] else '❌'} ({lifecycle_results['post_reboot']['api_time']:.2f}s)")
        logger.info(f"     SSH Key Persisted: {'✅' if lifecycle_results['post_reboot']['ssh_key_persisted'] else '❌'}")
        logger.info(f"   Operation Times:")
        logger.info(f"     Pause:   {lifecycle_results['post_resume']['pause_time']:.2f}s")
        logger.info(f"     Resume:  {lifecycle_results['post_resume']['resume_time']:.2f}s")
        logger.info(f"     Reboot:  {lifecycle_results['post_reboot']['reboot_time']:.2f}s")
        
        # Success criteria
        assert lifecycle_results['post_resume']['direct_success'], "Direct SSH should work after pause/resume"
        assert lifecycle_results['post_resume']['api_success'], "API SSH should work after pause/resume"
        assert lifecycle_results['post_resume']['ssh_key_persisted'], "SSH key should persist through pause/resume"
        
        assert lifecycle_results['post_reboot']['direct_success'], "Direct SSH should work after reboot"
        assert lifecycle_results['post_reboot']['api_success'], "API SSH should work after reboot"
        assert lifecycle_results['post_reboot']['ssh_key_persisted'], "SSH key should persist through reboot"
        
        logger.info("✅ SSH access lifecycle persistence test completed successfully")
        
    finally:
        # Cleanup marker file
        try:
            await instance.aexec(f"rm -f {marker_file}")
        except Exception as e:
            logger.warning(f"Error cleaning up marker file: {e}")


async def test_ssh_persistence_snapshot_restore(ssh_lifecycle_instance, client):
    """Test SSH access persistence across snapshot/restore operations (CRITICAL)."""
    logger.info("Testing SSH access persistence across snapshot/restore (CRITICAL)")
    
    instance_data = ssh_lifecycle_instance
    original_instance = instance_data['instance']
    
    test_id = uuid.uuid4().hex[:8]
    marker_file = f"/tmp/ssh_snapshot_test_{test_id}.txt"
    marker_content = f"SSH snapshot/restore test - {test_id} - {datetime.now().isoformat()}"
    
    # Test initial SSH on original instance
    logger.info("=== Testing INITIAL SSH on original instance ===")
    
    # Direct SSH test
    original_direct_success, original_direct_time, original_direct_details = await test_ssh_direct_connection(original_instance, test_id)
    assert original_direct_success, f"Original instance direct SSH failed: {original_direct_details}"
    logger.info(f"✅ Original instance direct SSH: {original_direct_time:.2f}s")
    
    # Create marker file and test API SSH
    api_result, original_api_time = await timed_operation(
        "original_ssh_api_test",
        lambda: original_instance.aexec(f"echo '{marker_content}' > {marker_file} && cat {marker_file} && whoami")
    )
    
    assert api_result.exit_code == 0 and test_id in api_result.stdout, "Original instance SSH API failed"
    logger.info(f"✅ Original instance SSH API: {original_api_time:.2f}s")
    
    # Get original SSH key
    original_ssh_key = await original_instance.assh_key()
    
    # Create snapshot from running instance
    logger.info("Creating snapshot from running instance with SSH test files...")
    
    instance_snapshot, snapshot_time = await timed_operation(
        "ssh_snapshot_create",
        lambda: original_instance.asnapshot()
    )
    
    logger.info(f"Created snapshot {instance_snapshot.id} ({snapshot_time:.2f}s)")
    
    # Start new instance from snapshot
    logger.info("Starting new instance from snapshot...")
    
    restored_instance, restore_time = await timed_operation(
        "ssh_snapshot_restore",
        lambda: client.instances.astart(instance_snapshot.id)
    )
    
    logger.info(f"Started restored instance {restored_instance.id} ({restore_time:.2f}s)")
    
    try:
        # Wait for restored instance to be ready
        await restored_instance.await_until_ready(timeout=600)
        logger.info("Restored instance is ready")
        
        # Test SSH access on restored instance
        logger.info("=== Testing SSH access on RESTORED instance ===")
        
        # Direct SSH test on restored instance
        restored_direct_success, restored_direct_time, restored_direct_details = await test_ssh_direct_connection(restored_instance, test_id)
        
        # API SSH test - check if marker file persisted
        restored_api_result, restored_api_time = await timed_operation(
            "restored_ssh_api_test",
            lambda: restored_instance.aexec(f"cat {marker_file} && echo 'Restored instance test: {test_id}' && hostname")
        )
        
        restored_api_success = restored_api_result.exit_code == 0 and test_id in restored_api_result.stdout
        marker_file_persisted = test_id in restored_api_result.stdout
        
        # Check SSH key on restored instance
        restored_ssh_key = await restored_instance.assh_key()
        
        # SSH keys should be different between instances (each instance gets its own key)
        ssh_keys_different = (original_ssh_key.private_key != restored_ssh_key.private_key or
                             original_ssh_key.public_key != restored_ssh_key.public_key)
        
        # Test if both SSH keys work on their respective instances
        logger.info("Testing SSH key isolation between original and restored instances...")
        
        # Original instance should still work with original key
        original_still_works, original_retest_time, _ = await test_ssh_direct_connection(original_instance, f"{test_id}_original")
        
        # Test SSH key rotation on restored instance
        logger.info("Testing SSH key rotation on restored instance...")
        
        rotated_ssh_key, rotation_time = await timed_operation(
            "restored_ssh_key_rotation",
            lambda: restored_instance.assh_key_rotate()
        )
        
        # Test SSH access after key rotation on restored instance
        post_rotation_success, post_rotation_time, post_rotation_details = await test_ssh_direct_connection(restored_instance, f"{test_id}_rotated")
        
        logger.info(f"📊 SSH Access Snapshot/Restore Results:")
        logger.info(f"   Original Instance:")
        logger.info(f"     Direct SSH:         ✅ ({original_direct_time:.2f}s)")
        logger.info(f"     API SSH:            ✅ ({original_api_time:.2f}s)")
        logger.info(f"     Still Works:        {'✅' if original_still_works else '❌'} ({original_retest_time:.2f}s)")
        logger.info(f"   Snapshot Operation:     {snapshot_time:.2f}s")
        logger.info(f"   Restore Operation:      {restore_time:.2f}s")
        logger.info(f"   Restored Instance:")
        logger.info(f"     Direct SSH:         {'✅' if restored_direct_success else '❌'} ({restored_direct_time:.2f}s)")
        logger.info(f"     API SSH:            {'✅' if restored_api_success else '❌'} ({restored_api_time:.2f}s)")
        logger.info(f"     Files Persisted:    {'✅' if marker_file_persisted else '❌'}")
        logger.info(f"     SSH Keys Different: {'✅' if ssh_keys_different else '❌'}")
        logger.info(f"     Key Rotation:       {'✅' if post_rotation_success else '❌'} ({rotation_time:.2f}s + {post_rotation_time:.2f}s)")
        
        # Success criteria
        assert restored_direct_success, "Direct SSH should work on restored instance"
        assert restored_api_success, "API SSH should work on restored instance"
        assert marker_file_persisted, "Files should persist through snapshot/restore"
        assert ssh_keys_different, "SSH keys should be different between original and restored instances"
        assert original_still_works, "Original instance SSH should still work after restore"
        assert post_rotation_success, "SSH key rotation should work on restored instance"
        
        logger.info("✅ SSH access snapshot/restore persistence test completed successfully")
        
    finally:
        # Cleanup
        try:
            await restored_instance.astop()
            logger.info("Restored instance stopped")
        except Exception as e:
            logger.error(f"Error stopping restored instance: {e}")
            
        try:
            await instance_snapshot.adelete()
            logger.info("Instance snapshot deleted")
        except Exception as e:
            logger.error(f"Error deleting instance snapshot: {e}")
            
        # Cleanup marker file on original instance
        try:
            await original_instance.aexec(f"rm -f {marker_file}")
        except Exception as e:
            logger.warning(f"Error cleaning up marker file: {e}")


async def test_ssh_persistence_combined_with_key_rotation(ssh_lifecycle_instance, client):
    """Test SSH persistence and key rotation across combined lifecycle operations."""
    logger.info("Testing SSH with key rotation across COMBINED lifecycle operations")
    
    instance_data = ssh_lifecycle_instance
    instance = instance_data['instance']
    
    test_id = uuid.uuid4().hex[:8]
    
    # Test initial state
    initial_success, initial_time, _ = await test_ssh_direct_connection(instance, test_id)
    assert initial_success, "Initial SSH must work"
    
    initial_ssh_key = await instance.assh_key()
    
    timeline = []
    key_history = [initial_ssh_key]
    
    try:
        # Step 1: Rotate key
        logger.info("Step 1: SSH key rotation")
        
        rotated_key_1, rotation_time_1 = await timed_operation(
            "combined_key_rotation_1",
            lambda: instance.assh_key_rotate()
        )
        
        key_history.append(rotated_key_1)
        timeline.append("KEY_ROTATED_1")
        
        # Test SSH after rotation
        post_rot_1_success, post_rot_1_time, _ = await test_ssh_direct_connection(instance, f"{test_id}_rot1")
        assert post_rot_1_success, "SSH should work after key rotation"
        
        # Step 2: Pause/Resume
        logger.info("Step 2: Pause → Resume")
        
        await instance.apause()
        timeline.append("PAUSED")
        
        await instance.aresume()
        await instance.await_until_ready(timeout=300)
        timeline.append("RESUMED")
        
        # Test SSH after pause/resume
        post_resume_success, post_resume_time, _ = await test_ssh_direct_connection(instance, f"{test_id}_resume")
        
        # Check key persistence
        post_resume_key = await instance.assh_key()
        key_persisted_resume = (rotated_key_1.private_key == post_resume_key.private_key)
        
        # Step 3: Another key rotation
        logger.info("Step 3: Second SSH key rotation")
        
        rotated_key_2, rotation_time_2 = await timed_operation(
            "combined_key_rotation_2",
            lambda: instance.assh_key_rotate()
        )
        
        key_history.append(rotated_key_2)
        timeline.append("KEY_ROTATED_2")
        
        # Test SSH after second rotation
        post_rot_2_success, post_rot_2_time, _ = await test_ssh_direct_connection(instance, f"{test_id}_rot2")
        
        # Step 4: Create snapshot
        logger.info("Step 4: Create snapshot")
        
        snapshot = await instance.asnapshot()
        timeline.append("SNAPSHOT_CREATED")
        
        # Step 5: Start new instance from snapshot
        logger.info("Step 5: Start new instance from snapshot")
        
        new_instance = await client.instances.astart(snapshot.id)
        await new_instance.await_until_ready(timeout=600)
        timeline.append("INSTANCE_RESTORED")
        
        # Test SSH on new instance
        new_instance_success, new_instance_time, _ = await test_ssh_direct_connection(new_instance, f"{test_id}_new")
        
        # Get SSH key from new instance
        new_instance_key = await new_instance.assh_key()
        
        # Step 6: Reboot new instance
        logger.info("Step 6: Reboot new instance")
        
        await new_instance.areboot()
        await new_instance.await_until_ready(timeout=300)
        timeline.append("REBOOTED")
        
        # Final SSH test
        final_success, final_time, _ = await test_ssh_direct_connection(new_instance, f"{test_id}_final")
        
        # Final key check
        final_key = await new_instance.assh_key()
        key_persisted_reboot = (new_instance_key.private_key == final_key.private_key)
        
        # Analysis
        logger.info(f"📊 Combined SSH Lifecycle with Key Rotation Results:")
        logger.info(f"   Timeline: {' → '.join(timeline)}")
        logger.info(f"   Initial SSH:            ✅ ({initial_time:.2f}s)")
        logger.info(f"   After Key Rotation 1:   {'✅' if post_rot_1_success else '❌'} ({post_rot_1_time:.2f}s)")
        logger.info(f"   After Pause/Resume:     {'✅' if post_resume_success else '❌'} ({post_resume_time:.2f}s)")
        logger.info(f"   Key Persisted P/R:      {'✅' if key_persisted_resume else '❌'}")
        logger.info(f"   After Key Rotation 2:   {'✅' if post_rot_2_success else '❌'} ({post_rot_2_time:.2f}s)")
        logger.info(f"   New Instance SSH:       {'✅' if new_instance_success else '❌'} ({new_instance_time:.2f}s)")
        logger.info(f"   After Reboot:           {'✅' if final_success else '❌'} ({final_time:.2f}s)")
        logger.info(f"   Key Persisted Reboot:   {'✅' if key_persisted_reboot else '❌'}")
        logger.info(f"   Key Rotations: {len(key_history) - 1}")
        
        # Verify all keys are different
        all_keys_different = True
        for i in range(len(key_history)):
            for j in range(i + 1, len(key_history)):
                if key_history[i].private_key == key_history[j].private_key:
                    all_keys_different = False
                    break
            if not all_keys_different:
                break
        
        logger.info(f"   All Keys Different:     {'✅' if all_keys_different else '❌'}")
        
        # Success criteria
        assert post_rot_1_success, "SSH should work after first key rotation"
        assert post_resume_success, "SSH should work after pause/resume"
        assert key_persisted_resume, "SSH key should persist through pause/resume"
        assert post_rot_2_success, "SSH should work after second key rotation"
        assert new_instance_success, "SSH should work on restored instance"
        assert final_success, "SSH should work after reboot"
        assert key_persisted_reboot, "SSH key should persist through reboot"
        assert all_keys_different, "All rotated keys should be unique"
        
        logger.info("✅ Combined SSH lifecycle with key rotation test completed successfully")
        
        # Cleanup
        try:
            await new_instance.astop()
            await snapshot.adelete()
        except Exception as e:
            logger.warning(f"Cleanup error: {e}")
            
    except Exception as e:
        logger.error(f"Combined SSH lifecycle test failed: {e}")
        raise