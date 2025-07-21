"""
Test SSH direct connection correctness.

This module validates actual SSH connectivity (not just API calls):
- Direct SSH connections using instance.ssh()
- SSH key structure validation (fail instead of skip)
- SSH connections before/after key rotation
- SSH connection stability with multiple commands
- Comparison between direct SSH and API methods
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
from typing import Optional, Tuple

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
async def ssh_direct_instance(client, base_image):
    """Create an instance with SSH access configured for direct SSH testing."""
    snapshot = None
    instance = None
    
    try:
        # Create snapshot
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=2048,  # Use larger instance for better SSH performance
            disk_size=16*1024
        )
        logger.info(f"Created snapshot {snapshot.id} for direct SSH testing")
        
        # Start instance  
        instance = await client.instances.astart(snapshot.id)
        logger.info(f"Started instance {instance.id}")
        
        # Wait until ready with longer timeout for SSH setup
        await instance.await_until_ready(timeout=600)
        logger.info(f"Instance {instance.id} is ready for direct SSH testing")
        
        yield {
            'instance': instance,
            'snapshot': snapshot
        }
        
    finally:
        # Clean up
        if instance:
            try:
                await instance.astop()
                logger.info("Direct SSH test instance stopped")
            except Exception as e:
                logger.error(f"Error stopping direct SSH test instance: {e}")
                
        if snapshot:
            try:
                await snapshot.adelete()
                logger.info("Direct SSH test snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting direct SSH test snapshot: {e}")


async def test_ssh_key_structure_validation(ssh_direct_instance):
    """Test SSH key object has all required fields - FAIL instead of skip."""
    logger.info("Testing SSH key structure validation (CRITICAL: must not skip)")
    
    instance_data = ssh_direct_instance
    instance = instance_data['instance']
    
    # Get SSH key 
    ssh_key, retrieval_time = await timed_operation(
        "ssh_key_structure_retrieval",
        lambda: instance.assh_key()
    )
    
    logger.info(f"SSH key retrieved in {retrieval_time:.2f}s")
    logger.info(f"SSH key type: {type(ssh_key)}")
    logger.info(f"SSH key attributes: {dir(ssh_key)}")
    
    # CRITICAL: These assertions must FAIL the test, not skip it
    assert hasattr(ssh_key, 'object'), "SSH key must have 'object' attribute"
    assert ssh_key.object == "instance_ssh_key", f"SSH key object type must be 'instance_ssh_key', got: {getattr(ssh_key, 'object', 'MISSING')}"
    
    assert hasattr(ssh_key, 'private_key'), "SSH key must have 'private_key' attribute"
    assert ssh_key.private_key, "SSH key private_key must not be empty"
    assert isinstance(ssh_key.private_key, str), f"SSH key private_key must be string, got: {type(ssh_key.private_key)}"
    assert len(ssh_key.private_key) > 100, "SSH key private_key seems too short"
    
    assert hasattr(ssh_key, 'public_key'), "SSH key must have 'public_key' attribute"
    assert ssh_key.public_key, "SSH key public_key must not be empty"
    assert isinstance(ssh_key.public_key, str), f"SSH key public_key must be string, got: {type(ssh_key.public_key)}"
    # SSH keys can start with various prefixes depending on key type
    valid_prefixes = ['ssh-', 'ecdsa-sha2-', 'ssh-rsa', 'ssh-ed25519']
    key_starts_valid = any(ssh_key.public_key.startswith(prefix) for prefix in valid_prefixes)
    assert key_starts_valid, f"SSH key public_key should start with valid prefix {valid_prefixes}, got: {ssh_key.public_key[:30]}"
    
    assert hasattr(ssh_key, 'password'), "SSH key must have 'password' attribute"
    # Note: password might be empty string, but the attribute must exist
    assert ssh_key.password is not None, "SSH key password must not be None"
    
    logger.info("✅ SSH key structure validation PASSED (all required fields present)")


async def test_direct_ssh_connection_basic(ssh_direct_instance):
    """Test actual direct SSH connection using instance.ssh() method."""
    logger.info("Testing direct SSH connection (CRITICAL: actual SSH, not API)")
    
    instance_data = ssh_direct_instance
    instance = instance_data['instance']
    
    # CRITICAL: Use direct SSH connection, not instance.aexec()
    logger.info("Opening direct SSH connection...")
    
    start_time = time.time()
    try:
        ssh_client = instance.ssh()
        connection_time = time.time() - start_time
        logger.info(f"SSH client created in {connection_time:.2f}s")
        
        try:
            # Test basic command execution via direct SSH
            logger.info("Running command via direct SSH connection...")
            
            cmd_start = time.time()
            result = ssh_client.run("echo 'Direct SSH test successful'", timeout=30)
            cmd_duration = time.time() - cmd_start
            
            # Log performance
            log_performance_metric("direct_ssh_command", cmd_duration, "success")
            
            # Validate result
            assert result.returncode == 0, f"Direct SSH command failed with exit code {result.returncode}: {result.stderr}"
            assert "Direct SSH test successful" in result.stdout, f"Unexpected SSH output: {result.stdout}"
            
            logger.info(f"✅ Direct SSH command executed successfully in {cmd_duration:.2f}s")
            
            # Test multiple commands to verify connection stability
            test_commands = [
                ("whoami", "Get current user"),
                ("pwd", "Get working directory"), 
                ("date", "Get current date"),
                ("echo $HOME", "Get home directory"),
                ("uname -s", "Get system name")
            ]
            
            command_results = []
            
            for command, description in test_commands:
                logger.info(f"Testing direct SSH: {description}")
                
                cmd_start = time.time()
                try:
                    result = ssh_client.run(command, timeout=15)
                    cmd_duration = time.time() - cmd_start
                    
                    success = result.returncode == 0
                    command_results.append({
                        'command': command,
                        'description': description,
                        'duration': cmd_duration,
                        'success': success,
                        'output_length': len(result.stdout) if success else 0
                    })
                    
                    if success:
                        logger.info(f"✅ '{command}' succeeded in {cmd_duration:.2f}s")
                    else:
                        logger.warning(f"⚠️ '{command}' failed: {result.stderr}")
                        
                except Exception as e:
                    cmd_duration = time.time() - cmd_start
                    logger.error(f"❌ '{command}' exception after {cmd_duration:.2f}s: {e}")
                    command_results.append({
                        'command': command,
                        'description': description,
                        'duration': cmd_duration,
                        'success': False,
                        'error': str(e)
                    })
            
            # Analyze command results
            successful_commands = [r for r in command_results if r['success']]
            success_rate = len(successful_commands) / len(test_commands)
            
            logger.info(f"📊 Direct SSH Connection Results:")
            logger.info(f"   Connection Time: {connection_time:.2f}s")
            logger.info(f"   Commands:       {len(successful_commands)}/{len(test_commands)} successful")
            logger.info(f"   Success Rate:   {success_rate*100:.1f}%")
            
            if successful_commands:
                avg_cmd_time = sum(r['duration'] for r in successful_commands) / len(successful_commands)
                logger.info(f"   Avg Cmd Time:   {avg_cmd_time:.2f}s")
            
            # Require high success rate for direct SSH
            assert success_rate >= 0.8, f"Direct SSH command success rate too low: {success_rate*100:.1f}% (need ≥80%)"
            
        finally:
            # Always close the SSH connection
            try:
                ssh_client.close()
                logger.info("SSH connection closed")
            except Exception as e:
                logger.warning(f"Error closing SSH connection: {e}")
                
    except Exception as e:
        connection_time = time.time() - start_time
        log_performance_metric("direct_ssh_connection", connection_time, "failed", str(e))
        logger.error(f"Direct SSH connection failed after {connection_time:.2f}s: {e}")
        raise


async def test_ssh_connection_before_after_rotation(ssh_direct_instance):
    """Test actual SSH connections before and after key rotation."""
    logger.info("Testing SSH connections before and after key rotation (CRITICAL: direct SSH)")
    
    instance_data = ssh_direct_instance
    instance = instance_data['instance']
    
    # Test SSH connection BEFORE rotation using direct SSH
    logger.info("Testing direct SSH connection BEFORE key rotation")
    
    ssh_client = instance.ssh()
    try:
        result, pre_rotation_time = await timed_operation(
            "direct_ssh_pre_rotation",
            lambda: asyncio.get_event_loop().run_in_executor(
                None, lambda: ssh_client.run("echo 'Pre-rotation SSH test'", timeout=15)
            )
        )
        
        assert result.returncode == 0, f"Pre-rotation SSH failed: {result.stderr}"
        assert "Pre-rotation SSH test" in result.stdout, "Pre-rotation SSH output incorrect"
        logger.info(f"✅ Direct SSH working before rotation ({pre_rotation_time:.2f}s)")
        
    finally:
        ssh_client.close()
    
    # Get original key for comparison
    original_key = await instance.assh_key()
    
    # Rotate the SSH key
    logger.info("Rotating SSH key...")
    new_key, rotation_time = await timed_operation(
        "ssh_key_rotation_direct_test",
        lambda: instance.assh_key_rotate()
    )
    
    logger.info(f"SSH key rotated in {rotation_time:.2f}s")
    
    # Verify keys are different
    assert original_key.private_key != new_key.private_key, "New SSH key should be different from original"
    assert original_key.public_key != new_key.public_key, "New SSH public key should be different from original"
    logger.info("✅ SSH keys are different after rotation")
    
    # Brief pause for key propagation
    await asyncio.sleep(2)
    
    # Test SSH connection AFTER rotation using direct SSH
    logger.info("Testing direct SSH connection AFTER key rotation")
    
    ssh_client = instance.ssh()
    try:
        result, post_rotation_time = await timed_operation(
            "direct_ssh_post_rotation",
            lambda: asyncio.get_event_loop().run_in_executor(
                None, lambda: ssh_client.run("echo 'Post-rotation SSH test'", timeout=15)
            )
        )
        
        assert result.returncode == 0, f"Post-rotation SSH failed: {result.stderr}"
        assert "Post-rotation SSH test" in result.stdout, "Post-rotation SSH output incorrect"
        logger.info(f"✅ Direct SSH working after rotation ({post_rotation_time:.2f}s)")
        
        # Test more complex command to verify full functionality
        complex_result, complex_time = await timed_operation(
            "direct_ssh_complex_post_rotation",
            lambda: asyncio.get_event_loop().run_in_executor(
                None, lambda: ssh_client.run("whoami && pwd && date && echo 'Complex SSH test complete'", timeout=20)
            )
        )
        
        assert complex_result.returncode == 0, f"Complex SSH command failed: {complex_result.stderr}"
        assert "Complex SSH test complete" in complex_result.stdout, "Complex SSH output incorrect"
        logger.info(f"✅ Complex SSH command working after rotation ({complex_time:.2f}s)")
        
    finally:
        ssh_client.close()
    
    # Performance summary
    logger.info(f"📊 SSH Key Rotation Performance (Direct SSH):")
    logger.info(f"   Pre-rotation SSH:  {pre_rotation_time:.2f}s")
    logger.info(f"   Key Rotation:      {rotation_time:.2f}s")
    logger.info(f"   Post-rotation SSH: {post_rotation_time:.2f}s")
    logger.info(f"   Complex Command:   {complex_time:.2f}s")
    logger.info(f"   Total Test Time:   {pre_rotation_time + rotation_time + post_rotation_time + complex_time:.2f}s")


async def test_direct_ssh_vs_api_comparison(ssh_direct_instance):
    """Compare direct SSH vs API methods for same operations."""
    logger.info("Comparing direct SSH vs API methods")
    
    instance_data = ssh_direct_instance
    instance = instance_data['instance']
    
    test_command = "echo 'Comparison test' && date && whoami"
    
    # Test via direct SSH
    logger.info("Testing via direct SSH...")
    
    ssh_client = instance.ssh()
    try:
        direct_result, direct_time = await timed_operation(
            "comparison_direct_ssh",
            lambda: asyncio.get_event_loop().run_in_executor(
                None, lambda: ssh_client.run(test_command, timeout=15)
            )
        )
        
        direct_success = direct_result.returncode == 0
        direct_output = direct_result.stdout if direct_success else direct_result.stderr
        
    finally:
        ssh_client.close()
    
    # Test via API
    logger.info("Testing via API...")
    
    api_result, api_time = await timed_operation(
        "comparison_api_exec",
        lambda: instance.aexec(test_command)
    )
    
    api_success = api_result.exit_code == 0
    api_output = api_result.stdout if api_success else api_result.stderr
    
    # Compare results
    logger.info(f"📊 Direct SSH vs API Comparison:")
    logger.info(f"   Direct SSH:")
    logger.info(f"     Success:  {direct_success}")
    logger.info(f"     Time:     {direct_time:.2f}s")
    logger.info(f"     Output:   {len(direct_output)} chars")
    logger.info(f"   API Method:")
    logger.info(f"     Success:  {api_success}")
    logger.info(f"     Time:     {api_time:.2f}s")
    logger.info(f"     Output:   {len(api_output)} chars")
    
    # Both methods should succeed
    assert direct_success, f"Direct SSH method should succeed: {direct_output}"
    assert api_success, f"API method should succeed: {api_output}"
    
    # Both should have similar output (allowing for minor differences)
    assert "Comparison test" in direct_output, "Direct SSH should contain test string"
    assert "Comparison test" in api_output, "API should contain test string"
    
    # Performance comparison
    speed_ratio = api_time / direct_time if direct_time > 0 else float('inf')
    logger.info(f"   Speed Ratio: API is {speed_ratio:.1f}x {'slower' if speed_ratio > 1 else 'faster'} than direct SSH")
    
    logger.info("✅ Both direct SSH and API methods working correctly")


async def test_direct_ssh_file_operations(ssh_direct_instance):
    """Test file operations via direct SSH connection."""
    logger.info("Testing file operations via direct SSH")
    
    instance_data = ssh_direct_instance
    instance = instance_data['instance']
    
    test_filename = f"/tmp/direct_ssh_test_{uuid.uuid4().hex[:8]}.txt"
    test_content = f"Direct SSH file test - {datetime.now().isoformat()}\nMultiple lines\nTest complete"
    
    ssh_client = instance.ssh()
    try:
        # Create file via SSH
        logger.info(f"Creating test file: {test_filename}")
        
        create_result, create_time = await timed_operation(
            "direct_ssh_file_create",
            lambda: asyncio.get_event_loop().run_in_executor(
                None, lambda: ssh_client.run(f"cat > {test_filename} << 'EOF'\n{test_content}\nEOF", timeout=15)
            )
        )
        
        assert create_result.returncode == 0, f"File creation failed: {create_result.stderr}"
        logger.info(f"✅ File created via direct SSH ({create_time:.2f}s)")
        
        # Read file back via SSH
        logger.info("Reading test file back")
        
        read_result, read_time = await timed_operation(
            "direct_ssh_file_read",
            lambda: asyncio.get_event_loop().run_in_executor(
                None, lambda: ssh_client.run(f"cat {test_filename}", timeout=15)
            )
        )
        
        assert read_result.returncode == 0, f"File reading failed: {read_result.stderr}"
        assert test_content.replace('\n', '') in read_result.stdout.replace('\n', ''), "File content doesn't match"
        logger.info(f"✅ File read via direct SSH ({read_time:.2f}s)")
        
        # Test file permissions and metadata
        logger.info("Testing file metadata")
        
        stat_result, stat_time = await timed_operation(
            "direct_ssh_file_stat",
            lambda: asyncio.get_event_loop().run_in_executor(
                None, lambda: ssh_client.run(f"ls -la {test_filename} && wc -l {test_filename}", timeout=15)
            )
        )
        
        assert stat_result.returncode == 0, f"File stat failed: {stat_result.stderr}"
        assert test_filename in stat_result.stdout, "Filename should appear in ls output"
        logger.info(f"✅ File metadata retrieved via direct SSH ({stat_time:.2f}s)")
        
        # Cleanup file
        logger.info("Cleaning up test file")
        
        cleanup_result, cleanup_time = await timed_operation(
            "direct_ssh_file_cleanup",
            lambda: asyncio.get_event_loop().run_in_executor(
                None, lambda: ssh_client.run(f"rm -f {test_filename}", timeout=15)
            )
        )
        
        assert cleanup_result.returncode == 0, f"File cleanup failed: {cleanup_result.stderr}"
        logger.info(f"✅ File cleaned up via direct SSH ({cleanup_time:.2f}s)")
        
        # Verify file is gone
        verify_result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: ssh_client.run(f"ls {test_filename} 2>/dev/null || echo 'FILE_NOT_FOUND'", timeout=10)
        )
        assert "FILE_NOT_FOUND" in verify_result.stdout or verify_result.returncode != 0, "File should be deleted"
        
        logger.info(f"📊 Direct SSH File Operations Performance:")
        logger.info(f"   Create: {create_time:.2f}s")
        logger.info(f"   Read:   {read_time:.2f}s")
        logger.info(f"   Stat:   {stat_time:.2f}s")
        logger.info(f"   Delete: {cleanup_time:.2f}s")
        logger.info(f"   Total:  {create_time + read_time + stat_time + cleanup_time:.2f}s")
        
    finally:
        ssh_client.close()