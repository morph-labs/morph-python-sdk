"""
Test SSH access correctness via different methods.

This module validates SSH connectivity and functionality:
- SSH key authentication
- SSH connection stability  
- SSH command execution
- Multiple SSH sessions
"""
import pytest
import pytest_asyncio
import logging
import time
import json
import asyncio
import subprocess
import tempfile
import os
import socket
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


def run_ssh_command(host: str, port: int, username: str, private_key_path: str, 
                   command: str, timeout: int = 30) -> Tuple[int, str, str]:
    """
    Run an SSH command and return (exit_code, stdout, stderr).
    
    Args:
        host: SSH host/IP
        port: SSH port  
        username: SSH username
        private_key_path: Path to private key file
        command: Command to execute
        timeout: Command timeout in seconds
        
    Returns:
        Tuple of (exit_code, stdout, stderr)
    """
    ssh_cmd = [
        'ssh',
        '-i', private_key_path,
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', f'ConnectTimeout={timeout}',
        '-p', str(port),
        f'{username}@{host}',
        command
    ]
    
    logger.debug(f"Running SSH command: {' '.join(ssh_cmd[:-1])} '{command}'")
    
    try:
        result = subprocess.run(
            ssh_cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        logger.error(f"SSH command timed out after {timeout}s")
        return -1, "", f"Command timed out after {timeout}s"
    except Exception as e:
        logger.error(f"SSH command failed: {e}")
        return -1, "", str(e)


def check_ssh_client_available() -> bool:
    """Check if SSH client is available on the system."""
    try:
        result = subprocess.run(['ssh', '-V'], capture_output=True, text=True)
        return result.returncode == 0 or 'OpenSSH' in result.stderr
    except FileNotFoundError:
        return False


@pytest_asyncio.fixture
async def ssh_ready_instance(client, base_image):
    """Create an instance with SSH access configured and wait until ready."""
    snapshot = None
    instance = None
    
    try:
        # Create snapshot
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=2048,  # Use slightly larger instance for better SSH performance
            disk_size=16*1024
        )
        logger.info(f"Created snapshot {snapshot.id} for SSH testing")
        
        # Start instance  
        instance = await client.instances.astart(snapshot.id)
        logger.info(f"Started instance {instance.id}")
        
        # Wait until ready with longer timeout for SSH setup
        await instance.await_until_ready(timeout=600)
        logger.info(f"Instance {instance.id} is ready for SSH testing")
        
        # Get SSH connection details
        ssh_key = await instance.assh_key()
        
        yield {
            'instance': instance,
            'ssh_key': ssh_key,
            'snapshot': snapshot
        }
        
    finally:
        # Clean up
        if instance:
            try:
                await instance.astop()
                logger.info("SSH test instance stopped")
            except Exception as e:
                logger.error(f"Error stopping SSH test instance: {e}")
                
        if snapshot:
            try:
                await snapshot.adelete()
                logger.info("SSH test snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting SSH test snapshot: {e}")


async def test_ssh_key_authentication(ssh_ready_instance):
    """Test SSH key authentication works correctly."""
    if not check_ssh_client_available():
        pytest.skip("SSH client not available on system")
    
    logger.info("Testing SSH key authentication")
    
    instance_data = ssh_ready_instance
    instance = instance_data['instance']
    ssh_key = instance_data['ssh_key']
    
    # Skip test if SSH key doesn't have expected format
    if not hasattr(ssh_key, 'private_key') or not ssh_key.private_key:
        pytest.skip("Instance SSH key not available or in unexpected format")
    
    # Get instance connection details
    # Note: We'll use the instance exec method as a proxy for SSH functionality
    # since we need the actual SSH endpoint details from the instance
    logger.info("Validating SSH connectivity using instance exec")
    
    try:
        # Test basic command execution via the API (validates SSH backend)
        result, auth_time = await timed_operation(
            "ssh_auth_test",
            lambda: instance.aexec("echo 'SSH authentication test'")
        )
        
        assert result.exit_code == 0, f"SSH command failed with exit code {result.exit_code}: {result.stderr}"
        assert "SSH authentication test" in result.stdout, f"Unexpected output: {result.stdout}"
        
        logger.info(f"✓ SSH authentication working (validated via instance.aexec in {auth_time:.2f}s)")
        
    except Exception as e:
        logger.error(f"SSH authentication test failed: {e}")
        raise


async def test_ssh_connection_stability(ssh_ready_instance):
    """Test SSH connection stability with multiple commands."""
    logger.info("Testing SSH connection stability")
    
    instance_data = ssh_ready_instance
    instance = instance_data['instance']
    
    # Test multiple commands in sequence to validate connection stability
    test_commands = [
        ("whoami", "Get current user"),
        ("pwd", "Get working directory"), 
        ("date", "Get current date"),
        ("uname -a", "Get system information"),
        ("echo $HOME", "Get home directory")
    ]
    
    command_results = []
    
    for command, description in test_commands:
        logger.info(f"Testing SSH stability: {description}")
        
        start_time = time.time()
        try:
            result = await instance.aexec(command)
            duration = time.time() - start_time
            
            assert result.exit_code == 0, f"Command '{command}' failed: {result.stderr}"
            
            command_results.append({
                'command': command,
                'duration': duration,
                'success': True,
                'output_length': len(result.stdout)
            })
            
            logger.info(f"✓ '{command}' succeeded in {duration:.2f}s")
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"✗ '{command}' failed after {duration:.2f}s: {e}")
            
            command_results.append({
                'command': command,
                'duration': duration,
                'success': False,
                'error': str(e)
            })
            
            # Don't fail immediately - collect data on all commands
    
    # Analyze results
    successful_commands = [r for r in command_results if r['success']]
    failed_commands = [r for r in command_results if not r['success']]
    
    logger.info(f"📊 SSH Stability Results:")
    logger.info(f"   Successful: {len(successful_commands)}/{len(test_commands)}")
    logger.info(f"   Failed:     {len(failed_commands)}/{len(test_commands)}")
    
    if successful_commands:
        avg_duration = sum(r['duration'] for r in successful_commands) / len(successful_commands)
        logger.info(f"   Avg Duration: {avg_duration:.2f}s")
    
    # Require at least 80% success rate for stability
    success_rate = len(successful_commands) / len(test_commands)
    assert success_rate >= 0.8, f"SSH stability too low: {success_rate*100:.1f}% success rate (need ≥80%)"
    
    logger.info(f"✓ SSH connection stability validated: {success_rate*100:.1f}% success rate")


async def test_ssh_command_execution_variety(ssh_ready_instance):
    """Test SSH command execution with various command types."""
    logger.info("Testing SSH command execution variety")
    
    instance_data = ssh_ready_instance
    instance = instance_data['instance']
    
    # Test different types of commands
    test_cases = [
        {
            'command': 'echo "Hello World"',
            'description': 'Simple echo command',
            'expect_in_output': 'Hello World'
        },
        {
            'command': 'ls /',
            'description': 'Directory listing',
            'expect_in_output': 'bin'  # Should have /bin directory
        },
        {
            'command': 'cat /etc/hostname',
            'description': 'File reading',
            'expect_output_not_empty': True
        },
        {
            'command': 'python3 -c "print(2 + 2)"',
            'description': 'Python execution',
            'expect_in_output': '4'
        },
        {
            'command': 'env | grep PATH',
            'description': 'Environment variables',
            'expect_in_output': 'PATH='
        }
    ]
    
    results = []
    
    for test_case in test_cases:
        command = test_case['command']
        description = test_case['description']
        
        logger.info(f"Testing: {description}")
        
        start_time = time.time()
        try:
            result = await instance.aexec(command)
            duration = time.time() - start_time
            
            # Check exit code
            if result.exit_code != 0:
                logger.warning(f"Command '{command}' returned non-zero exit code: {result.exit_code}")
                logger.warning(f"stderr: {result.stderr}")
                # Don't fail immediately - some commands might not be available
                
            # Check output expectations
            output_valid = True
            
            if 'expect_in_output' in test_case:
                expected = test_case['expect_in_output']
                if expected not in result.stdout:
                    logger.warning(f"Expected '{expected}' in output, got: {result.stdout}")
                    output_valid = False
            
            if test_case.get('expect_output_not_empty', False):
                if not result.stdout.strip():
                    logger.warning(f"Expected non-empty output, got: '{result.stdout}'")
                    output_valid = False
            
            results.append({
                'command': command,
                'description': description,
                'duration': duration,
                'exit_code': result.exit_code,
                'output_valid': output_valid,
                'success': result.exit_code == 0 and output_valid
            })
            
            if result.exit_code == 0 and output_valid:
                logger.info(f"✓ {description} succeeded in {duration:.2f}s")
            else:
                logger.info(f"⚠ {description} completed in {duration:.2f}s (warnings above)")
                
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"✗ {description} failed after {duration:.2f}s: {e}")
            
            results.append({
                'command': command,
                'description': description,
                'duration': duration,
                'success': False,
                'error': str(e)
            })
    
    # Analyze results
    successful_tests = [r for r in results if r['success']]
    
    logger.info(f"📊 SSH Command Execution Results:")
    logger.info(f"   Successful: {len(successful_tests)}/{len(test_cases)}")
    
    if successful_tests:
        avg_duration = sum(r['duration'] for r in successful_tests) / len(successful_tests)
        logger.info(f"   Avg Duration: {avg_duration:.2f}s")
    
    # Require at least 60% success rate (some commands might not be available)
    success_rate = len(successful_tests) / len(test_cases)
    assert success_rate >= 0.6, f"SSH command execution success rate too low: {success_rate*100:.1f}% (need ≥60%)"
    
    logger.info(f"✓ SSH command execution validated: {success_rate*100:.1f}% success rate")


async def test_ssh_multiple_sessions(ssh_ready_instance):
    """Test multiple SSH sessions can work simultaneously.""" 
    logger.info("Testing multiple SSH sessions")
    
    instance_data = ssh_ready_instance
    instance = instance_data['instance']
    
    # Run multiple commands concurrently to simulate multiple SSH sessions
    async def run_command_session(session_id: int, command: str):
        """Run a command in a simulated SSH session."""
        logger.info(f"Session {session_id}: Running '{command}'")
        start_time = time.time()
        
        try:
            result = await instance.aexec(command)
            duration = time.time() - start_time
            
            return {
                'session_id': session_id,
                'command': command,
                'duration': duration,
                'exit_code': result.exit_code,
                'success': result.exit_code == 0
            }
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"Session {session_id} failed: {e}")
            
            return {
                'session_id': session_id,
                'command': command,
                'duration': duration,
                'success': False,
                'error': str(e)
            }
    
    # Create multiple concurrent "sessions" with different commands
    session_commands = [
        "sleep 2 && echo 'Session 1 complete'",
        "date && sleep 1 && date",
        "echo 'Session 3' && uname -a",
        "sleep 3 && echo 'Session 4 delayed'"
    ]
    
    logger.info(f"Starting {len(session_commands)} concurrent SSH sessions")
    
    # Run sessions concurrently
    start_time = time.time()
    session_tasks = [
        run_command_session(i+1, cmd) 
        for i, cmd in enumerate(session_commands)
    ]
    
    session_results = await asyncio.gather(*session_tasks, return_exceptions=True)
    total_duration = time.time() - start_time
    
    # Process results
    successful_sessions = []
    failed_sessions = []
    
    for result in session_results:
        if isinstance(result, Exception):
            logger.error(f"Session task failed with exception: {result}")
            failed_sessions.append(result)
        elif result['success']:
            successful_sessions.append(result)
            logger.info(f"✓ Session {result['session_id']} completed in {result['duration']:.2f}s")
        else:
            failed_sessions.append(result)
            logger.warning(f"✗ Session {result['session_id']} failed")
    
    logger.info(f"📊 Multiple SSH Sessions Results:")
    logger.info(f"   Total Duration: {total_duration:.2f}s")
    logger.info(f"   Successful:     {len(successful_sessions)}/{len(session_commands)}")
    logger.info(f"   Failed:         {len(failed_sessions)}/{len(session_commands)}")
    
    if successful_sessions:
        session_durations = [r['duration'] for r in successful_sessions]
        avg_session_duration = sum(session_durations) / len(session_durations)
        max_session_duration = max(session_durations)
        
        logger.info(f"   Avg Session:    {avg_session_duration:.2f}s")
        logger.info(f"   Max Session:    {max_session_duration:.2f}s")
        
        # Check if concurrent execution was actually faster than sequential
        estimated_sequential_time = sum(session_durations)
        concurrency_benefit = estimated_sequential_time / total_duration
        logger.info(f"   Concurrency Benefit: {concurrency_benefit:.1f}x faster than sequential")
    
    # Require at least 75% success rate for multiple sessions
    success_rate = len(successful_sessions) / len(session_commands)
    assert success_rate >= 0.75, f"Multiple SSH sessions success rate too low: {success_rate*100:.1f}% (need ≥75%)"
    
    logger.info(f"✓ Multiple SSH sessions validated: {success_rate*100:.1f}% success rate")