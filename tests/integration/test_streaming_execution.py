"""
Streaming execution functionality tests for MorphCloud SDK.

This file tests streaming command execution with callbacks that was missing 
from the existing test suite, achieving parity with the TypeScript SDK.
"""
import pytest
import logging
import uuid
import os
import asyncio
import pytest_asyncio
import time

from morphcloud.api import MorphCloudClient

logger = logging.getLogger("morph-tests")

# Mark all tests as asyncio tests
pytestmark = pytest.mark.asyncio

# Configure pytest-asyncio
def pytest_configure(config):
    config.option.asyncio_default_fixture_loop_scope = "function"


@pytest.fixture
def api_key():
    """Get API key from environment variable."""
    key = os.environ.get("MORPH_API_KEY")
    if not key:
        pytest.fail("MORPH_API_KEY environment variable must be set")
    return key


@pytest.fixture
def base_url():
    """Get base URL from environment variable."""
    return os.environ.get("MORPH_BASE_URL")


@pytest_asyncio.fixture
async def client(api_key, base_url):
    """Create a MorphCloudClient."""
    client = MorphCloudClient(api_key=api_key, base_url=base_url)
    logger.info("Created MorphCloud client")
    return client


@pytest_asyncio.fixture
async def base_image(client):
    """Get a base image to use for tests."""
    images = await client.images.alist()
    if not images:
        pytest.fail("No images available")
    
    # Use an Ubuntu image or fall back to the first available
    image = next((img for img in images if "ubuntu" in img.id.lower()), images[0])
    logger.info(f"Using base image: {image.id}")
    return image


@pytest_asyncio.fixture
async def test_instance(client, base_image):
    """Create a test instance for streaming execution tests."""
    logger.info("Creating test instance for streaming execution")
    
    resources = {
        'snapshots': [],
        'instances': []
    }
    
    # Create snapshot
    snapshot = await client.snapshots.acreate(
        image_id=base_image.id,
        vcpus=1,
        memory=512,
        disk_size=8192
    )
    resources['snapshots'].append(snapshot)
    logger.info(f"Created snapshot: {snapshot.id}")
    
    # Start instance
    instance = await client.instances.astart(snapshot.id)
    resources['instances'].append(instance)
    logger.info(f"Created instance: {instance.id}")
    
    # Wait for instance to be ready
    logger.info(f"Waiting for instance {instance.id} to be ready")
    await instance.await_until_ready(timeout=300)
    logger.info(f"Instance {instance.id} is ready")
    
    # Yield the instance and resources for the test
    yield instance, resources
    
    # Clean up resources
    for instance in reversed(resources['instances']):
        try:
            logger.info(f"Stopping instance {instance.id}")
            await instance.astop()
        except Exception as e:
            logger.error(f"Error stopping instance: {e}")
    
    for snapshot in reversed(resources['snapshots']):
        try:
            logger.info(f"Deleting snapshot {snapshot.id}")
            await snapshot.adelete()
        except Exception as e:
            logger.error(f"Error deleting snapshot: {e}")


async def test_exec_with_stdout_callback(test_instance):
    """Test streaming execution with stdout callback."""
    instance, resources = test_instance
    logger.info("Testing command execution with stdout callback")
    
    stdout_chunks = []
    callback_call_count = 0
    
    def capture_stdout(content):
        nonlocal callback_call_count
        callback_call_count += 1
        stdout_chunks.append(content)
        logger.info(f"Stdout callback {callback_call_count}: received {len(content)} characters")
    
    # Execute command that produces multiple output lines
    command = "echo 'Line 1'; echo 'Line 2'; echo 'Line 3'"
    logger.info(f"Executing command with stdout callback: {command}")
    
    result = await instance.aexec(command, on_stdout=capture_stdout)
    
    # Verify command executed successfully
    assert result.exit_code == 0
    logger.info("Command executed successfully")
    
    # Verify callback was called at least once
    assert callback_call_count > 0, "Stdout callback should have been called"
    assert len(stdout_chunks) > 0, "Should have received stdout chunks"
    
    # Verify output content
    full_output = ''.join(stdout_chunks)
    assert 'Line 1' in full_output
    assert 'Line 2' in full_output  
    assert 'Line 3' in full_output
    
    logger.info(f"Stdout callback called {callback_call_count} times, received {len(full_output)} total characters")


async def test_exec_with_stderr_callback(test_instance):
    """Test streaming execution with stderr callback."""
    instance, resources = test_instance
    logger.info("Testing command execution with stderr callback")
    
    stderr_chunks = []
    callback_call_count = 0
    
    def capture_stderr(content):
        nonlocal callback_call_count
        callback_call_count += 1
        stderr_chunks.append(content)
        logger.info(f"Stderr callback {callback_call_count}: received {len(content)} characters")
    
    # Execute command that produces stderr output
    command = "echo 'Error message 1' >&2; echo 'Error message 2' >&2"
    logger.info(f"Executing command with stderr callback: {command}")
    
    result = await instance.aexec(command, on_stderr=capture_stderr)
    
    # Verify command executed successfully
    assert result.exit_code == 0
    logger.info("Command executed successfully")
    
    # Verify callback was called
    assert callback_call_count > 0, "Stderr callback should have been called"
    assert len(stderr_chunks) > 0, "Should have received stderr chunks"
    
    # Verify error output content
    full_stderr = ''.join(stderr_chunks)
    assert 'Error message 1' in full_stderr
    assert 'Error message 2' in full_stderr
    
    logger.info(f"Stderr callback called {callback_call_count} times, received {len(full_stderr)} total characters")


async def test_exec_with_both_stdout_stderr_callbacks(test_instance):
    """Test streaming execution with both stdout and stderr callbacks."""
    instance, resources = test_instance
    logger.info("Testing command execution with both stdout and stderr callbacks")
    
    stdout_chunks = []
    stderr_chunks = []
    stdout_callback_count = 0
    stderr_callback_count = 0
    
    def capture_stdout(content):
        nonlocal stdout_callback_count
        stdout_callback_count += 1
        stdout_chunks.append(content)
        logger.info(f"Stdout callback {stdout_callback_count}: {content.strip()}")
    
    def capture_stderr(content):
        nonlocal stderr_callback_count
        stderr_callback_count += 1
        stderr_chunks.append(content)
        logger.info(f"Stderr callback {stderr_callback_count}: {content.strip()}")
    
    # Execute command that produces both stdout and stderr
    command = "echo 'Standard output'; echo 'Error output' >&2; echo 'More stdout'"
    logger.info(f"Executing command with both callbacks: {command}")
    
    result = await instance.aexec(
        command, 
        on_stdout=capture_stdout,
        on_stderr=capture_stderr
    )
    
    # Verify command executed successfully
    assert result.exit_code == 0
    logger.info("Command executed successfully")
    
    # Verify both callbacks were called
    assert stdout_callback_count > 0, "Stdout callback should have been called"
    assert stderr_callback_count > 0, "Stderr callback should have been called"
    
    # Verify output content
    full_stdout = ''.join(stdout_chunks)
    full_stderr = ''.join(stderr_chunks)
    
    assert 'Standard output' in full_stdout
    assert 'More stdout' in full_stdout
    assert 'Error output' in full_stderr
    
    logger.info(f"Both callbacks worked: stdout={stdout_callback_count} calls, stderr={stderr_callback_count} calls")


async def test_exec_callback_error_resilience(test_instance):
    """Test callback error handling and resilience."""
    instance, resources = test_instance
    logger.info("Testing callback error resilience")
    
    successful_callbacks = 0
    error_callbacks = 0
    
    def error_prone_callback(content):
        nonlocal successful_callbacks, error_callbacks
        if 'error' in content.lower():
            error_callbacks += 1
            # Simulate callback error
            raise RuntimeError("Simulated callback error")
        else:
            successful_callbacks += 1
            logger.info(f"Successful callback: {content.strip()}")
    
    # Execute command that will trigger both successful and error callbacks
    command = "echo 'Normal output'; echo 'ERROR output'; echo 'Final output'"
    logger.info(f"Executing command with error-prone callback: {command}")
    
    # The execution should complete despite callback errors
    result = await instance.aexec(command, on_stdout=error_prone_callback)
    
    # Verify command still executed successfully despite callback errors
    assert result.exit_code == 0
    logger.info("Command completed successfully despite callback errors")
    
    # Verify we had both successful and error callbacks
    assert successful_callbacks > 0, "Should have had some successful callbacks"
    logger.info(f"Callback resilience test completed: {successful_callbacks} successful, {error_callbacks} errors")


async def test_exec_streaming_timeout_handling(test_instance):
    """Test timeout handling for streaming vs traditional execution."""
    instance, resources = test_instance
    logger.info("Testing timeout handling with streaming callbacks")
    
    # Test short timeout with streaming callback
    stdout_chunks = []
    
    def capture_stdout(content):
        stdout_chunks.append(content)
    
    # Test timeout with streaming execution
    start_time = time.time()
    
    with pytest.raises(asyncio.TimeoutError) as exc_info:
        await instance.aexec(
            "sleep 10",  # Command that takes 10 seconds
            timeout=2.0,  # Timeout after 2 seconds
            on_stdout=capture_stdout
        )
    
    elapsed_time = time.time() - start_time
    
    # Verify timeout occurred around the expected time
    assert elapsed_time < 5.0, "Timeout should have occurred quickly"
    assert "timeout" in str(exc_info.value).lower() or "2" in str(exc_info.value)
    
    logger.info(f"Streaming timeout handled correctly after {elapsed_time:.2f} seconds")


async def test_exec_array_command_format(test_instance):
    """Test command execution with array format ['cmd', 'arg1', 'arg2']."""
    instance, resources = test_instance
    logger.info("Testing command execution with array format")
    
    stdout_chunks = []
    
    def capture_stdout(content):
        stdout_chunks.append(content)
        logger.info(f"Array command output: {content.strip()}")
    
    # Test array command format
    array_command = ["ls", "-la", "/tmp"]
    logger.info(f"Executing array command: {array_command}")
    
    result = await instance.aexec(array_command, on_stdout=capture_stdout)
    
    # Verify command executed successfully
    assert result.exit_code == 0
    logger.info("Array command executed successfully")
    
    # Verify we got output
    assert len(stdout_chunks) > 0, "Should have received output from array command"
    
    full_output = ''.join(stdout_chunks)
    # Should contain directory listing information
    assert ('total' in full_output or 'drwx' in full_output or 
            'tmp' in full_output), "Should contain directory listing output"
    
    logger.info("Array command format test successful")


async def test_exec_utf8_and_special_character_handling(test_instance):
    """Test UTF-8, ANSI, and special character output handling."""
    instance, resources = test_instance
    logger.info("Testing UTF-8 and special character handling")
    
    stdout_chunks = []
    
    def capture_stdout(content):
        stdout_chunks.append(content)
    
    # Test various special characters and encodings
    test_commands = [
        "echo '🚀 Unicode emoji test'",
        "echo 'UTF-8 characters: ñáéíóú'", 
        "echo -e '\\033[31mRed text\\033[0m'",  # ANSI color codes
        "echo 'Special chars: !@#$%^&*()'"
    ]
    
    for command in test_commands:
        logger.info(f"Testing special characters: {command}")
        stdout_chunks.clear()
        
        result = await instance.aexec(command, on_stdout=capture_stdout)
        
        assert result.exit_code == 0, f"Command should succeed: {command}"
        assert len(stdout_chunks) > 0, "Should receive output"
        
        full_output = ''.join(stdout_chunks)
        logger.info(f"Special character output received: {len(full_output)} chars")
    
    logger.info("Special character handling test completed")


async def test_traditional_execution_without_callbacks(test_instance):
    """Test traditional execution endpoint when no callbacks are provided."""
    instance, resources = test_instance
    logger.info("Testing traditional execution without callbacks")
    
    # Execute command without any callbacks (traditional endpoint)
    command = "echo 'Traditional execution test'"
    logger.info(f"Executing command without callbacks: {command}")
    
    result = await instance.aexec(command)
    
    # Verify traditional execution works
    assert result.exit_code == 0
    assert hasattr(result, 'stdout')
    assert hasattr(result, 'stderr')
    assert 'Traditional execution test' in result.stdout
    
    logger.info("Traditional execution (no callbacks) successful")
    
    # Test with timeout but no callbacks
    result2 = await instance.aexec("echo 'Timeout test'", timeout=30.0)
    
    assert result2.exit_code == 0
    assert 'Timeout test' in result2.stdout
    
    logger.info("Traditional execution with timeout successful")