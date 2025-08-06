"""
Function-scoped tests for command execution in MorphCloud SDK.
"""
import pytest
import logging
import uuid
import os
import asyncio
import pytest_asyncio

from morphcloud.api import MorphCloudClient

logger = logging.getLogger("morph-tests")

# Mark all tests as asyncio tests
pytestmark = pytest.mark.asyncio



@pytest_asyncio.fixture
async def test_instance(client, base_image):
    """Create a test instance for command execution tests."""
    logger.info("Creating test instance")
    
    # Create snapshot
    snapshot = await client.snapshots.acreate(
        image_id=base_image.id,
        vcpus=1,
        memory=512,
        disk_size=8192
    )
    logger.info(f"Created snapshot: {snapshot.id}")
    
    # Start instance
    instance = await client.instances.astart(snapshot.id)
    logger.info(f"Created instance: {instance.id}")
    
    # Wait for instance to be ready
    logger.info(f"Waiting for instance {instance.id} to be ready")
    await instance.await_until_ready(timeout=300)
    logger.info(f"Instance {instance.id} is ready")
    
    # Yield the instance for the test
    yield instance
    
    # Clean up resources
    logger.info(f"Stopping instance {instance.id}")
    await instance.astop()
    logger.info(f"Instance stopped")
    
    logger.info(f"Deleting snapshot {snapshot.id}")
    await snapshot.adelete()
    logger.info(f"Snapshot deleted")


async def test_basic_command_execution(test_instance):
    """Test basic command execution."""
    logger.info("Testing basic command execution")
    
    # Execute a simple command
    result = await test_instance.aexec("echo 'hello world'")
    
    # Verify command output
    assert result.exit_code == 0, "Command should execute successfully"
    assert "hello world" in result.stdout, "Command output should contain 'hello world'"
    assert not result.stderr, "Command should not produce stderr output"
    
    logger.info("Basic command execution test passed")


async def test_command_with_nonzero_exit_code(test_instance):
    """Test command that produces a non-zero exit code."""
    logger.info("Testing command with non-zero exit code")
    
    # Execute a command that should fail
    result = await test_instance.aexec("false")
    
    # Verify command output
    assert result.exit_code != 0, "Command should fail with non-zero exit code"
    
    logger.info("Command with non-zero exit code test passed")


async def test_command_with_stderr(test_instance):
    """Test command that produces stderr output."""
    logger.info("Testing command with stderr output")
    
    # Execute a command that should produce stderr output
    result = await test_instance.aexec("ls /nonexistent")
    
    # Verify command output
    assert result.exit_code != 0, "Command should fail with non-zero exit code"
    assert "No such file or directory" in result.stderr, "Command should produce stderr output about nonexistent file"
    
    logger.info("Command with stderr output test passed")


async def test_command_with_arguments(test_instance):
    """Test command with arguments."""
    logger.info("Testing command with arguments")
    
    # Generate a unique string
    test_string = uuid.uuid4().hex
    
    # Execute command with arguments
    result = await test_instance.aexec(f"echo 'test-{test_string}'")
    
    # Verify command output
    assert result.exit_code == 0, "Command should execute successfully"
    assert f"test-{test_string}" in result.stdout, "Command output should contain the unique test string"
    
    logger.info("Command with arguments test passed")


async def test_command_with_environment_variables(test_instance):
    """Test command with environment variables."""
    logger.info("Testing command with environment variables")
    
    # Define environment variables
    test_key = f"TEST_KEY_{uuid.uuid4().hex[:8]}"
    test_value = f"test_value_{uuid.uuid4().hex[:8]}"
    env = {test_key: test_value}
    
    # Execute command with environment variables (set via shell)
    result = await test_instance.aexec(f"export {test_key}={test_value} && echo ${test_key}")
    
    # Verify command output
    assert result.exit_code == 0, "Command should execute successfully"
    assert test_value in result.stdout, "Command output should contain the environment variable value"
    
    logger.info("Command with environment variables test passed")


async def test_command_with_working_directory(test_instance):
    """Test command with working directory."""
    logger.info("Testing command with working directory")
    
    # Create a test directory
    test_dir = f"/tmp/test_dir_{uuid.uuid4().hex[:8]}"
    mkdir_result = await test_instance.aexec(f"mkdir -p {test_dir}")
    assert mkdir_result.exit_code == 0, f"Failed to create test directory {test_dir}"
    
    # Create a test file in the test directory
    test_file = "test_file.txt"
    test_content = f"test_content_{uuid.uuid4().hex[:8]}"
    write_result = await test_instance.aexec(f"echo '{test_content}' > {test_dir}/{test_file}")
    assert write_result.exit_code == 0, f"Failed to create test file {test_dir}/{test_file}"
    
    # Execute command with working directory (use cd)
    result = await test_instance.aexec(f"cd {test_dir} && cat {test_file}")
    
    # Verify command output
    assert result.exit_code == 0, "Command should execute successfully"
    assert test_content in result.stdout, "Command output should contain the test file content"
    
    logger.info("Command with working directory test passed")


async def test_command_with_input(test_instance):
    """Test command with input data."""
    logger.info("Testing command with input data")
    
    # Define input data
    input_data = f"test_input_{uuid.uuid4().hex[:8]}"
    
    # Execute command with input data (use echo and pipe)
    result = await test_instance.aexec(f"echo '{input_data}' | cat")
    
    # Verify command output
    assert result.exit_code == 0, "Command should execute successfully"
    assert input_data in result.stdout, "Command output should contain the input data"
    
    logger.info("Command with input data test passed")


async def test_long_running_command(test_instance):
    """Test a long-running command."""
    logger.info("Testing long-running command")
    
    # Execute a long-running command (sleep for 10 seconds)
    start_time = asyncio.get_event_loop().time()
    result = await test_instance.aexec("sleep 10 && echo 'done'")
    end_time = asyncio.get_event_loop().time()
    
    # Verify command output
    assert result.exit_code == 0, "Command should execute successfully"
    assert "done" in result.stdout, "Command output should contain 'done'"
    
    # Verify command took at least 10 seconds
    elapsed_time = end_time - start_time
    assert elapsed_time >= 10, f"Command should take at least 10 seconds, but took {elapsed_time} seconds"
    
    logger.info("Long-running command test passed")


async def test_complex_command_pipeline(test_instance):
    """Test a complex command pipeline."""
    logger.info("Testing complex command pipeline")
    
    # Create a test file with multiple lines
    test_file = f"/tmp/test_file_{uuid.uuid4().hex[:8]}.txt"
    lines = ["apple", "banana", "cherry", "date", "elderberry", "fig", "grape"]
    content = "\n".join(lines)
    write_result = await test_instance.aexec(f"echo '{content}' > {test_file}")
    assert write_result.exit_code == 0, f"Failed to create test file {test_file}"
    
    # Execute a complex pipeline: grep for lines containing 'a', sort them, and take the first 2
    pipeline = f"grep 'a' {test_file} | sort | head -2"
    result = await test_instance.aexec(pipeline)
    
    # Verify command output
    assert result.exit_code == 0, "Command should execute successfully"
    assert "apple" in result.stdout, "Command output should contain 'apple'"
    assert "banana" in result.stdout, "Command output should contain 'banana'"
    assert "date" not in result.stdout, "Command output should not contain 'date'"
    
    logger.info("Complex command pipeline test passed")


async def test_command_with_sudo(test_instance):
    """Test command execution with sudo."""
    logger.info("Testing command execution with sudo")
    
    # Check if sudo is available and doesn't require password
    sudo_check = await test_instance.aexec("sudo -n true")
    if sudo_check.exit_code != 0:
        logger.warning("sudo is not available without password, skipping test")
        pytest.skip("sudo is not available without password")
    
    # Execute a command with sudo
    result = await test_instance.aexec("sudo whoami")
    
    # Verify command output
    assert result.exit_code == 0, "Command should execute successfully"
    assert "root" in result.stdout.lower(), "Command output should contain 'root'"
    
    logger.info("Command with sudo test passed")


async def test_streaming_stdout_callback(test_instance):
    """Test streaming execution with stdout callback."""
    logger.info("Testing streaming execution with stdout callback")
    
    # Collect stdout chunks
    stdout_chunks = []
    def capture_stdout(content):
        stdout_chunks.append(content)
        logger.info(f"Received stdout chunk: {content[:50]}...")
    
    # Execute command with streaming
    result = await test_instance.aexec(
        "echo 'line1'; echo 'line2'; echo 'line3'",
        on_stdout=capture_stdout
    )
    
    # Verify final response
    assert result.exit_code == 0, "Command should execute successfully"
    assert "line1" in result.stdout, "Final response should contain line1"
    assert "line2" in result.stdout, "Final response should contain line2" 
    assert "line3" in result.stdout, "Final response should contain line3"
    
    # Verify callbacks were called
    assert len(stdout_chunks) > 0, "Stdout callback should have been called"
    stdout_content = "".join(stdout_chunks)
    assert "line1" in stdout_content, "Stdout callbacks should contain line1"
    assert "line2" in stdout_content, "Stdout callbacks should contain line2"
    assert "line3" in stdout_content, "Stdout callbacks should contain line3"
    
    logger.info("Streaming stdout callback test passed")


async def test_streaming_stderr_callback(test_instance):
    """Test streaming execution with stderr callback."""
    logger.info("Testing streaming execution with stderr callback")
    
    # Collect stderr chunks
    stderr_chunks = []
    def capture_stderr(content):
        stderr_chunks.append(content)
        logger.info(f"Received stderr chunk: {content[:50]}...")
    
    # Execute command that produces stderr
    result = await test_instance.aexec(
        "echo 'error1' >&2; echo 'error2' >&2",
        on_stderr=capture_stderr
    )
    
    # Verify final response
    assert result.exit_code == 0, "Command should execute successfully"
    assert "error1" in result.stderr, "Final response should contain error1"
    assert "error2" in result.stderr, "Final response should contain error2"
    
    # Verify callbacks were called
    assert len(stderr_chunks) > 0, "Stderr callback should have been called"
    stderr_content = "".join(stderr_chunks)
    assert "error1" in stderr_content, "Stderr callbacks should contain error1"
    assert "error2" in stderr_content, "Stderr callbacks should contain error2"
    
    logger.info("Streaming stderr callback test passed")


async def test_streaming_both_callbacks(test_instance):
    """Test streaming execution with both stdout and stderr callbacks."""
    logger.info("Testing streaming execution with both callbacks")
    
    # Collect output chunks
    stdout_chunks = []
    stderr_chunks = []
    
    def capture_stdout(content):
        stdout_chunks.append(content)
        logger.info(f"Received stdout: {content[:50]}...")
    
    def capture_stderr(content):
        stderr_chunks.append(content)
        logger.info(f"Received stderr: {content[:50]}...")
    
    # Execute command that produces both stdout and stderr
    result = await test_instance.aexec(
        "echo 'stdout message'; echo 'stderr message' >&2; exit 0",
        on_stdout=capture_stdout,
        on_stderr=capture_stderr
    )
    
    # Verify final response
    assert result.exit_code == 0, "Command should execute successfully"
    assert "stdout message" in result.stdout, "Final response should contain stdout"
    assert "stderr message" in result.stderr, "Final response should contain stderr"
    
    # Verify stdout callback was called
    assert len(stdout_chunks) > 0, "Stdout callback should have been called"
    stdout_content = "".join(stdout_chunks)
    assert "stdout message" in stdout_content, "Stdout callbacks should contain message"
    
    # Verify stderr callback was called
    assert len(stderr_chunks) > 0, "Stderr callback should have been called"
    stderr_content = "".join(stderr_chunks)
    assert "stderr message" in stderr_content, "Stderr callbacks should contain message"
    
    logger.info("Streaming both callbacks test passed")


async def test_streaming_vs_traditional_consistency(test_instance):
    """Test that streaming and traditional endpoints return consistent results."""
    logger.info("Testing streaming vs traditional consistency")
    
    # Same command executed both ways
    command = "echo 'test output'; echo 'test error' >&2; exit 42"
    
    # Execute without callbacks (traditional endpoint)
    traditional_result = await test_instance.aexec(command)
    
    # Execute with callbacks (streaming endpoint)
    stdout_chunks = []
    stderr_chunks = []
    
    streaming_result = await test_instance.aexec(
        command,
        on_stdout=lambda content: stdout_chunks.append(content),
        on_stderr=lambda content: stderr_chunks.append(content)
    )
    
    # Results should be identical
    assert traditional_result.exit_code == streaming_result.exit_code, "Exit codes should match"
    assert traditional_result.stdout == streaming_result.stdout, "Stdout should match"
    assert traditional_result.stderr == streaming_result.stderr, "Stderr should match"
    
    # Streaming callbacks should contain the same content
    assert "test output" in "".join(stdout_chunks), "Streaming stdout should match"
    assert "test error" in "".join(stderr_chunks), "Streaming stderr should match"
    
    logger.info("Streaming vs traditional consistency test passed")


async def test_streaming_with_timeout(test_instance):
    """Test streaming execution with timeout."""
    logger.info("Testing streaming execution with timeout")
    
    stdout_chunks = []
    def capture_stdout(content):
        stdout_chunks.append(content)
    
    # Execute command with short timeout (should timeout)
    with pytest.raises(TimeoutError) as exc_info:
        await test_instance.aexec(
            "sleep 10",  # Simple sleep command - timeout expected 
            timeout=1.0,
            on_stdout=capture_stdout
        )
    
    # Verify it's the correct timeout error 
    assert "1.0 seconds" in str(exc_info.value), "Error message should contain timeout duration"
    logger.info("Streaming with timeout test passed")


async def test_traditional_with_timeout(test_instance):
    """Test traditional execution with timeout."""
    logger.info("Testing traditional execution with timeout")
    
    # Execute command with short timeout (should timeout)
    try:
        result = await test_instance.aexec("sleep 5", timeout=2.0)
        # If we get here, something went wrong
        assert False, "Command should have timed out"
    except Exception as e:
        # Timeout is expected
        logger.info(f"Command timed out as expected: {e}")
    
    logger.info("Traditional with timeout test passed")


async def test_sync_streaming_stdout_callback(test_instance):
    """Test synchronous streaming execution with stdout callback."""
    logger.info("Testing sync streaming execution with stdout callback")
    
    # Collect stdout chunks
    stdout_chunks = []
    def capture_stdout(content):
        stdout_chunks.append(content)
        logger.info(f"Received stdout chunk: {content[:50]}...")
    
    # Execute command with streaming (sync version)
    result = test_instance.exec(
        "echo 'sync line1'; echo 'sync line2'",
        on_stdout=capture_stdout
    )
    
    # Verify final response
    assert result.exit_code == 0, "Command should execute successfully"
    assert "sync line1" in result.stdout, "Final response should contain sync line1"
    assert "sync line2" in result.stdout, "Final response should contain sync line2"
    
    # Verify callbacks were called
    assert len(stdout_chunks) > 0, "Stdout callback should have been called"
    stdout_content = "".join(stdout_chunks)
    assert "sync line1" in stdout_content, "Stdout callbacks should contain sync line1"
    assert "sync line2" in stdout_content, "Stdout callbacks should contain sync line2"
    
    logger.info("Sync streaming stdout callback test passed")


async def test_timeout_error_type_streaming(test_instance):
    """Test that streaming timeout raises TimeoutError with proper message."""
    logger.info("Testing streaming timeout error type and message")
    
    stdout_chunks = []
    def capture_stdout(content):
        stdout_chunks.append(content)
    
    # Execute command with short timeout (should raise TimeoutError)
    with pytest.raises(TimeoutError) as exc_info:
        await test_instance.aexec(
            "echo 'start'; sleep 5; echo 'end'",
            timeout=1.0,
            on_stdout=capture_stdout
        )
    
    # Verify exception message contains timeout duration
    assert "1.0 seconds" in str(exc_info.value), "Exception message should contain timeout duration"
    logger.info("Streaming timeout error type test passed")


async def test_timeout_error_type_traditional(test_instance):
    """Test that traditional timeout raises TimeoutError with proper message."""
    logger.info("Testing traditional timeout error type and message")
    
    # Execute command with short timeout (should raise TimeoutError)
    with pytest.raises(TimeoutError) as exc_info:
        await test_instance.aexec("sleep 5", timeout=1.0)
    
    # Verify exception message contains timeout duration
    assert "1.0 seconds" in str(exc_info.value), "Exception message should contain timeout duration"
    logger.info("Traditional timeout error type test passed")



async def test_callback_exception_handling(test_instance):
    """Test that callback exceptions don't interrupt command execution."""
    logger.info("Testing callback exception handling")
    
    stdout_chunks = []
    callback_error_count = 0
    
    def failing_stdout_callback(content):
        nonlocal callback_error_count
        callback_error_count += 1
        stdout_chunks.append(content)
        if "line1" in content:
            raise ValueError("Intentional callback error")
    
    # Execute command with callback that raises exceptions
    result = await test_instance.aexec(
        "echo 'line1'; echo 'line2'; echo 'line3'",
        on_stdout=failing_stdout_callback
    )
    
    # Command should still complete successfully despite callback errors
    assert result.exit_code == 0, "Command should complete despite callback errors"
    assert "line1" in result.stdout, "Final response should contain line1"
    assert "line2" in result.stdout, "Final response should contain line2"
    assert "line3" in result.stdout, "Final response should contain line3"
    
    # Verify callback was called multiple times
    assert len(stdout_chunks) >= 2, "Callback should have been called multiple times"
    assert callback_error_count > 0, "Callback should have raised at least one error"
    
    logger.info("Callback exception handling test passed")


async def test_utf8_and_colored_output_streaming(test_instance):
    """Test streaming with UTF-8 characters and ANSI color codes."""
    logger.info("Testing UTF-8 and colored output streaming")
    
    stdout_chunks = []
    def capture_stdout(content):
        stdout_chunks.append(content)
        logger.info(f"Received chunk: {repr(content)}")
    
    # Command that produces UTF-8 characters and ANSI color codes
    result = await test_instance.aexec(
        "echo -e '\\033[31mRed Text\\033[0m'; echo 'UTF-8: ñáéíóú 中文 🚀'; echo -e '\\033[32mGreen Text\\033[0m'",
        on_stdout=capture_stdout
    )
    
    # Verify final response
    assert result.exit_code == 0, "Command should execute successfully"
    
    # Check UTF-8 characters are preserved
    assert "ñáéíóú" in result.stdout, "UTF-8 Spanish characters should be preserved"
    assert "中文" in result.stdout, "UTF-8 Chinese characters should be preserved"
    assert "🚀" in result.stdout, "UTF-8 emoji should be preserved"
    
    # Check ANSI color codes are preserved
    assert "\033[31m" in result.stdout, "ANSI red color code should be preserved"
    assert "\033[32m" in result.stdout, "ANSI green color code should be preserved" 
    assert "\033[0m" in result.stdout, "ANSI reset code should be preserved"
    assert "Red Text" in result.stdout, "Colored text content should be preserved"
    assert "Green Text" in result.stdout, "Colored text content should be preserved"
    
    # Verify streaming preserved encoding
    combined_chunks = "".join(stdout_chunks)
    assert combined_chunks == result.stdout, "Streamed chunks should match final result exactly"
    
    # Check that individual chunks contain valid UTF-8
    for chunk in stdout_chunks:
        assert isinstance(chunk, str), "All chunks should be strings"
        # Verify chunk can be encoded/decoded without errors
        chunk.encode('utf-8').decode('utf-8')
    
    logger.info("UTF-8 and colored output streaming test passed")


async def test_stderr_only_with_stdout_callback(test_instance):
    """Test command that produces only stderr with stdout callback provided."""
    logger.info("Testing stderr-only command with stdout callback")
    
    stdout_chunks = []
    stderr_chunks = []
    
    def capture_stdout(content):
        stdout_chunks.append(content)
    
    def capture_stderr(content):
        stderr_chunks.append(content)
    
    # Command that only produces stderr
    result = await test_instance.aexec(
        "echo 'error message' >&2",
        on_stdout=capture_stdout,
        on_stderr=capture_stderr
    )
    
    # Verify final response
    assert result.exit_code == 0, "Command should execute successfully"
    assert result.stdout == "", "Should have no stdout"
    assert "error message" in result.stderr, "Should have stderr content"
    
    # Verify callbacks
    assert len(stdout_chunks) == 0, "Stdout callback should not be called"
    assert len(stderr_chunks) > 0, "Stderr callback should be called"
    assert "error message" in "".join(stderr_chunks), "Stderr callback should receive message"
    
    logger.info("Stderr-only with stdout callback test passed")


async def test_none_callback_vs_not_provided(test_instance):
    """Test difference between on_stdout=None vs not providing parameter."""
    logger.info("Testing None callback vs not provided")
    
    # Test 1: No callback parameters (should use traditional endpoint)
    result1 = await test_instance.aexec("echo 'test1'")
    
    # Test 2: Explicit None callback (should still use traditional endpoint)
    result2 = await test_instance.aexec("echo 'test2'", on_stdout=None)
    
    # Test 3: Empty lambda callback (should use streaming endpoint)
    stdout_chunks = []
    result3 = await test_instance.aexec(
        "echo 'test3'", 
        on_stdout=lambda content: stdout_chunks.append(content)
    )
    
    # All should work and produce similar results
    assert result1.exit_code == 0, "Traditional exec should work"
    assert result2.exit_code == 0, "Explicit None callback should work"
    assert result3.exit_code == 0, "Lambda callback should work"
    
    assert "test1" in result1.stdout, "Result1 should contain test1"
    assert "test2" in result2.stdout, "Result2 should contain test2" 
    assert "test3" in result3.stdout, "Result3 should contain test3"
    
    # Verify streaming was used for test3
    assert len(stdout_chunks) > 0, "Lambda callback should have received chunks"
    assert "test3" in "".join(stdout_chunks), "Chunks should contain test3"
    
    logger.info("None callback vs not provided test passed")


