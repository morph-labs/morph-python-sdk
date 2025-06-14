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
