"""
Function-scoped tests for SSH key rotation in MorphCloud SDK.
"""
import pytest
import logging
import os
import time
import requests
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
    """Create a test instance for SSH key rotation tests."""
    logger.info("Creating test instance for SSH key rotation")
    
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
    try:
        logger.info(f"Stopping instance {instance.id}")
        await instance.astop()
        logger.info(f"Instance stopped")
    except Exception as e:
        logger.error(f"Error stopping instance: {e}")
    
    try:
        logger.info(f"Deleting snapshot {snapshot.id}")
        await snapshot.adelete()
        logger.info(f"Snapshot deleted")
    except Exception as e:
        logger.error(f"Error deleting snapshot: {e}")


async def test_ssh_key_get(test_instance):
    """Test retrieving SSH key details."""
    logger.info("Testing SSH key retrieval")
    
    # Test sync method
    ssh_key = test_instance.ssh_key()
    
    # Verify SSH key properties
    assert ssh_key.object == "instance_ssh_key", "SSH key object type should be 'instance_ssh_key'"
    assert hasattr(ssh_key, "private_key"), "SSH key should have a private_key attribute"
    assert hasattr(ssh_key, "public_key"), "SSH key should have a public_key attribute"
    assert hasattr(ssh_key, "password"), "SSH key should have a password attribute"
    assert ssh_key.private_key, "Private key should not be empty"
    assert ssh_key.public_key, "Public key should not be empty"
    assert ssh_key.password, "Password should not be empty"
    
    logger.info("SSH key retrieval test passed")


async def test_ssh_key_get_async(test_instance):
    """Test asynchronous SSH key retrieval."""
    logger.info("Testing asynchronous SSH key retrieval")
    
    # Test async method
    ssh_key = await test_instance.assh_key()
    
    # Verify SSH key properties
    assert ssh_key.object == "instance_ssh_key", "SSH key object type should be 'instance_ssh_key'"
    assert hasattr(ssh_key, "private_key"), "SSH key should have a private_key attribute"
    assert hasattr(ssh_key, "public_key"), "SSH key should have a public_key attribute"
    assert hasattr(ssh_key, "password"), "SSH key should have a password attribute"
    assert ssh_key.private_key, "Private key should not be empty"
    assert ssh_key.public_key, "Public key should not be empty"
    assert ssh_key.password, "Password should not be empty"
    
    logger.info("Asynchronous SSH key retrieval test passed")


async def test_ssh_key_rotation_sync(test_instance):
    """Test synchronous SSH key rotation."""
    logger.info("Testing synchronous SSH key rotation")
    
    # Get current SSH key
    current_key = test_instance.ssh_key()
    logger.info(f"Current public key: {current_key.public_key[:50]}...")
    
    # Rotate SSH key
    new_key = test_instance.ssh_key_rotate()
    logger.info(f"New public key: {new_key.public_key[:50]}...")
    
    # Verify new key properties
    assert new_key.object == "instance_ssh_key", "New SSH key object type should be 'instance_ssh_key'"
    assert new_key.private_key, "New private key should not be empty"
    assert new_key.public_key, "New public key should not be empty"
    assert new_key.password, "New password should not be empty"
    
    # Verify keys are different
    assert new_key.public_key != current_key.public_key, "New public key should be different from current key"
    assert new_key.private_key != current_key.private_key, "New private key should be different from current key"
    
    logger.info("Synchronous SSH key rotation test passed")


async def test_ssh_key_rotation_async(test_instance):
    """Test asynchronous SSH key rotation."""
    logger.info("Testing asynchronous SSH key rotation")
    
    # Get current SSH key
    current_key = await test_instance.assh_key()
    logger.info(f"Current public key: {current_key.public_key[:50]}...")
    
    # Rotate SSH key
    new_key = await test_instance.assh_key_rotate()
    logger.info(f"New public key: {new_key.public_key[:50]}...")
    
    # Verify new key properties
    assert new_key.object == "instance_ssh_key", "New SSH key object type should be 'instance_ssh_key'"
    assert new_key.private_key, "New private key should not be empty"
    assert new_key.public_key, "New public key should not be empty"
    assert new_key.password, "New password should not be empty"
    
    # Verify keys are different
    assert new_key.public_key != current_key.public_key, "New public key should be different from current key"
    assert new_key.private_key != current_key.private_key, "New private key should be different from current key"
    
    logger.info("Asynchronous SSH key rotation test passed")


async def test_ssh_connection_works(test_instance):
    """Test that SSH connection works before and after key rotation."""
    logger.info("Testing SSH connection before and after key rotation")
    
    # Test SSH connection before rotation
    logger.info("Testing SSH connection before rotation")
    ssh_client = test_instance.ssh()
    try:
        result = ssh_client.run("echo 'pre-rotation test'", timeout=10)
        assert result.returncode == 0, "SSH connection should work before rotation"
        assert "pre-rotation test" in result.stdout, "SSH command should execute successfully"
        logger.info("SSH connection successful before rotation")
    finally:
        ssh_client.close()
    
    # Rotate SSH key
    logger.info("Rotating SSH key")
    new_key = test_instance.ssh_key_rotate()
    logger.info(f"SSH key rotated, new public key: {new_key.public_key[:50]}...")
    
    # Brief pause to ensure key rotation is propagated
    time.sleep(2)
    
    # Test SSH connection after rotation
    logger.info("Testing SSH connection after rotation")
    ssh_client = test_instance.ssh()
    try:
        result = ssh_client.run("echo 'post-rotation test'", timeout=10)
        assert result.returncode == 0, "SSH connection should work after rotation"
        assert "post-rotation test" in result.stdout, "SSH command should execute successfully after rotation"
        logger.info("SSH connection successful after rotation")
    finally:
        ssh_client.close()
    
    logger.info("SSH connection test passed")


async def test_key_uniqueness(test_instance):
    """Test that multiple SSH key rotations produce unique keys."""
    logger.info("Testing SSH key uniqueness across multiple rotations")
    
    # Collect multiple keys
    keys = []
    for i in range(3):
        logger.info(f"Rotation {i+1}: Rotating SSH key")
        rotated_key = test_instance.ssh_key_rotate()
        keys.append(rotated_key.public_key)
        logger.info(f"Rotation {i+1}: New public key: {rotated_key.public_key[:50]}...")
    
    # Verify all keys are unique
    unique_keys = set(keys)
    assert len(unique_keys) == len(keys), f"All {len(keys)} keys should be unique, but found {len(unique_keys)} unique keys"
    
    logger.info("SSH key uniqueness test passed")


async def test_raw_api_endpoint(test_instance, api_key, base_url):
    """Test the raw HTTP API endpoint for SSH key rotation."""
    logger.info("Testing raw HTTP API endpoint for SSH key rotation")
    
    # Set up for raw HTTP request
    if not base_url:
        base_url = "https://cloud.morph.so/api"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    # Get current SSH key via raw API
    logger.info("Getting current SSH key via raw API")
    get_response = requests.get(f"{base_url}/instance/{test_instance.id}/ssh/key", headers=headers)
    assert get_response.status_code == 200, f"GET request should succeed, got {get_response.status_code}"
    
    current_key_data = get_response.json()
    assert current_key_data["object"] == "instance_ssh_key", "Response should be an instance_ssh_key object"
    logger.info(f"Current key retrieved: {current_key_data['public_key'][:50]}...")
    
    # Rotate SSH key via raw API
    logger.info("Rotating SSH key via raw API")
    post_response = requests.post(f"{base_url}/instance/{test_instance.id}/ssh/key", headers=headers)
    assert post_response.status_code == 200, f"POST request should succeed, got {post_response.status_code}"
    
    new_key_data = post_response.json()
    assert new_key_data["object"] == "instance_ssh_key", "Response should be an instance_ssh_key object"
    logger.info(f"New key retrieved: {new_key_data['public_key'][:50]}...")
    
    # Verify keys are different
    assert new_key_data["public_key"] != current_key_data["public_key"], "New public key should be different from current key"
    assert new_key_data["private_key"] != current_key_data["private_key"], "New private key should be different from current key"
    
    logger.info("Raw HTTP API endpoint test passed")


async def test_mixed_sync_async_operations(test_instance):
    """Test mixing synchronous and asynchronous SSH key operations."""
    logger.info("Testing mixed sync/async SSH key operations")
    
    # Get key with sync method
    sync_key = test_instance.ssh_key()
    logger.info(f"Sync key: {sync_key.public_key[:50]}...")
    
    # Rotate with async method
    async_rotated_key = await test_instance.assh_key_rotate()
    logger.info(f"Async rotated key: {async_rotated_key.public_key[:50]}...")
    
    # Get key with async method
    async_key = await test_instance.assh_key()
    logger.info(f"Async key: {async_key.public_key[:50]}...")
    
    # Rotate with sync method
    sync_rotated_key = test_instance.ssh_key_rotate()
    logger.info(f"Sync rotated key: {sync_rotated_key.public_key[:50]}...")
    
    # Verify all keys are different
    all_keys = [
        sync_key.public_key,
        async_rotated_key.public_key,
        async_key.public_key,
        sync_rotated_key.public_key
    ]
    
    # The middle two should be the same (async_rotated_key and async_key)
    assert async_rotated_key.public_key == async_key.public_key, "Async rotated key and async retrieved key should be the same"
    
    # All others should be different
    unique_keys = {sync_key.public_key, async_rotated_key.public_key, sync_rotated_key.public_key}
    assert len(unique_keys) == 3, "Should have 3 unique keys from the different operations"
    
    logger.info("Mixed sync/async operations test passed")