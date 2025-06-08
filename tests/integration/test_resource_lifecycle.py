"""
Tests for basic resource lifecycle operations with proper cleanup.
"""
import os
import pytest
import logging
import asyncio
from functools import wraps

import pytest_asyncio
from morphcloud.api import MorphCloudClient

logger = logging.getLogger("morph-tests")

# Resource tracking for session-level cleanup
_CREATED_INSTANCES = []
_CREATED_SNAPSHOTS = []

def register_instance(instance):
    """Register an instance for cleanup."""
    _CREATED_INSTANCES.append(instance)
    return instance

def register_snapshot(snapshot):
    """Register a snapshot for cleanup."""
    _CREATED_SNAPSHOTS.append(snapshot)
    return snapshot

# Event loop management
@pytest.fixture(scope="session")
def event_loop():
    """Create a single event loop for the entire test session."""
    # Create a new loop
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    asyncio.set_event_loop(loop)
    
    # Yield the loop for tests to use
    yield loop
    
    # Close the loop after all tests complete
    loop.close()

@pytest_asyncio.fixture(scope="session")
async def morph_client(event_loop):
    """Create and configure a MorphCloud client."""
    # Use environment variables or defaults
    api_key = os.environ.get("MORPH_API_KEY")
    base_url = os.environ.get("MORPH_BASE_URL")
    
    if not api_key:
        pytest.fail("MORPH_API_KEY environment variable must be set")
    
    client = MorphCloudClient(
        api_key=api_key,
        base_url=base_url
    )
    
    logger.info("Created MorphCloud client")
    return client

@pytest_asyncio.fixture(scope="session")
async def base_image(morph_client):
    """Get a base image to use for tests."""
    images = await morph_client.images.alist()
    if not images:
        pytest.fail("No base images available")
    
    # Usually use an Ubuntu image or fall back to the first available
    image = next((img for img in images if "ubuntu" in img.id.lower()), images[0])
    logger.info(f"Using base image: {image.id}")
    return image.id

@pytest.fixture(scope="session", autouse=True)
def cleanup_resources(event_loop):
    """Automatically clean up resources after all tests."""
    # Setup - nothing to do
    yield
    
    # Cleanup
    logger.info("Running session cleanup")
    
    async def cleanup():
        # Clean up instances first
        for instance in reversed(_CREATED_INSTANCES):
            try:
                logger.info(f"Stopping instance {instance.id}")
                await instance.astop()
                logger.info(f"Instance {instance.id} stopped")
            except Exception as e:
                logger.error(f"Error stopping instance {instance.id}: {e}")
        
        # Then clean up snapshots
        for snapshot in reversed(_CREATED_SNAPSHOTS):
            try:
                logger.info(f"Deleting snapshot {snapshot.id}")
                await snapshot.adelete()
                logger.info(f"Snapshot {snapshot.id} deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot {snapshot.id}: {e}")
    
    # Run the cleanup in the event loop
    if _CREATED_INSTANCES or _CREATED_SNAPSHOTS:
        event_loop.run_until_complete(cleanup())
    logger.info("Cleanup complete")

@pytest.mark.asyncio
async def test_create_snapshot(morph_client, base_image):
    """Test creating a snapshot from a base image."""
    logger.info("Creating test snapshot")
    
    # Create snapshot
    snapshot = await morph_client.snapshots.acreate(
        image_id=base_image,
        vcpus=1,
        memory=512,
        disk_size=8192  # Minimum allowed disk size
    )
    
    # Register for cleanup
    register_snapshot(snapshot)
    
    logger.info(f"Created test snapshot: {snapshot.id}")
    
    # Verify snapshot properties
    assert snapshot.id.startswith("snapshot_"), "Snapshot ID should start with 'snapshot_'"
    assert hasattr(snapshot, "image_id"), "Snapshot should have an image_id attribute"
    assert snapshot.image_id == base_image, "Snapshot should be created from the specified base image"

@pytest.mark.asyncio
async def test_instance_lifecycle(morph_client, base_image):
    """Test full instance lifecycle."""
    # Create snapshot
    logger.info("Creating test snapshot")
    snapshot = await morph_client.snapshots.acreate(
        image_id=base_image,
        vcpus=1,
        memory=512,
        disk_size=8192
    )
    register_snapshot(snapshot)
    logger.info(f"Created test snapshot: {snapshot.id}")
    
    # Start instance
    logger.info(f"Starting instance from snapshot {snapshot.id}")
    instance = await morph_client.instances.astart(snapshot.id)
    register_instance(instance)
    logger.info(f"Created instance: {instance.id}")
    
    # Wait for instance to be ready
    logger.info(f"Waiting for instance {instance.id} to be ready")
    await instance.await_until_ready(timeout=300)
    logger.info(f"Instance {instance.id} is ready")
    
    # Execute command
    logger.info(f"Executing command on instance {instance.id}")
    result = await instance.aexec("echo 'hello world'")
    logger.info(f"Command result: exit_code={result.exit_code}, stdout={result.stdout}")
    
    # Verify command output
    assert result.exit_code == 0, "Command should execute successfully"
    assert "hello world" in result.stdout, "Command output should contain 'hello world'"
    
    # NOTE: We rely on the session-level cleanup fixture to clean up resources
    # This approach keeps tests simple while ensuring cleanup happens even if tests fail