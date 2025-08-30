"""
Simple function-scoped tests for MorphCloud SDK.

This file doesn't rely on conftest.py and can be run directly.
"""
import pytest
import logging
import uuid
import os
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


async def test_snapshot_creation(client, base_image):
    """Test creating a snapshot."""
    logger.info("Testing snapshot creation")
    
    try:
        # Create snapshot
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=512,
            disk_size=8192  # Minimum allowed disk size
        )
        logger.info(f"Created snapshot: {snapshot.id}")
        
        # Verify snapshot properties
        assert snapshot.id.startswith("snapshot_"), "Snapshot ID should start with 'snapshot_'"
        assert hasattr(snapshot, "refs"), "Snapshot should have a refs attribute"
        assert hasattr(snapshot.refs, "image_id"), "Snapshot should have refs.image_id attribute"
        assert snapshot.refs.image_id == base_image.id, "Snapshot should be created from the specified base image"
        
    finally:
        # Clean up resources
        if 'snapshot' in locals():
            try:
                logger.info(f"Deleting snapshot {snapshot.id}")
                await snapshot.adelete()
                logger.info(f"Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")


async def test_instance_lifecycle(client, base_image):
    """Test instance creation, startup, and shutdown."""
    logger.info("Testing instance lifecycle")
    
    try:
        # Create snapshot
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=512,
            disk_size=8192
        )
        logger.info(f"Created snapshot: {snapshot.id}")
        
        # Start instance
        logger.info(f"Creating instance from snapshot {snapshot.id}")
        instance = await client.instances.astart(snapshot.id)
        logger.info(f"Created instance: {instance.id}")
        
        # Wait for instance to be ready
        logger.info(f"Waiting for instance {instance.id} to be ready")
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} is ready")
        
        # Verify instance properties
        assert instance.id.startswith("morphvm_"), "Instance ID should start with 'morphvm_'"
        assert hasattr(instance, "refs"), "Instance should have a refs attribute"
        assert hasattr(instance.refs, "snapshot_id"), "Instance should have refs.snapshot_id attribute"
        assert instance.refs.snapshot_id == snapshot.id, "Instance should be created from the specified snapshot"
        
        # Verify instance can be found in list
        instances = await client.instances.alist()
        assert any(i.id == instance.id for i in instances), "Instance should be in the list of instances"
        
        # Test stopping the instance
        logger.info(f"Stopping instance {instance.id}")
        await instance.astop()
        logger.info(f"Instance stopped")
        
    finally:
        # Clean up resources
        if 'instance' in locals():
            try:
                # Make sure instance is stopped
                logger.info(f"Ensuring instance {instance.id} is stopped")
                await instance.astop()
                logger.info(f"Instance stopped")
            except Exception as e:
                logger.error(f"Error stopping instance: {e}")
        
        if 'snapshot' in locals():
            try:
                logger.info(f"Deleting snapshot {snapshot.id}")
                await snapshot.adelete()
                logger.info(f"Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")
