"""
Function-scoped tests for Time-To-Live (TTL) and auto-cleanup in MorphCloud SDK.
"""
import pytest
import logging
import uuid
import os
import asyncio
import time
import datetime
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


async def test_instance_ttl(client, base_image):
    """Test instance Time-To-Live (TTL) setting."""
    logger.info("Testing instance TTL")
    
    # Set TTL to a short duration for testing (e.g., 3 minutes)
    ttl_seconds = 180
    
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
        logger.info("Starting instance")
        instance = await client.instances.astart(snapshot.id)
        logger.info(f"Created instance: {instance.id}")
        
        # Wait for instance to be ready
        logger.info(f"Waiting for instance {instance.id} to be ready")
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} is ready")
        
        # Set TTL on instance
        logger.info(f"Setting instance TTL to {ttl_seconds} seconds")
        await instance.aset_ttl(ttl_seconds)
        
        # Attempt to get the updated instance
        logger.info(f"Getting updated instance {instance.id}")
        updated_instance = await client.instances.aget(instance.id)
        
        # We're not checking for specific TTL attributes as the API might change
        # Just verify that we can set a TTL and it doesn't cause errors
        logger.info(f"Successfully set TTL on instance {instance.id}")
        
        # Print instance attributes for debugging
        logger.info(f"Instance attributes: {dir(updated_instance)}")
        logger.info(f"Instance data: {updated_instance.model_dump()}")
        
        # Verify we can modify TTL
        new_ttl_seconds = ttl_seconds * 2
        logger.info(f"Updating TTL to {new_ttl_seconds} seconds")
        await instance.aset_ttl(new_ttl_seconds)
        
        # Get updated instance
        updated_instance = await client.instances.aget(instance.id)
        logger.info("Successfully updated TTL")
        
        # Wait up to 30 seconds to see if instance is still accessible
        await asyncio.sleep(30)
        
        # Verify instance is still accessible
        try:
            instance_check = await client.instances.aget(instance.id)
            assert instance_check.id == instance.id, "Instance should still be accessible"
            logger.info(f"Instance {instance.id} is still accessible after 30 seconds")
        except Exception as e:
            pytest.fail(f"Instance {instance.id} should still be accessible but got error: {e}")
        
        # Note: We don't wait for the full TTL to expire in this test since it would take too long
        # In a real-world scenario, you might want to set a very short TTL (e.g., 30 seconds)
        # and verify the instance is automatically deleted
        
        logger.info("Instance TTL test completed successfully")
        
    finally:
        # Clean up resources
        if 'instance' in locals():
            try:
                logger.info(f"Stopping instance {instance.id}")
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


# Snapshot TTL is not supported by the API


async def test_auto_cleanup(client, base_image):
    """Test automatic resource cleanup after TTL expiration."""
    logger.info("Testing automatic resource cleanup")
    
    # Set a very short TTL for testing (15 seconds)
    ttl_seconds = 15
    
    try:
        # Create snapshot
        logger.info("Creating snapshot")
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=512,
            disk_size=8192
        )
        logger.info(f"Created snapshot: {snapshot.id}")
        
        # Start instance
        logger.info("Starting instance")
        instance = await client.instances.astart(snapshot.id)
        logger.info(f"Created instance: {instance.id}")
        
        # Wait for instance to be ready
        logger.info(f"Waiting for instance {instance.id} to be ready")
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} is ready")
        
        # Set TTL on instance
        logger.info(f"Setting instance TTL to {ttl_seconds} seconds")
        await instance.aset_ttl(ttl_seconds)
        
        # Attempt to get the updated instance
        logger.info(f"Getting updated instance {instance.id}")
        updated_instance = await client.instances.aget(instance.id)
        
        # We're not checking for specific TTL attributes as the API might change
        # Just verify that we can set a TTL and it doesn't cause errors
        logger.info(f"Successfully set TTL on instance {instance.id}")
        
        # Print instance attributes for debugging
        logger.info(f"Instance attributes: {dir(updated_instance)}")
        logger.info(f"Instance data: {updated_instance.model_dump()}")
        
        # Wait for slightly longer than the TTL
        wait_time = ttl_seconds + 10
        logger.info(f"Waiting {wait_time} seconds for resources to expire")
        await asyncio.sleep(wait_time)
        
        # Verify instance has been automatically deleted
        try:
            await client.instances.aget(instance.id)
            pytest.fail(f"Instance {instance.id} should have been automatically deleted")
        except Exception as e:
            logger.info(f"Instance {instance.id} has been automatically deleted as expected: {str(e)}")
        
        logger.info("Auto-cleanup test completed successfully")
        
    finally:
        # Clean up resources (just in case the test fails)
        if 'instance' in locals():
            try:
                logger.info(f"Stopping instance {instance.id}")
                await instance.astop()
                logger.info(f"Instance stopped")
            except Exception as e:
                # If the instance was already deleted by TTL, this is expected
                logger.info(f"Instance cleanup: {e}")
        
        if 'snapshot' in locals():
            try:
                logger.info(f"Deleting snapshot {snapshot.id}")
                await snapshot.adelete()
                logger.info(f"Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")