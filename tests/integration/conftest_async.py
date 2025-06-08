"""
Pytest configuration and fixtures for async integration tests.
Resolves common event loop issues.
"""
import os
import pytest
import logging
import asyncio

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

# This is the most critical fix for event loop issues
@pytest.fixture(scope="session")
def event_loop():
    """Create a single event loop for the entire test session."""
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()

@pytest.fixture(scope="session")
async def morph_client():
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
    yield client

@pytest.fixture(scope="session")
async def base_image(morph_client):
    """Get a base image to use for tests."""
    images = await morph_client.images.alist()
    if not images:
        pytest.fail("No base images available")
    
    # Usually use an Ubuntu image or fall back to the first available
    image = next((img for img in images if "ubuntu" in img.id.lower()), images[0])
    logger.info(f"Using base image: {image.id}")
    yield image.id

@pytest.fixture(autouse=True, scope="session")
async def cleanup_resources():
    """
    Clean up all resources created during tests.
    This fixture runs after all tests in the session.
    """
    # Setup (before tests)
    yield
    
    # Teardown (after tests)
    logger.info("Running cleanup")
    
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