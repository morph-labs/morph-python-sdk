"""
Pytest configuration with all fixtures at session scope.
This approach uses a single event loop for the entire test session.
"""
import os
import pytest
import logging
import asyncio
import uuid

import pytest_asyncio
from morphcloud.api import MorphCloudClient

logger = logging.getLogger("morph-tests")

# Resource tracking
_RESOURCES = {
    "instances": [],
    "snapshots": []
}

def register_instance(instance):
    """Register an instance for cleanup."""
    _RESOURCES["instances"].append(instance)
    return instance

def register_snapshot(snapshot):
    """Register a snapshot for cleanup."""
    _RESOURCES["snapshots"].append(snapshot)
    return snapshot

# Session-scoped event loop
@pytest.fixture(scope="session")
def event_loop():
    """Create a single event loop for the entire test session."""
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    
    # Clean up pending tasks before closing the loop
    try:
        pending = asyncio.all_tasks(loop)
        if pending:
            logger.info(f"Cancelling {len(pending)} pending tasks")
            for task in pending:
                task.cancel()
            
            # Wait for tasks to be cancelled
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
    except Exception as e:
        logger.error(f"Error cleaning up tasks: {e}")
    
    # Close the loop
    loop.close()

@pytest_asyncio.fixture(scope="session")
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

@pytest_asyncio.fixture(scope="session")
async def session_snapshot(morph_client, base_image):
    """Create a shared snapshot for tests."""
    logger.info("Creating session snapshot")
    snapshot = await morph_client.snapshots.acreate(
        image_id=base_image,
        vcpus=1,
        memory=512,
        disk_size=8192  # Minimum allowed disk size
    )
    
    # Register for cleanup
    register_snapshot(snapshot)
    
    logger.info(f"Created session snapshot: {snapshot.id}")
    return snapshot

@pytest_asyncio.fixture(scope="session")
async def session_instance(morph_client, session_snapshot):
    """Create a shared instance for tests."""
    logger.info(f"Starting session instance from snapshot {session_snapshot.id}")
    instance = await morph_client.instances.astart(session_snapshot.id)
    
    # Register for cleanup
    register_instance(instance)
    
    # Wait for instance to be ready
    logger.info(f"Waiting for instance {instance.id} to be ready")
    await instance.await_until_ready(timeout=300)
    logger.info(f"Session instance {instance.id} is ready")
    
    return instance

@pytest.fixture(scope="session", autouse=True)
def cleanup_resources(event_loop):
    """Automatically clean up resources after all tests."""
    # Setup - nothing to do
    yield
    
    # Teardown
    logger.info("Running cleanup")
    
    async def cleanup():
        # Clean up instances first
        for instance in reversed(_RESOURCES["instances"]):
            try:
                logger.info(f"Stopping instance {instance.id}")
                await instance.astop()
                logger.info(f"Instance {instance.id} stopped")
            except Exception as e:
                logger.error(f"Error stopping instance {instance.id}: {e}")
        
        # Then clean up snapshots
        for snapshot in reversed(_RESOURCES["snapshots"]):
            try:
                logger.info(f"Deleting snapshot {snapshot.id}")
                await snapshot.adelete()
                logger.info(f"Snapshot {snapshot.id} deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot {snapshot.id}: {e}")
    
    # Run cleanup in the event loop
    event_loop.run_until_complete(cleanup())
    logger.info("Cleanup complete")

# Helper functions for tests
@pytest_asyncio.fixture(scope="session")
async def create_test_file(session_instance):
    """Create a test file with unique content on the shared instance."""
    content = f"test-content-{uuid.uuid4()}"
    path = f"/tmp/test-{uuid.uuid4()}.txt"
    
    result = await session_instance.aexec(f"echo '{content}' > {path}")
    assert result.exit_code == 0, f"Failed to create test file: {result.stderr}"
    
    return {"path": path, "content": content}