"""
Test for Snapshot.from_tag() method when multiple snapshots have the same tag.
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


async def test_from_tag_multiple_snapshots(client: MorphCloudClient, base_image):
    """Test that from_tag returns the most recent snapshot when multiple snapshots have the same tag."""
    from morphcloud.experimental import Snapshot
    
    test_tag = f"test-tag-{uuid.uuid4().hex[:8]}"
    created_snapshots = []
    
    try:
        logger.info(f"Starting from_tag multiple snapshots test with tag: {test_tag}")
        
        # Create multiple snapshots with the same tag
        for i in range(3):
            logger.info(f"Creating snapshot {i+1}")
            instance = await client.instances.acreate(base_image.id)
            snapshot = await instance.asave()
            
            # Tag each snapshot with the same tag
            snapshot.set_metadata({"tag": test_tag, "index": str(i)})
            created_snapshots.append(snapshot)
            
            logger.info(f"Created snapshot {snapshot.id} with tag {test_tag}")
            await instance.astop()
        
        # Test from_tag method - should return the most recent (last created) snapshot
        logger.info(f"Testing from_tag with tag: {test_tag}")
        retrieved_snapshot = Snapshot.from_tag(test_tag)
        
        # The most recent snapshot should be the last one created (index 2)
        assert retrieved_snapshot.snapshot.id == created_snapshots[-1].id, \
            f"Expected most recent snapshot {created_snapshots[-1].id}, got {retrieved_snapshot.snapshot.id}"
        assert retrieved_snapshot.snapshot.metadata.get("index") == "2", \
            f"Expected index '2', got {retrieved_snapshot.snapshot.metadata.get('index')}"
        
        logger.info("from_tag multiple snapshots test completed successfully")
        
    finally:
        # Clean up all created snapshots
        for snapshot in reversed(created_snapshots):
            try:
                logger.info(f"Deleting snapshot {snapshot.id}")
                await snapshot.adelete()
                logger.info(f"Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")


async def test_from_tag_single_snapshot(client: MorphCloudClient, base_image):
    """Test that from_tag works correctly with a single snapshot (existing behavior)."""
    from morphcloud.experimental import Snapshot
    
    test_tag = f"single-tag-{uuid.uuid4().hex[:8]}"
    
    try:
        logger.info(f"Starting from_tag single snapshot test with tag: {test_tag}")
        
        # Create single snapshot with unique tag
        instance = await client.instances.acreate(base_image.id)
        snapshot = await instance.asave()
        snapshot.set_metadata({"tag": test_tag})
        
        logger.info(f"Created snapshot {snapshot.id} with tag {test_tag}")
        await instance.astop()
        
        # Test from_tag method - should return the snapshot
        retrieved_snapshot = Snapshot.from_tag(test_tag)
        
        assert retrieved_snapshot.snapshot.id == snapshot.id, \
            f"Expected snapshot {snapshot.id}, got {retrieved_snapshot.snapshot.id}"
        
        logger.info("from_tag single snapshot test completed successfully")
        
    finally:
        # Clean up
        try:
            logger.info(f"Deleting snapshot {snapshot.id}")
            await snapshot.adelete()
            logger.info(f"Snapshot deleted")
        except Exception as e:
            logger.error(f"Error deleting snapshot: {e}")


async def test_from_tag_no_snapshots(client: MorphCloudClient):
    """Test that from_tag raises appropriate error when no snapshots found."""
    from morphcloud.experimental import Snapshot
    
    nonexistent_tag = f"nonexistent-{uuid.uuid4().hex[:8]}"
    
    logger.info(f"Testing from_tag with nonexistent tag: {nonexistent_tag}")
    
    # Test from_tag method - should raise ValueError
    with pytest.raises(ValueError, match=f"No snapshot found with tag: {nonexistent_tag}"):
        Snapshot.from_tag(nonexistent_tag)
    
    logger.info("from_tag no snapshots test completed successfully")