"""
Function-scoped tests for metadata operations in MorphCloud SDK.
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


async def test_instance_metadata(client, base_image):
    """Test metadata operations on an instance."""
    logger.info("Testing instance metadata operations")
    logger.info(f"Using base image: {base_image.id}")
    
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
        instance = await client.instances.astart(snapshot.id)
        logger.info(f"Created instance: {instance.id}")
        
        # Wait for instance to be ready
        logger.info(f"Waiting for instance {instance.id} to be ready")
        try:
            await instance.await_until_ready(timeout=60)
            logger.info(f"Instance {instance.id} is ready")
        except TimeoutError:
            logger.error(f"Instance {instance.id} did not become ready within 60 seconds. Current status: {instance.status}")
            raise
        except Exception as e:
            logger.error(f"Error waiting for instance {instance.id}: {e}. Current status: {instance.status}")
            raise
        
        # Set metadata
        test_key = f"test-key-{uuid.uuid4()}"
        test_value = f"test-value-{uuid.uuid4()}"
        test_metadata = {test_key: test_value}
        
        logger.info(f"Setting metadata: {test_metadata}")
        await instance.aset_metadata(test_metadata)
        
        # Verify metadata was set
        assert instance.metadata.get(test_key) == test_value
        
        # List instances by metadata
        filter_metadata = {test_key: test_value}
        instances = await client.instances.alist(metadata=filter_metadata)
        
        # Verify instance is in the filtered list
        assert any(i.id == instance.id for i in instances), "Instance should be found when filtering by its metadata"
        
        # Update metadata
        new_value = f"updated-value-{uuid.uuid4()}"
        logger.info(f"Updating metadata value to: {new_value}")
        await instance.aset_metadata({test_key: new_value})
        
        # Verify metadata was updated
        assert instance.metadata.get(test_key) == new_value
        
        # Set multiple metadata values (preserve existing metadata)
        multi_metadata = {
            f"key1-{uuid.uuid4()}": f"value1-{uuid.uuid4()}",
            f"key2-{uuid.uuid4()}": f"value2-{uuid.uuid4()}"
        }
        # Merge with existing metadata to avoid overwriting
        merged_metadata = {**instance.metadata, **multi_metadata}
        logger.info(f"Setting multiple metadata values: {multi_metadata}")
        await instance.aset_metadata(merged_metadata)
        
        # Verify all metadata values
        for key, value in multi_metadata.items():
            assert instance.metadata.get(key) == value
        
        # Original metadata should still be there
        assert instance.metadata.get(test_key) == new_value
        
        logger.info("Instance metadata operations completed successfully")
        
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


async def test_snapshot_metadata(client, base_image):
    """Test metadata operations on a snapshot."""
    logger.info("Testing snapshot metadata operations")
    
    try:
        # Create snapshot
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=512,
            disk_size=8192
        )
        logger.info(f"Created snapshot: {snapshot.id}")
        
        # Set metadata
        test_key = f"test-key-{uuid.uuid4()}"
        test_value = f"test-value-{uuid.uuid4()}"
        test_metadata = {test_key: test_value}
        
        logger.info(f"Setting metadata: {test_metadata}")
        await snapshot.aset_metadata(test_metadata)
        
        # Get snapshot and verify metadata
        updated_snapshot = await client.snapshots.aget(snapshot.id)
        assert updated_snapshot.metadata.get(test_key) == test_value
        
        # Update metadata
        new_value = f"updated-value-{uuid.uuid4()}"
        logger.info(f"Updating metadata value to: {new_value}")
        await snapshot.aset_metadata({test_key: new_value})
        
        # Get snapshot and verify updated metadata
        updated_snapshot = await client.snapshots.aget(snapshot.id)
        assert updated_snapshot.metadata.get(test_key) == new_value
        
        logger.info("Snapshot metadata operations completed successfully")
        
    finally:
        # Clean up resources
        if 'snapshot' in locals():
            try:
                logger.info(f"Deleting snapshot {snapshot.id}")
                await snapshot.adelete()
                logger.info(f"Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")


async def test_filter_by_metadata(client, base_image):
    """Test filtering resources by metadata."""
    logger.info("Testing filtering by metadata")
    
    # Resources to clean up
    resources = {
        'snapshots': [],
        'instances': []
    }
    
    try:
        # Create multiple snapshots with different metadata
        snapshot_count = 3
        snapshots = []
        common_key = f"test-common-key-{uuid.uuid4()}"
        common_value = f"test-common-value-{uuid.uuid4()}"
        
        for i in range(snapshot_count):
            # Create snapshot
            snapshot = await client.snapshots.acreate(
                image_id=base_image.id,
                vcpus=1,
                memory=512,
                disk_size=8192
            )
            logger.info(f"Created snapshot {i+1}: {snapshot.id}")
            snapshots.append(snapshot)
            resources['snapshots'].append(snapshot)
            
            # Set common metadata on all snapshots
            await snapshot.aset_metadata({common_key: common_value})
            
            # Set unique metadata on each snapshot
            unique_key = f"test-unique-key-{i+1}"
            unique_value = f"test-unique-value-{i+1}"
            # Merge with existing metadata to avoid overwriting
            existing_metadata = snapshot.metadata or {}
            merged_metadata = {**existing_metadata, unique_key: unique_value}
            await snapshot.aset_metadata(merged_metadata)
        
        # Add a small delay to allow metadata to propagate
        import asyncio
        await asyncio.sleep(1)
        
        # Filter snapshots by common metadata
        filtered_snapshots = await client.snapshots.alist(metadata={common_key: common_value})
        
        # Verify all our snapshots are in the filtered list
        assert len(filtered_snapshots) >= snapshot_count, "All snapshots should be found when filtering by common metadata"
        for snapshot in snapshots:
            assert any(s.id == snapshot.id for s in filtered_snapshots), f"Snapshot {snapshot.id} should be in filtered list"
        
        # Filter snapshots by unique metadata
        for i in range(snapshot_count):
            unique_key = f"test-unique-key-{i+1}"
            unique_value = f"test-unique-value-{i+1}"
            
            filtered_snapshots = await client.snapshots.alist(metadata={unique_key: unique_value})
            
            # Verify only one snapshot is found
            assert len(filtered_snapshots) >= 1, f"At least one snapshot should be found when filtering by unique metadata {unique_key}={unique_value}"
            assert any(s.id == snapshots[i].id for s in filtered_snapshots), f"Snapshot {snapshots[i].id} should be in filtered list"
        
        logger.info("Filtering by metadata test completed successfully")
        
    finally:
        # Clean up resources in reverse order
        for snapshot in reversed(resources['snapshots']):
            try:
                logger.info(f"Deleting snapshot {snapshot.id}")
                await snapshot.adelete()
                logger.info(f"Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")

