"""
Function-scoped tests for snapshot operations in MorphCloud SDK.
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
    """Test creating a snapshot from a base image."""
    logger.info("Testing snapshot creation")
    
    try:
        # Create snapshot
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=512,
            disk_size=8192
        )
        logger.info(f"Created snapshot: {snapshot.id}")
        
        # Verify snapshot properties
        assert snapshot.id.startswith("snapshot_"), "Snapshot ID should start with 'snapshot_'"
        assert hasattr(snapshot, "refs"), "Snapshot should have a refs attribute"
        assert hasattr(snapshot.refs, "image_id"), "Snapshot should have refs.image_id attribute"
        assert snapshot.refs.image_id == base_image.id, "Snapshot should be created from the specified base image"
        
        # List snapshots and verify our snapshot is included
        snapshots = await client.snapshots.alist()
        assert any(s.id == snapshot.id for s in snapshots), "Snapshot should be in the list of snapshots"
        
        logger.info("Snapshot creation test completed successfully")
        
    finally:
        # Clean up resources
        if 'snapshot' in locals():
            try:
                logger.info(f"Deleting snapshot {snapshot.id}")
                await snapshot.adelete()
                logger.info(f"Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")


async def test_instance_to_instance_snapshot(client, base_image):
    """Test creating a snapshot from a running instance and starting a new instance from it."""
    logger.info("Testing instance to instance snapshot")
    
    # Track created resources for cleanup
    created_resources = {
        'snapshots': [],
        'instances': []
    }
    
    try:
        # Create first snapshot from base image
        logger.info(f"Creating snapshot from base image {base_image.id}")
        first_snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=512,
            disk_size=8192
        )
        logger.info(f"Created first snapshot: {first_snapshot.id}")
        created_resources['snapshots'].append(first_snapshot)
        
        # Start first instance
        logger.info(f"Starting first instance from snapshot {first_snapshot.id}")
        first_instance = await client.instances.astart(first_snapshot.id)
        logger.info(f"Created first instance: {first_instance.id}")
        created_resources['instances'].append(first_instance)
        
        # Wait for instance to be ready
        logger.info(f"Waiting for instance {first_instance.id} to be ready")
        await first_instance.await_until_ready(timeout=300)
        logger.info(f"Instance {first_instance.id} is ready")
        
        # Create a test file on the first instance
        test_file = f"/root/test-file-{uuid.uuid4()}.txt"
        test_content = f"test-content-{uuid.uuid4()}"
        
        # Write test file
        logger.info(f"Writing test file {test_file}")
        result = await first_instance.aexec(f"echo '{test_content}' > {test_file}")
        assert result.exit_code == 0, "Failed to write test file"
        
        # Verify file exists
        result = await first_instance.aexec(f"cat {test_file}")
        assert result.exit_code == 0, "Failed to read test file"
        assert test_content in result.stdout, "Test file content does not match"
        
        # Create snapshot from running instance
        logger.info(f"Creating snapshot from instance {first_instance.id}")
        second_snapshot = await first_instance.asnapshot()
        logger.info(f"Created second snapshot: {second_snapshot.id}")
        created_resources['snapshots'].append(second_snapshot)
        
        # Start new instance from the second snapshot
        logger.info(f"Starting second instance from snapshot {second_snapshot.id}")
        second_instance = await client.instances.astart(second_snapshot.id)
        logger.info(f"Created second instance: {second_instance.id}")
        created_resources['instances'].append(second_instance)
        
        # Wait for second instance to be ready
        logger.info(f"Waiting for instance {second_instance.id} to be ready")
        await second_instance.await_until_ready(timeout=300)
        logger.info(f"Instance {second_instance.id} is ready")
        
        # Verify the test file persisted in the snapshot
        logger.info(f"Verifying test file {test_file} exists on second instance")
        result = await second_instance.aexec(f"cat {test_file}")
        assert result.exit_code == 0, "Failed to read test file on second instance"
        assert test_content in result.stdout, "Test file content does not match on second instance"
        
        logger.info("Instance to instance snapshot test completed successfully")
        
    finally:
        # Clean up resources in reverse order
        for instance in reversed(created_resources['instances']):
            try:
                logger.info(f"Stopping instance {instance.id}")
                await instance.astop()
                logger.info(f"Instance stopped")
            except Exception as e:
                logger.error(f"Error stopping instance: {e}")
        
        for snapshot in reversed(created_resources['snapshots']):
            try:
                logger.info(f"Deleting snapshot {snapshot.id}")
                await snapshot.adelete()
                logger.info(f"Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")


async def test_snapshot_metadata(client, base_image):
    """Test setting and retrieving snapshot metadata."""
    logger.info("Testing snapshot metadata")
    
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
        
        # Verify metadata was set
        assert snapshot.metadata.get(test_key) == test_value, "Snapshot metadata should contain the test key-value pair"
        
        # Get snapshot and verify metadata
        updated_snapshot = await client.snapshots.aget(snapshot.id)
        assert updated_snapshot.metadata.get(test_key) == test_value, "Updated snapshot metadata should contain the test key-value pair"
        
        # List snapshots by metadata
        filter_metadata = {test_key: test_value}
        snapshots = await client.snapshots.alist(metadata=filter_metadata)
        
        # Verify snapshot is in the filtered list
        assert any(s.id == snapshot.id for s in snapshots), "Snapshot should be found when filtering by its metadata"
        
        # Update metadata
        new_value = f"updated-value-{uuid.uuid4()}"
        await snapshot.aset_metadata({test_key: new_value})
        
        # Verify metadata was updated
        updated_snapshot = await client.snapshots.aget(snapshot.id)
        assert updated_snapshot.metadata.get(test_key) == new_value, "Snapshot metadata should be updated"
        
        logger.info("Snapshot metadata test completed successfully")
        
    finally:
        # Clean up resources
        if 'snapshot' in locals():
            try:
                logger.info(f"Deleting snapshot {snapshot.id}")
                await snapshot.adelete()
                logger.info(f"Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")


async def test_snapshot_multiple_instances(client, base_image):
    """Test starting multiple instances from the same snapshot."""
    logger.info("Testing starting multiple instances from the same snapshot")
    
    # Track created resources for cleanup
    created_resources = {
        'snapshots': [],
        'instances': []
    }
    
    try:
        # Create snapshot
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=512,
            disk_size=8192
        )
        logger.info(f"Created snapshot: {snapshot.id}")
        created_resources['snapshots'].append(snapshot)
        
        # Start multiple instances from the same snapshot
        num_instances = 3
        instances = []
        
        for i in range(num_instances):
            logger.info(f"Starting instance {i+1} from snapshot {snapshot.id}")
            instance = await client.instances.astart(snapshot.id)
            logger.info(f"Created instance: {instance.id}")
            instances.append(instance)
            created_resources['instances'].append(instance)
        
        # Wait for all instances to be ready
        for instance in instances:
            logger.info(f"Waiting for instance {instance.id} to be ready")
            await instance.await_until_ready(timeout=300)
            logger.info(f"Instance {instance.id} is ready")
        
        # Verify all instances are running and have the same snapshot ID
        for instance in instances:
            assert instance.refs.snapshot_id == snapshot.id, f"Instance {instance.id} should be created from snapshot {snapshot.id}"
        
        # List instances and verify all our instances are included
        all_instances = await client.instances.alist()
        for instance in instances:
            assert any(i.id == instance.id for i in all_instances), f"Instance {instance.id} should be in the list of instances"
        
        logger.info("Starting multiple instances test completed successfully")
        
    finally:
        # Clean up resources in reverse order
        for instance in reversed(created_resources['instances']):
            try:
                logger.info(f"Stopping instance {instance.id}")
                await instance.astop()
                logger.info(f"Instance stopped")
            except Exception as e:
                logger.error(f"Error stopping instance: {e}")
        
        for snapshot in reversed(created_resources['snapshots']):
            try:
                logger.info(f"Deleting snapshot {snapshot.id}")
                await snapshot.adelete()
                logger.info(f"Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")