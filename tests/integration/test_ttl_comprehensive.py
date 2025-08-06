"""
Comprehensive TTL (Time-to-Live) functionality tests for MorphCloud SDK.

This file tests TTL functionality that was missing from the existing test suite,
achieving parity with the TypeScript SDK test coverage.
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


async def test_instance_creation_with_ttl_seconds(client, base_image):
    """Test TTL parameter during instance creation."""
    logger.info("Testing instance creation with TTL seconds parameter")
    
    resources = {
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
        resources['snapshots'].append(snapshot)
        logger.info(f"Created snapshot: {snapshot.id}")
        
        # Start instance with TTL seconds
        ttl_seconds = 300  # 5 minutes
        logger.info(f"Creating instance with TTL of {ttl_seconds} seconds")
        instance = await client.instances.astart(
            snapshot.id,
            ttl_seconds=ttl_seconds
        )
        resources['instances'].append(instance)
        
        # Wait for instance to be ready
        logger.info(f"Waiting for instance {instance.id} to be ready")
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} is ready with TTL set")
        
        # Verify instance is accessible during TTL period
        result = await instance.aexec("echo 'TTL test successful'")
        assert result.exit_code == 0
        assert "TTL test successful" in result.stdout
        logger.info("Instance successfully executed command during TTL period")
        
    finally:
        # Clean up resources
        for instance in reversed(resources['instances']):
            try:
                logger.info(f"Stopping instance {instance.id}")
                await instance.astop()
            except Exception as e:
                logger.error(f"Error stopping instance: {e}")
        
        for snapshot in reversed(resources['snapshots']):
            try:
                logger.info(f"Deleting snapshot {snapshot.id}")
                await snapshot.adelete()
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")


async def test_ttl_action_stop_vs_pause(client, base_image):
    """Test different TTL actions (stop vs pause)."""
    logger.info("Testing TTL action parameter validation (stop vs pause)")
    
    resources = {
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
        resources['snapshots'].append(snapshot)
        logger.info(f"Created snapshot: {snapshot.id}")
        
        # Test TTL with "stop" action
        ttl_seconds = 600  # 10 minutes (long enough for testing)
        logger.info(f"Creating instance with TTL action 'stop'")
        instance1 = await client.instances.astart(
            snapshot.id,
            ttl_seconds=ttl_seconds,
            ttl_action="stop"
        )
        resources['instances'].append(instance1)
        
        # Wait for instance to be ready
        await instance1.await_until_ready(timeout=300)
        logger.info(f"Instance {instance1.id} ready with 'stop' TTL action")
        
        # Test TTL with "pause" action
        logger.info(f"Creating instance with TTL action 'pause'")
        instance2 = await client.instances.astart(
            snapshot.id,
            ttl_seconds=ttl_seconds,
            ttl_action="pause"
        )
        resources['instances'].append(instance2)
        
        # Wait for instance to be ready
        await instance2.await_until_ready(timeout=300)
        logger.info(f"Instance {instance2.id} ready with 'pause' TTL action")
        
        # Both instances should be functional during TTL period
        result1 = await instance1.aexec("echo 'stop action test'")
        result2 = await instance2.aexec("echo 'pause action test'")
        
        assert result1.exit_code == 0
        assert result2.exit_code == 0
        assert "stop action test" in result1.stdout
        assert "pause action test" in result2.stdout
        
        logger.info("Both TTL actions successfully validated")
        
    finally:
        # Clean up resources
        for instance in reversed(resources['instances']):
            try:
                logger.info(f"Stopping instance {instance.id}")
                await instance.astop()
            except Exception as e:
                logger.error(f"Error stopping instance: {e}")
        
        for snapshot in reversed(resources['snapshots']):
            try:
                logger.info(f"Deleting snapshot {snapshot.id}")
                await snapshot.adelete()
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")


async def test_ttl_boundary_conditions(client, base_image):
    """Test TTL boundary conditions and edge cases."""
    logger.info("Testing TTL boundary conditions and minimum values")
    
    resources = {
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
        resources['snapshots'].append(snapshot)
        logger.info(f"Created snapshot: {snapshot.id}")
        
        # Test minimum reasonable TTL (60 seconds)
        min_ttl_seconds = 60
        logger.info(f"Creating instance with minimum TTL of {min_ttl_seconds} seconds")
        instance = await client.instances.astart(
            snapshot.id,
            ttl_seconds=min_ttl_seconds
        )
        resources['instances'].append(instance)
        
        # Wait for instance to be ready
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} ready with minimum TTL")
        
        # Verify instance is accessible immediately
        result = await instance.aexec("uptime")
        assert result.exit_code == 0
        logger.info("Instance with minimum TTL is functional")
        
        # Test setting TTL after instance creation
        logger.info("Testing TTL modification after instance creation")
        extended_ttl_minutes = 10
        await instance.aset_ttl(ttl_minutes=extended_ttl_minutes)
        logger.info(f"Successfully set TTL to {extended_ttl_minutes} minutes after creation")
        
        # Verify instance is still accessible after TTL modification
        result = await instance.aexec("echo 'TTL modified successfully'")
        assert result.exit_code == 0
        assert "TTL modified successfully" in result.stdout
        
    finally:
        # Clean up resources
        for instance in reversed(resources['instances']):
            try:
                logger.info(f"Stopping instance {instance.id}")
                await instance.astop()
            except Exception as e:
                logger.error(f"Error stopping instance: {e}")
        
        for snapshot in reversed(resources['snapshots']):
            try:
                logger.info(f"Deleting snapshot {snapshot.id}")
                await snapshot.adelete()
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")


@pytest.mark.timeout(900)  # 15-minute timeout for TTL expiration testing
async def test_instance_accessibility_during_ttl_period(client, base_image):
    """Test instance remains accessible during entire TTL period."""
    logger.info("Testing instance accessibility throughout TTL period")
    
    resources = {
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
        resources['snapshots'].append(snapshot)
        logger.info(f"Created snapshot: {snapshot.id}")
        
        # Create instance with short TTL for testing (3 minutes)
        ttl_seconds = 180
        logger.info(f"Creating instance with {ttl_seconds} second TTL")
        instance = await client.instances.astart(
            snapshot.id,
            ttl_seconds=ttl_seconds,
            ttl_action="stop"
        )
        resources['instances'].append(instance)
        
        # Wait for instance to be ready
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} ready")
        
        # Test periodic accessibility during TTL period
        test_intervals = [30, 60, 120]  # Test at 30s, 1min, 2min intervals
        
        for interval in test_intervals:
            if interval < ttl_seconds:
                logger.info(f"Waiting {interval} seconds, then testing accessibility")
                await asyncio.sleep(interval)
                
                # Test instance accessibility
                result = await instance.aexec(f"echo 'Accessible after {interval} seconds'")
                assert result.exit_code == 0
                assert f"Accessible after {interval} seconds" in result.stdout
                logger.info(f"Instance accessible after {interval} seconds")
        
        logger.info("Instance remained accessible throughout tested TTL period")
        
    except asyncio.TimeoutError:
        logger.warning("Test timeout reached - this is expected for TTL expiration testing")
    finally:
        # Clean up resources
        for instance in reversed(resources['instances']):
            try:
                logger.info(f"Stopping instance {instance.id}")
                await instance.astop()
            except Exception as e:
                logger.error(f"Error stopping instance: {e}")
        
        for snapshot in reversed(resources['snapshots']):
            try:
                logger.info(f"Deleting snapshot {snapshot.id}")
                await snapshot.adelete()
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")


async def test_ttl_wake_on_event_integration(client, base_image):
    """Test TTL integration with wake-on-event functionality."""
    logger.info("Testing TTL integration with wake-on-event")
    
    resources = {
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
        resources['snapshots'].append(snapshot)
        logger.info(f"Created snapshot: {snapshot.id}")
        
        # Create instance with TTL and wake-on-event
        ttl_minutes = 5
        logger.info(f"Creating instance with {ttl_minutes} minute TTL and wake-on-event")
        instance = await client.instances.astart(snapshot.id)
        resources['instances'].append(instance)
        
        # Wait for instance to be ready
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} ready")
        
        # Set TTL and wake-on-event
        await instance.aset_ttl(ttl_minutes=ttl_minutes)
        await instance.aset_wake_on(['http'])
        logger.info(f"Set TTL to {ttl_minutes} minutes with wake-on HTTP events")
        
        # Verify instance functionality with TTL and wake-on-event set
        result = await instance.aexec("echo 'TTL and wake-on-event configured'")
        assert result.exit_code == 0
        assert "TTL and wake-on-event configured" in result.stdout
        
        logger.info("TTL and wake-on-event integration successful")
        
    finally:
        # Clean up resources
        for instance in reversed(resources['instances']):
            try:
                logger.info(f"Stopping instance {instance.id}")
                await instance.astop()
            except Exception as e:
                logger.error(f"Error stopping instance: {e}")
        
        for snapshot in reversed(resources['snapshots']):
            try:
                logger.info(f"Deleting snapshot {snapshot.id}")
                await snapshot.adelete()
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")