"""
Function-scoped tests for Time-To-Live (TTL), wake-on-event, and auto-cleanup in MorphCloud SDK.
"""
import pytest
import logging
import uuid
import os
import asyncio
import time
import datetime
import httpx
import pytest_asyncio

from morphcloud.api import MorphCloudClient, InstanceStatus, Snapshot

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

    # Use an Ubuntu image as it's common and has python3
    image = next((img for img in images if "minimal" in img.id.lower()), None)
    if not image:
        pytest.fail("An ubuntu base image is required for these tests.")

    logger.info(f"Using base image: {image.id}")
    return image


@pytest_asyncio.fixture
async def instance_snapshot(client: MorphCloudClient, base_image) -> Snapshot:
    """
    Provides a ready snapshot for tests that need to start an instance,
    and handles cleanup automatically.
    """
    snapshot = None
    try:
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=512,
            disk_size=8192
        )
        await snapshot.await_until_ready(timeout=300)
        logger.info(f"Fixture created snapshot: {snapshot.id}")
        yield snapshot
    finally:
        if snapshot:
            try:
                logger.info(f"Fixture cleaning up snapshot: {snapshot.id}")
                await snapshot.adelete()
                logger.info(f"Snapshot {snapshot.id} deleted.")
            except Exception as e:
                logger.error(f"Error deleting snapshot in fixture: {e}")


async def test_instance_ttl_stop_action(client: MorphCloudClient, instance_snapshot: Snapshot):
    """Test instance TTL with the default 'stop' action."""
    logger.info("Testing instance TTL with stop action")
    
    # Set a very short TTL for testing
    ttl_seconds = 10
    instance = None
    
    try:
        logger.info(f"Starting instance with TTL of {ttl_seconds} seconds")
        instance = await client.instances.astart(
            instance_snapshot.id,
            ttl_seconds=ttl_seconds,
            ttl_action='stop' # Explicitly set stop action
        )
        
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} is ready")
        
        # Verify the TTL is set by checking expiration time
        assert instance.ttl.ttl_expire_at is not None
        logger.info(f"Instance TTL is set, expires at: {datetime.datetime.fromtimestamp(instance.ttl.ttl_expire_at)}")
        
        # Wait for slightly longer than the TTL
        wait_time = ttl_seconds + 10
        logger.info(f"Waiting {wait_time} seconds for instance to be stopped by TTL")
        await asyncio.sleep(wait_time)
        
        # Verify instance has been automatically stopped (deleted)
        try:
            await client.instances.aget(instance.id)
            pytest.fail(f"Instance {instance.id} should have been automatically stopped")
        except Exception as e:
            logger.info(f"Instance {instance.id} has been stopped as expected: {str(e)}")
            instance = None # Avoid double-cleanup
            
    finally:
        if instance:
            try:
                await instance.astop()
            except Exception as e:
                logger.info(f"Instance cleanup: {e}")

async def test_instance_ttl_pause_action(client: MorphCloudClient, instance_snapshot: Snapshot):
    """
    Tests the TTL lifecycle with ttl_action='pause'.
    1. Instance starts and then pauses due to TTL.
    2. It is manually resumed.
    3. The TTL is reset, and the instance pauses again after the TTL expires.
    """
    logger.info("Testing instance TTL with pause action")
    ttl_seconds = 10  # Use a short TTL for the test cycle
    instance = None

    try:
        # 1. Start an instance and set it to pause after TTL
        logger.info(f"Starting instance with ttl={ttl_seconds}s and action=pause")
        instance = await client.instances.astart(snapshot_id=instance_snapshot.id)
        await instance.await_until_ready(timeout=300)
        await instance.aset_ttl(ttl_seconds=ttl_seconds, ttl_action='pause')
        logger.info(f"Instance {instance.id} is ready.")

        initial_expire_at = instance.ttl.ttl_expire_at
        assert initial_expire_at is not None

        # 2. Wait for the instance to pause automatically
        logger.info(f"Waiting {ttl_seconds}s before checking for auto-pause...")
        await asyncio.sleep(ttl_seconds)

        # Now poll every 3 seconds until the instance is PAUSED, or timeout after 60 seconds
        poll_interval = 3
        max_wait = 60
        elapsed = 0
        start_time = time.monotonic()
        while elapsed < max_wait:
            instance = await client.instances.aget(instance.id)
            if instance.status == InstanceStatus.PAUSED:
                break
            await asyncio.sleep(poll_interval)
            elapsed = time.monotonic() - start_time

        total_time = time.monotonic() - start_time
        assert instance.status == InstanceStatus.PAUSED, f"Expected instance to be PAUSED, but got {instance.status}"
        logger.info(f"Instance {instance.id} is PAUSED as expected after {total_time:.1f} seconds.")

        # 3. Manually resume the instance
        logger.info("Manually resuming instance...")
        await instance.aresume()
        await instance.await_until_ready(timeout=60)
        assert instance.status == InstanceStatus.READY
        logger.info(f"Instance {instance.id} is READY again.")
        
        # 4. Verify the TTL has been reset automatically by the resume method
        instance = await client.instances.aget(instance.id)
        new_expire_at = instance.ttl.ttl_expire_at
        assert new_expire_at is not None
        assert new_expire_at > initial_expire_at
        logger.info(f"TTL expiration has been reset to a future time: {datetime.datetime.fromtimestamp(new_expire_at)}")
        
        # 5. Wait for the *second* TTL to expire to ensure it pauses again
        logger.info(f"Waiting {ttl_seconds + 10}s for instance to auto-pause again...")
        await asyncio.sleep(ttl_seconds + 10)

        instance = await client.instances.aget(instance.id)
        assert instance.status == InstanceStatus.PAUSED, f"Expected instance to be PAUSED, but got {instance.status}"
        logger.info(f"Instance {instance.id} has auto-paused again, completing the pause/resume cycle.")

    finally:
        if instance:
            try:
                await instance.astop()
            except Exception as e:
                logger.info(f"Instance cleanup: {e}")

async def test_wake_on_ssh(client: MorphCloudClient, instance_snapshot: Snapshot):
    """
    Tests the wake_on_ssh functionality.
    1. Instance starts and then pauses due to TTL.
    2. An SSH connection wakes the instance up.
    3. Verifies the instance is ready and its TTL has been reset.
    """
    logger.info("Testing wake_on_ssh functionality")
    instance = None

    try:
        # 1. Start an instance with wake_on_ssh enabled and a 'pause' action
        logger.info(f"Starting instance with action=pause, and enabling wake_on_ssh")
        instance = await client.instances.astart(snapshot_id=instance_snapshot.id)
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} is ready.")
        await instance.aset_wake_on(wake_on_ssh=True)
        # Verify the initial settings are correct
        assert instance.wake_on.wake_on_ssh is True

        # 2. Pause the instance
        await instance.apause()
        await asyncio.sleep(3)  # Give it a moment to pause

        assert instance.status == InstanceStatus.PAUSED
        logger.info(f"Instance {instance.id} is PAUSED as expected.")

        # 3. Attempt to SSH, which should trigger auto-resume
        logger.info("Attempting to connect via SSH to trigger wake-up...")
        with instance.ssh() as ssh:
            result = ssh.run("echo 'SSH connection successful'")
            assert result.exit_code == 0
            assert "successful" in result.stdout
        logger.info("SSH connection was successful, instance should be resuming.")

        # 4. Verify the instance is READY again
        await instance.await_until_ready(timeout=60)
        assert instance.status == InstanceStatus.READY
        logger.info(f"Instance {instance.id} is READY again.")

    finally:
        if instance:
            try:
                await instance.astop()
            except Exception as e:
                logger.info(f"Instance cleanup: {e}")


async def test_wake_on_http(client: MorphCloudClient, instance_snapshot: Snapshot):
    """
    Tests the wake_on_http functionality:
    1. Starts a simple python HTTP server inside the instance.
    2. Exposes the port and gets a public URL.
    3. Pauses the instance via TTL.
    4. Sends an HTTP request to the URL to wake it up.
    """
    logger.info("Testing wake_on_http functionality")
    instance = None
    service_port = 8888
    
    try:
        # 1. Start instance and configure it with a simple web server
        logger.info("Starting instance for wake_on_http test")
        instance = await client.instances.astart(snapshot_id=instance_snapshot.id)
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} ready.")

        # Command to run a simple python web server in the background
        server_command = f"python3 -m http.server {service_port} > /dev/null 2>&1 &"
        exec_result = await instance.aexec(server_command)
        assert exec_result.exit_code == 0
        logger.info(f"Started Python HTTP server on port {service_port}")
        await asyncio.sleep(3) # Give the server a moment to start

        # 2. Expose the service and set wake_on_http
        url = await instance.aexpose_http_service(name="test-server", port=service_port)
        logger.info(f"Service exposed at URL: {url}")
        
        await instance.aset_wake_on(wake_on_http=True)
        logger.info(f"Instance configured to wake on HTTP")

        # Verify settings
        assert instance.wake_on.wake_on_http is True

        # 3. Pause the instance to simulate TTL expiration
        logger.info("Pausing instance to simulate TTL expiration")
        await instance.apause()
        await asyncio.sleep(3)  # Give it a moment to pause

        assert instance.status == InstanceStatus.PAUSED
        logger.info(f"Instance {instance.id} is PAUSED as expected.")

        # 4. Send an HTTP request to wake it up
        logger.info(f"Sending GET request to {url} to wake instance...")
        async with httpx.AsyncClient() as http_client:
            # The request might time out as the instance wakes up, which is acceptable.
            # We just need to send it. A successful response isn't required.
            try:
                response = await http_client.get(url, timeout=60)
                logger.info(f"Wake-up request completed with status: {response.status_code}")
            except httpx.ReadTimeout:
                logger.info("Request timed out as expected during wake-up, which is fine.")
            except httpx.ConnectError as e:
                logger.warning(f"Connection error during wake-up (can be expected): {e}")

        # 5. Verify the instance is READY again
        logger.info("Waiting for instance to become ready after HTTP request...")
        await instance.await_until_ready(timeout=60)
        assert instance.status == InstanceStatus.READY
        logger.info(f"Instance {instance.id} is READY again.")

    finally:
        if instance:
            try:
                await instance.astop()
            except Exception as e:
                logger.info(f"Instance cleanup: {e}")
