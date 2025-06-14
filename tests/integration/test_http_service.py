"""
Function-scoped tests for HTTP service functionality in MorphCloud SDK.
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


async def test_http_service_expose_unexpose(client, base_image):
    """Test exposing and unexposing an HTTP service on an instance."""
    logger.info("Testing HTTP service exposure and unexposure")
    
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
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} is ready")
        
        # Set up a simple HTTP server on the instance
        port = 8000
        logger.info(f"Setting up HTTP server on port {port}")
        
        # Create a simple HTML file to serve
        test_id = uuid.uuid4().hex
        html_content = f"<html><body><h1>Hello World</h1><p>Test ID: {test_id}</p></body></html>"
        await instance.aexec(f"echo '{html_content}' > /tmp/index.html")
        
        # Install tmux if not available
        await instance.aexec("apt-get update && apt-get install -y tmux python3")
        
        # Start a Python HTTP server in tmux session
        server_cmd = f"cd /tmp && tmux new-session -d -s httpserver 'python3 -m http.server {port}'"
        result = await instance.aexec(server_cmd)
        assert result.exit_code == 0, "Failed to start HTTP server in tmux"
        
        # Give the server a moment to start
        await asyncio.sleep(3)
        
        # Verify the tmux session is running
        tmux_result = await instance.aexec("tmux list-sessions")
        assert "httpserver" in tmux_result.stdout, "HTTP server tmux session is not running"
        
        # Expose the HTTP service
        logger.info(f"Exposing HTTP service on port {port}")
        service_url = await instance.aexpose_http_service(name="test-service", port=port)
        logger.info(f"Service exposed at URL: {service_url}")
        
        # Verify service is listed in instance networking
        assert len(instance.networking.http_services) > 0, "No HTTP services exposed"
        assert any(s.port == port for s in instance.networking.http_services), "Service not found in instance networking"
        
        # Test unexpose
        logger.info("Unexposing HTTP service")
        await instance.ahide_http_service(name="test-service")
        
        # Verify service is no longer listed
        instance = await client.instances.aget(instance.id)  # Refresh instance data
        assert not any(s.port == port for s in instance.networking.http_services), "Service still exposed after unexpose"
        
        logger.info("HTTP service exposure/unexposure test completed successfully")
        
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


async def test_http_service_access(client, base_image):
    """Test accessing an HTTP service on an instance."""
    logger.info("Testing HTTP service access")
    
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
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} is ready")
        
        # Set up a simple HTTP server on the instance
        port = 8000
        logger.info(f"Setting up HTTP server on port {port}")
        
        # Create a simple HTML file to serve
        test_id = uuid.uuid4().hex
        html_content = f"<html><body><h1>Hello World</h1><p>Test ID: {test_id}</p></body></html>"
        await instance.aexec(f"echo '{html_content}' > /tmp/index.html")
        
        # Install tmux if not available
        await instance.aexec("apt-get update && apt-get install -y tmux python3")
        
        # Start a Python HTTP server in tmux session
        server_cmd = f"cd /tmp && tmux new-session -d -s httpserver2 'python3 -m http.server {port}'"
        result = await instance.aexec(server_cmd)
        assert result.exit_code == 0, "Failed to start HTTP server in tmux"
        
        # Give the server a moment to start
        await asyncio.sleep(3)
        
        # Expose the HTTP service
        logger.info(f"Exposing HTTP service on port {port}")
        service_url = await instance.aexpose_http_service(name="test-service-access", port=port)
        logger.info(f"Service exposed at URL: {service_url}")
        
        # Verify we can access the service (if possible)
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(service_url) as response:
                    # Check status code
                    assert response.status == 200, f"HTTP request failed with status {response.status}"
                    
                    # Check content
                    content = await response.text()
                    assert f"Test ID: {test_id}" in content, "Content does not match expected"
                    logger.info("Successfully accessed HTTP service")
        except ImportError:
            logger.warning("aiohttp not available, skipping HTTP service access test")
            # Try using curl from the instance itself as a fallback
            curl_cmd = f"curl -s localhost:{port}"
            curl_result = await instance.aexec(curl_cmd)
            assert curl_result.exit_code == 0, "Failed to access HTTP service with curl"
            assert f"Test ID: {test_id}" in curl_result.stdout, "Content does not match expected"
            logger.info("Successfully accessed HTTP service using curl from inside the instance")
        
        logger.info("HTTP service access test completed successfully")
        
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


async def test_multiple_http_services(client, base_image):
    """Test exposing multiple HTTP services on an instance."""
    logger.info("Testing multiple HTTP services")
    
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
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} is ready")
        
        # Install tmux if not available
        await instance.aexec("apt-get update && apt-get install -y tmux python3")
        
        # Set up multiple HTTP servers on different ports
        ports = [8000, 8001, 8002]
        exposed_services = []
        
        for i, port in enumerate(ports):
            # Create a simple HTML file to serve
            test_id = uuid.uuid4().hex
            html_content = f"<html><body><h1>Service {i+1}</h1><p>Port: {port}</p><p>Test ID: {test_id}</p></body></html>"
            await instance.aexec(f"mkdir -p /tmp/service{i+1}")
            await instance.aexec(f"echo '{html_content}' > /tmp/service{i+1}/index.html")
            
            # Start a Python HTTP server in tmux session
            server_cmd = f"cd /tmp/service{i+1} && tmux new-session -d -s httpserver{i+1} 'python3 -m http.server {port}'"
            result = await instance.aexec(server_cmd)
            assert result.exit_code == 0, f"Failed to start HTTP server on port {port} in tmux"
            
            # Give the server a moment to start
            await asyncio.sleep(2)
            
            # Expose the HTTP service
            logger.info(f"Exposing HTTP service on port {port}")
            service_name = f"test-service-{i+1}"
            service_url = await instance.aexpose_http_service(name=service_name, port=port)
            logger.info(f"Service {i+1} exposed at URL: {service_url}")
            exposed_services.append((port, service_url, test_id, service_name))
        
        # Verify all services are listed in instance networking
        instance = await client.instances.aget(instance.id)  # Refresh instance data
        for port, _, _, _ in exposed_services:
            assert any(s.port == port for s in instance.networking.http_services), f"Service on port {port} not found in instance networking"
        
        # Unexpose services one by one
        for i, (port, _, _, service_name) in enumerate(exposed_services):
            logger.info(f"Unexposing service {i+1} on port {port}")
            await instance.ahide_http_service(name=service_name)
            
            # Verify service is no longer listed
            instance = await client.instances.aget(instance.id)  # Refresh instance data
            assert not any(s.port == port for s in instance.networking.http_services), f"Service on port {port} still exposed after unexpose"
        
        logger.info("Multiple HTTP services test completed successfully")
        
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
