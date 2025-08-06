"""
Global pytest fixtures for morphcloud SDK tests.
"""
import pytest
import pytest_asyncio
import os
import logging
from unittest.mock import Mock, patch

from morphcloud.api import MorphCloudClient

logger = logging.getLogger("morph-tests")

# Mark all tests as asyncio tests by default
pytestmark = pytest.mark.asyncio


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
    return os.environ.get("MORPH_BASE_URL", "https://api.morph.so")


@pytest_asyncio.fixture
async def client(api_key, base_url):
    """Create a MorphCloudClient."""
    logger.info(f"Creating client with base_url: {base_url}")
    client = MorphCloudClient(api_key=api_key, base_url=base_url)
    return client


@pytest_asyncio.fixture
async def base_image(client):
    """Get a base image to use for tests."""
    logger.info("Fetching available images")
    images = await client.images.alist()
    logger.info(f"Found {len(images)} images")
    
    # Find Ubuntu image
    ubuntu_image = None
    for image in images:
        logger.info(f"Image: {image.name} ({image.id})")
        if "ubuntu" in image.name.lower():
            ubuntu_image = image
            break
    
    if not ubuntu_image:
        pytest.fail("No Ubuntu image found")
    
    logger.info(f"Using base image: {ubuntu_image.name} ({ubuntu_image.id})")
    return ubuntu_image


# Unit test fixtures (mocks)
@pytest.fixture
def mock_client():
    """Mock MorphCloudClient for unit tests."""
    with patch('morphcloud.api.MorphCloudClient') as mock:
        # Configure mock to have basic structure
        mock_instance = Mock()
        mock_instance.instances = Mock()
        mock_instance.snapshots = Mock()
        mock_instance.images = Mock()
        mock.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_instance():
    """Mock Instance for unit tests."""
    with patch('morphcloud.api.Instance') as mock:
        mock_instance = Mock()
        # Configure common methods
        mock_instance.aexec = Mock()
        mock_instance.assh_key_rotate = Mock()
        mock_instance.assh_key = Mock()
        mock_instance.astop = Mock()
        mock_instance.awake = Mock()
        mock.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_api_response():
    """Standard mock API response for unit tests."""
    return {
        "status": "success",
        "data": {
            "id": "test-123",
            "created_at": "2024-01-01T00:00:00Z"
        }
    }


@pytest.fixture  
def mock_ssh_key_data():
    """Mock SSH key data for unit tests."""
    return {
        "id": "test-key-123",
        "public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...",
        "created_at": "2024-01-01T00:00:00Z"
    }