"""
Shared configuration and fixtures for API tests.

This module provides pytest configuration options and fixtures for comprehensive
API endpoint testing across all MorphCloud machine configurations.
"""
import pytest
import pytest_asyncio
import os
import logging
from morphcloud.api import MorphCloudClient

logger = logging.getLogger("morph-api-tests")

# Mark all tests as asyncio tests
pytestmark = pytest.mark.asyncio

# Machine size configurations for testing
MACHINE_SIZES = {
    "nano": {"vcpus": 1, "memory": 1024, "disk_size": 8*1024},
    "micro": {"vcpus": 1, "memory": 2048, "disk_size": 16*1024},
    "small": {"vcpus": 1, "memory": 4*1024, "disk_size": 16*1024},
    "medium": {"vcpus": 2, "memory": 8*1024, "disk_size": 32*1024},
    "large": {"vcpus": 4, "memory": 16*1024, "disk_size": 64*1024},
    "xlarge": {"vcpus": 8, "memory": 32*1024, "disk_size": 128*1024}
}

# Base image types
BASE_IMAGE_TYPES = ["minimal", "sandbox"]

# All 12 configuration combinations (2 base images × 6 sizes)
ALL_CONFIGS = [
    (base_image, size_name, size_config)
    for base_image in BASE_IMAGE_TYPES
    for size_name, size_config in MACHINE_SIZES.items()
]


def pytest_addoption(parser):
    """Add command-line options for API tests."""
    parser.addoption(
        "--base-image",
        action="store",
        default=None,
        help="Specify which base image to use: 'minimal', 'sandbox', or 'auto' (default: auto)"
    )
    parser.addoption(
        "--test-both-images",
        action="store_true",
        default=False,
        help="Run tests with both morphvm-minimal and morphvm-sandbox images"
    )


def pytest_configure(config):
    """Configure pytest settings."""
    config.option.asyncio_default_fixture_loop_scope = "function"


def pytest_generate_tests(metafunc):
    """Generate parameterized tests based on command-line options."""
    if "base_image_type" in metafunc.fixturenames:
        if metafunc.config.getoption("--test-both-images"):
            # Parameterize to run with both images
            metafunc.parametrize("base_image_type", BASE_IMAGE_TYPES)
        else:
            # Run with specified image or auto
            image_type = metafunc.config.getoption("--base-image") or "auto"
            metafunc.parametrize("base_image_type", [image_type])
    
    # Parameterize tests that need all configuration combinations
    if "machine_config" in metafunc.fixturenames:
        metafunc.parametrize("machine_config", ALL_CONFIGS, 
                            ids=[f"{base}-{size}" for base, size, _ in ALL_CONFIGS])


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
    logger.info("Created MorphCloud client for API tests")
    return client


async def _select_image_by_type(client, image_type):
    """Select an image based on the specified type."""
    images = await client.images.alist()
    if not images:
        pytest.fail("No images available")
    
    if image_type == "minimal":
        # Look for morphvm-minimal image
        image = next((img for img in images if "morphvm-minimal" in img.id.lower()), None)
        if not image:
            pytest.fail("morphvm-minimal image not available. Available images: " + 
                       ", ".join([img.id for img in images]))
    elif image_type == "sandbox":
        # Look for morphvm-sandbox image
        image = next((img for img in images if "morphvm-sandbox" in img.id.lower()), None)
        if not image:
            pytest.fail("morphvm-sandbox image not available. Available images: " + 
                       ", ".join([img.id for img in images]))
    elif image_type == "auto":
        # Original behavior: prefer ubuntu, fallback to first available
        image = next((img for img in images if "ubuntu" in img.id.lower()), images[0])
    else:
        pytest.fail(f"Unknown image type: {image_type}. Use 'minimal', 'sandbox', or 'auto'")
    
    logger.info(f"Using base image: {image.id}")
    return image


@pytest_asyncio.fixture
async def base_image(client, request):
    """Get a base image to use for tests."""
    # Check if this is a parameterized test with base_image_type
    if hasattr(request, 'param'):
        image_type = request.param
    elif "base_image_type" in request.fixturenames:
        # Get from the base_image_type fixture
        image_type = request.getfixturevalue("base_image_type")
    else:
        # Get from command line or default to auto
        image_type = request.config.getoption("--base-image") or "auto"
    
    return await _select_image_by_type(client, image_type)


@pytest.fixture
def base_image_type(request):
    """Fixture to provide the base image type for parameterized tests."""
    return request.param if hasattr(request, 'param') else (
        request.config.getoption("--base-image") or "auto"
    )


@pytest_asyncio.fixture
async def minimal_image(client):
    """Get the morphvm-minimal base image."""
    return await _select_image_by_type(client, "minimal")


@pytest_asyncio.fixture  
async def sandbox_image(client):
    """Get the morphvm-sandbox base image."""
    return await _select_image_by_type(client, "sandbox")


@pytest.fixture
def machine_sizes():
    """Provide machine size configurations."""
    return MACHINE_SIZES


@pytest.fixture
def all_configs():
    """Provide all 12 machine configurations."""
    return ALL_CONFIGS


def adjust_config_for_image(base_image_type: str, size_config: dict) -> dict:
    """
    Adjust configuration based on base image requirements.
    
    Args:
        base_image_type: "minimal" or "sandbox" 
        size_config: Base size configuration
        
    Returns:
        Adjusted configuration with appropriate disk size
    """
    adjusted_config = size_config.copy()
    
    # Sandbox images need minimum 10GB disk space
    if base_image_type == "sandbox":
        min_sandbox_disk = 10 * 1024  # 10GB
        if adjusted_config["disk_size"] < min_sandbox_disk:
            adjusted_config["disk_size"] = min_sandbox_disk
    
    return adjusted_config


async def get_image_by_type(client, image_type: str):
    """Get base image by type (minimal or sandbox)."""
    images = await client.images.alist()
    
    if image_type == "minimal":
        image = next((img for img in images if "morphvm-minimal" in img.id.lower()), None)
        if not image:
            pytest.fail(f"morphvm-minimal image not available. Available: {[img.id for img in images]}")
    elif image_type == "sandbox":
        image = next((img for img in images if "morphvm-sandbox" in img.id.lower()), None)
        if not image:
            pytest.fail(f"morphvm-sandbox image not available. Available: {[img.id for img in images]}")
    else:
        pytest.fail(f"Unknown image type: {image_type}")
    
    return image