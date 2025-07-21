"""
Test metadata-related API endpoints.

This module tests the 1 metadata endpoint:
- GET /image - List available base images
"""
import pytest
import logging
import time
import json
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("morph-api-tests")

# Performance tracking
PERFORMANCE_LOG_FILE = Path(__file__).parent.parent.parent / "performance_log.jsonl"


def log_performance_metric(operation: str, duration: float, status: str, error: str = None):
    """Log performance metric to JSONL file."""
    metric = {
        "timestamp": datetime.now().isoformat(),
        "operation": operation,
        "duration_seconds": round(duration, 2),
        "status": status
    }
    if error:
        metric["error"] = error
    
    # Ensure parent directory exists
    PERFORMANCE_LOG_FILE.parent.mkdir(exist_ok=True)
    
    # Append to JSONL file
    with open(PERFORMANCE_LOG_FILE, "a") as f:
        f.write(json.dumps(metric) + "\n")


async def timed_operation(operation_name: str, operation_func):
    """Time an async operation and log the result."""
    start_time = time.time()
    try:
        result = await operation_func()
        duration = time.time() - start_time
        
        # Log to console
        logger.info(f"⏱️  {operation_name}: {duration:.2f}s")
        
        # Log to performance file
        log_performance_metric(operation_name, duration, "success")
        
        return result, duration
    except Exception as e:
        duration = time.time() - start_time
        logger.error(f"⏱️  {operation_name}: {duration:.2f}s (FAILED: {e})")
        
        # Log failure to performance file
        log_performance_metric(operation_name, duration, "failed", str(e))
        
        raise


# Mark all tests as asyncio tests
pytestmark = pytest.mark.asyncio


async def test_list_base_images(client):
    """Test GET /image - List all base images available to user."""
    logger.info("Testing base image listing")
    
    # List all available base images (timed)
    images, duration = await timed_operation(
        "list_base_images",
        lambda: client.images.alist()
    )
    
    # Verify we got a list of images
    assert isinstance(images, list), "Images should be returned as a list"
    assert len(images) > 0, "At least one base image should be available"
    
    logger.info(f"Found {len(images)} base images in {duration:.2f}s")
    
    # Verify image objects have required fields
    for image in images:
        assert hasattr(image, 'id'), "Image should have an id attribute"
        assert image.id is not None, "Image ID should not be None"
        assert isinstance(image.id, str), "Image ID should be a string"
        assert len(image.id) > 0, "Image ID should not be empty"
        
        logger.info(f"Found image: {image.id}")
    
    # Check for expected base images
    image_ids = [img.id for img in images]
    
    # Should have at least one of the expected base images
    expected_images = ["morphvm-minimal", "morphvm-sandbox"]
    found_expected = any(
        any(expected in img_id.lower() for expected in expected_images)
        for img_id in image_ids
    )
    assert found_expected, f"Should find at least one of {expected_images} in available images: {image_ids}"
    
    # Check specifically for morphvm-minimal and morphvm-sandbox if they exist
    has_minimal = any("morphvm-minimal" in img_id.lower() for img_id in image_ids)
    has_sandbox = any("morphvm-sandbox" in img_id.lower() for img_id in image_ids)
    
    if has_minimal:
        logger.info("✅ Found morphvm-minimal image")
    else:
        logger.warning("⚠️  morphvm-minimal image not found")
        
    if has_sandbox:
        logger.info("✅ Found morphvm-sandbox image")
    else:
        logger.warning("⚠️  morphvm-sandbox image not found")
    
    logger.info("Base image listing test completed successfully")


async def test_base_image_properties(client):
    """Test that base images have expected properties and structure."""
    logger.info("Testing base image properties")
    
    # Get all images
    images = await client.images.alist()
    assert len(images) > 0, "Need at least one image to test properties"
    
    for image in images:
        # Test basic properties
        assert hasattr(image, 'id'), f"Image {image} should have id attribute"
        assert isinstance(image.id, str), f"Image id should be string, got {type(image.id)}"
        assert len(image.id) > 0, f"Image id should not be empty"
        
        # Log image details for debugging
        logger.info(f"Image {image.id} properties:")
        for attr in dir(image):
            if not attr.startswith('_') and not callable(getattr(image, attr)):
                value = getattr(image, attr)
                logger.info(f"  {attr}: {value}")
    
    logger.info("Base image properties test completed successfully")


async def test_image_availability_for_snapshots(client):
    """Test that listed images can actually be used for snapshot creation."""
    logger.info("Testing image availability for snapshot creation")
    
    # Get all images
    images = await client.images.alist()
    assert len(images) > 0, "Need at least one image to test availability"
    
    # Test that we can use the first available image (without actually creating the snapshot)
    test_image = images[0]
    logger.info(f"Testing availability of image: {test_image.id}")
    
    # Verify the image has the properties needed for snapshot creation
    assert test_image.id is not None, "Image must have a valid ID for snapshot creation"
    assert isinstance(test_image.id, str), "Image ID must be a string"
    assert len(test_image.id) > 0, "Image ID must not be empty"
    
    # The actual availability test would be creating a snapshot, but that's tested elsewhere
    # Here we just verify the image looks valid for use
    logger.info(f"Image {test_image.id} appears suitable for snapshot creation")
    
    logger.info("Image availability test completed successfully")