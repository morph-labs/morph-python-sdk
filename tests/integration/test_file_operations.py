"""
Function-scoped tests for file operations in MorphCloud SDK.
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


async def test_basic_file_operations(client, base_image):
    """Test basic file operations on an instance."""
    logger.info("Testing basic file operations")
    
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
        
        # Create a test file
        test_file = f"/tmp/test-{uuid.uuid4()}.txt"
        test_content = f"test-content-{uuid.uuid4()}"
        
        # Write file
        logger.info(f"Writing test file: {test_file}")
        write_result = await instance.aexec(f"echo '{test_content}' > {test_file}")
        assert write_result.exit_code == 0, "Should be able to write file"
        
        # Read the file content
        logger.info(f"Reading test file: {test_file}")
        read_result = await instance.aexec(f"cat {test_file}")
        
        # Verify file content
        assert read_result.exit_code == 0, "File should exist and be readable"
        assert test_content in read_result.stdout, "File content should match what was written"
        
        # Append to the file
        append_text = f"additional-content-{uuid.uuid4()}"
        logger.info(f"Appending to test file: {test_file}")
        append_result = await instance.aexec(f"echo '{append_text}' >> {test_file}")
        assert append_result.exit_code == 0, "Should be able to append to file"
        
        # Verify appended content
        logger.info(f"Verifying appended content in: {test_file}")
        read_result2 = await instance.aexec(f"cat {test_file}")
        assert read_result2.exit_code == 0
        assert test_content in read_result2.stdout, "Original content should still be there"
        assert append_text in read_result2.stdout, "Appended content should be in the file"
        
        logger.info("Basic file operations completed successfully")
        
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


async def test_file_permissions(client, base_image):
    """Test file permissions on an instance."""
    logger.info("Testing file permissions")
    
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
        
        # Create a test file
        test_file = f"/tmp/test-perms-{uuid.uuid4()}.txt"
        test_content = f"test-content-{uuid.uuid4()}"
        
        # Write file
        logger.info(f"Creating test file: {test_file}")
        write_result = await instance.aexec(f"echo '{test_content}' > {test_file}")
        assert write_result.exit_code == 0, "Should be able to write file"
        
        # Check default permissions
        logger.info(f"Checking default permissions on: {test_file}")
        perms_result = await instance.aexec(f"ls -l {test_file}")
        assert perms_result.exit_code == 0, "Should be able to get file permissions"
        
        # Change file permissions
        logger.info(f"Changing permissions on: {test_file}")
        chmod_result = await instance.aexec(f"chmod 600 {test_file}")
        assert chmod_result.exit_code == 0, "Should be able to change file permissions"
        
        # Verify new permissions
        logger.info(f"Verifying new permissions on: {test_file}")
        new_perms_result = await instance.aexec(f"ls -l {test_file}")
        assert new_perms_result.exit_code == 0, "Should be able to get file permissions"
        assert "-rw-------" in new_perms_result.stdout, "File should have 600 permissions"
        
        logger.info("File permissions test completed successfully")
        
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


async def test_directory_operations(client, base_image):
    """Test directory operations on an instance."""
    logger.info("Testing directory operations")
    
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
        
        # Create a test directory
        test_dir = f"/tmp/test-dir-{uuid.uuid4()}"
        
        # Create directory
        logger.info(f"Creating test directory: {test_dir}")
        mkdir_result = await instance.aexec(f"mkdir -p {test_dir}")
        assert mkdir_result.exit_code == 0, "Should be able to create directory"
        
        # Verify directory exists
        logger.info(f"Verifying directory exists: {test_dir}")
        ls_result = await instance.aexec(f"ls -ld {test_dir}")
        assert ls_result.exit_code == 0, "Directory should exist"
        assert "d" in ls_result.stdout, "Should be a directory"
        
        # Create files in the directory
        file1 = f"{test_dir}/file1.txt"
        file2 = f"{test_dir}/file2.txt"
        
        logger.info(f"Creating files in directory: {file1}, {file2}")
        await instance.aexec(f"echo 'content1' > {file1}")
        await instance.aexec(f"echo 'content2' > {file2}")
        
        # List files in directory
        logger.info(f"Listing files in directory: {test_dir}")
        ls_dir_result = await instance.aexec(f"ls -la {test_dir}")
        assert ls_dir_result.exit_code == 0, "Should be able to list directory"
        assert "file1.txt" in ls_dir_result.stdout, "file1.txt should be in directory"
        assert "file2.txt" in ls_dir_result.stdout, "file2.txt should be in directory"
        
        # Remove directory
        logger.info(f"Removing directory: {test_dir}")
        rm_result = await instance.aexec(f"rm -rf {test_dir}")
        assert rm_result.exit_code == 0, "Should be able to remove directory"
        
        # Verify directory is gone
        logger.info(f"Verifying directory is gone: {test_dir}")
        ls_gone_result = await instance.aexec(f"ls -ld {test_dir} 2>&1 || echo 'Not found'")
        assert "Not found" in ls_gone_result.stdout or "No such file or directory" in ls_gone_result.stderr, "Directory should be gone"
        
        logger.info("Directory operations test completed successfully")
        
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