"""
Function-scoped tests for instance branching in MorphCloud SDK.
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


async def test_instance_branching(client, base_image):
    """Test instance branching."""
    logger.info("Testing instance branching")
    
    # Resources to clean up
    resources = {
        'snapshots': [],
        'instances': []
    }
    
    try:
        # Create initial snapshot
        logger.info("Creating initial snapshot")
        initial_snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=512,
            disk_size=8192
        )
        logger.info(f"Created initial snapshot: {initial_snapshot.id}")
        resources['snapshots'].append(initial_snapshot)
        
        # Start initial instance
        logger.info("Starting initial instance")
        initial_instance = await client.instances.astart(initial_snapshot.id)
        logger.info(f"Created initial instance: {initial_instance.id}")
        resources['instances'].append(initial_instance)
        
        # Wait for instance to be ready
        logger.info(f"Waiting for instance {initial_instance.id} to be ready")
        await initial_instance.await_until_ready(timeout=300)
        logger.info(f"Instance {initial_instance.id} is ready")
        
        # Create a test file on the instance
        test_file = f"/root/test-file-{uuid.uuid4()}.txt"
        test_content = f"test-content-{uuid.uuid4()}"
        
        # Write test file
        logger.info(f"Creating test file {test_file}")
        result = await initial_instance.aexec(f"echo '{test_content}' > {test_file}")
        assert result.exit_code == 0, "Failed to create test file"
        
        # Verify file exists
        result = await initial_instance.aexec(f"cat {test_file}")
        assert result.exit_code == 0, "Failed to read test file"
        assert test_content in result.stdout, "Test file content does not match"
        
        # Create 2 branches from the instance
        branch_count = 2
        logger.info(f"Creating {branch_count} branches from instance {initial_instance.id}")
        branch_snapshot, branch_instances = await initial_instance.abranch(branch_count)
        
        # Add to resources for cleanup
        resources['snapshots'].append(branch_snapshot)
        resources['instances'].extend(branch_instances)
        
        logger.info(f"Created branch snapshot: {branch_snapshot.id}")
        for i, instance in enumerate(branch_instances):
            logger.info(f"Created branch instance {i+1}: {instance.id}")
        
        # Verify branch snapshot properties
        assert branch_snapshot.id.startswith("snapshot_"), "Branch snapshot ID should start with 'snapshot_'"
        
        # Verify the number of branch instances
        assert len(branch_instances) == branch_count, f"Expected {branch_count} branch instances"
        
        # Verify each branch instance
        for i, branch_instance in enumerate(branch_instances):
            logger.info(f"Verifying branch instance {i+1}: {branch_instance.id}")
            
            # Verify instance properties
            assert branch_instance.id.startswith("morphvm_"), "Branch instance ID should start with 'morphvm_'"
            assert branch_instance.refs.snapshot_id == branch_snapshot.id, "Branch instance should be created from the branch snapshot"
            
            # Verify the test file persisted in the branch
            result = await branch_instance.aexec(f"cat {test_file}")
            assert result.exit_code == 0, f"Failed to read test file on branch instance {i+1}"
            assert test_content in result.stdout, f"Test file content does not match on branch instance {i+1}"
            
            # Create a unique file on each branch to verify they're independent
            branch_file = f"/root/branch-file-{i+1}-{uuid.uuid4()}.txt"
            branch_content = f"branch-content-{i+1}-{uuid.uuid4()}"
            
            result = await branch_instance.aexec(f"echo '{branch_content}' > {branch_file}")
            assert result.exit_code == 0, f"Failed to create branch file on branch instance {i+1}"
            
            # Verify branch file
            result = await branch_instance.aexec(f"cat {branch_file}")
            assert result.exit_code == 0, f"Failed to read branch file on branch instance {i+1}"
            assert branch_content in result.stdout, f"Branch file content does not match on branch instance {i+1}"
        
        # Verify branches are independent by checking that a file created on one branch
        # doesn't exist on the other branch
        for i, branch_instance in enumerate(branch_instances):
            other_idx = (i + 1) % branch_count
            other_branch_file = f"/root/branch-file-{other_idx+1}-{uuid.uuid4()}.txt"
            
            # This should fail because the file should only exist on the other branch
            result = await branch_instance.aexec(f"cat {other_branch_file}")
            assert result.exit_code != 0, f"Branch instance {i+1} should not have a file from branch instance {other_idx+1}"
        
        logger.info("Instance branching test completed successfully")
        
    finally:
        # Clean up resources in reverse order
        for instance in reversed(resources['instances']):
            try:
                logger.info(f"Stopping instance {instance.id}")
                await instance.astop()
                logger.info(f"Instance stopped")
            except Exception as e:
                logger.error(f"Error stopping instance: {e}")
        
        for snapshot in reversed(resources['snapshots']):
            try:
                logger.info(f"Deleting snapshot {snapshot.id}")
                await snapshot.adelete()
                logger.info(f"Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")


async def test_parallel_operations(client, base_image):
    """Test running multiple operations in parallel."""
    logger.info("Testing parallel operations")
    
    # Number of instances to create
    instance_count = 3
    
    # Resources to clean up
    resources = {
        'snapshots': [],
        'instances': []
    }
    
    try:
        # Create snapshot
        logger.info("Creating snapshot")
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=512,
            disk_size=8192
        )
        logger.info(f"Created snapshot: {snapshot.id}")
        resources['snapshots'].append(snapshot)
        
        # Start multiple instances in parallel
        logger.info(f"Starting {instance_count} instances in parallel")
        import asyncio
        
        async def start_instance():
            instance = await client.instances.astart(snapshot.id)
            logger.info(f"Created instance: {instance.id}")
            await instance.await_until_ready(timeout=300)
            logger.info(f"Instance {instance.id} is ready")
            return instance
        
        # Create instances in parallel
        tasks = [start_instance() for _ in range(instance_count)]
        instances = await asyncio.gather(*tasks)
        resources['instances'].extend(instances)
        
        # Execute commands on all instances in parallel
        async def run_command(instance):
            # Run a simple command
            result = await instance.aexec("echo 'hello world'")
            assert result.exit_code == 0, "Command execution failed"
            assert "hello world" in result.stdout, "Command output does not match"
            return result
        
        # Run commands in parallel
        logger.info("Running commands on all instances in parallel")
        command_tasks = [run_command(instance) for instance in instances]
        results = await asyncio.gather(*command_tasks)
        
        # Verify all commands succeeded
        assert len(results) == instance_count, f"Expected {instance_count} command results"
        for i, result in enumerate(results):
            assert result.exit_code == 0, f"Command on instance {i+1} failed"
        
        logger.info("Parallel operations test completed successfully")
        
    finally:
        # Clean up resources in reverse order
        for instance in reversed(resources['instances']):
            try:
                logger.info(f"Stopping instance {instance.id}")
                await instance.astop()
                logger.info(f"Instance stopped")
            except Exception as e:
                logger.error(f"Error stopping instance: {e}")
        
        for snapshot in reversed(resources['snapshots']):
            try:
                logger.info(f"Deleting snapshot {snapshot.id}")
                await snapshot.adelete()
                logger.info(f"Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")