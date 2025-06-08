"""
Tests for basic instance lifecycle operations.
"""
import pytest
import logging
import asyncio

logger = logging.getLogger("morph-tests")

@pytest.mark.asyncio
async def test_instance_startup(test_instance):
    """Test that an instance starts and is accessible."""
    # The test_instance fixture already waits for the instance to be ready
    # and registers it for cleanup, so we just need to verify it's working
    
    # Check instance properties
    assert test_instance.id.startswith("instance_")
    assert test_instance.status == "running"
    
    # Test basic command execution
    result = await test_instance.aexec("echo 'hello world'")
    assert result.exit_code == 0
    assert "hello world" in result.stdout
    assert not result.stderr


@pytest.mark.asyncio
async def test_command_execution(test_instance):
    """Test command execution on an instance."""
    # Test simple command
    result = await test_instance.aexec("uname -a")
    assert result.exit_code == 0
    assert len(result.stdout) > 0
    
    # Test command with arguments as list
    result = await test_instance.aexec(["ls", "-la", "/"])
    assert result.exit_code == 0
    assert "root" in result.stdout
    
    # Test command with error
    result = await test_instance.aexec("ls /nonexistent")
    assert result.exit_code != 0
    assert "No such file or directory" in result.stderr


@pytest.mark.asyncio
async def test_snapshot_creation(test_instance, resource_registry):
    """Test creating a snapshot from a running instance."""
    # Create a file to verify it persists in the snapshot
    test_file = "/root/test_file.txt"
    test_content = "This is a test file"
    
    # Write file
    result = await test_instance.aexec(f"echo '{test_content}' > {test_file}")
    assert result.exit_code == 0
    
    # Verify file exists
    result = await test_instance.aexec(f"cat {test_file}")
    assert result.exit_code == 0
    assert test_content in result.stdout
    
    # Create snapshot
    logger.info(f"Creating snapshot from instance {test_instance.id}")
    snapshot = await test_instance.asnapshot()
    logger.info(f"Created snapshot: {snapshot.id}")
    
    # Register snapshot for cleanup
    resource_registry.register_snapshot(snapshot)
    
    # Start new instance from snapshot
    logger.info(f"Starting new instance from snapshot {snapshot.id}")
    new_instance = await test_instance.client.instances.astart(snapshot.id)
    logger.info(f"Started new instance: {new_instance.id}")
    
    # Register new instance for cleanup
    resource_registry.register_instance(new_instance)
    
    # Wait for instance to be ready
    logger.info(f"Waiting for instance {new_instance.id} to be ready")
    await new_instance.await_until_ready(timeout=300)
    logger.info(f"Instance {new_instance.id} is ready")
    
    # Verify file persisted in the snapshot
    result = await new_instance.aexec(f"cat {test_file}")
    assert result.exit_code == 0
    assert test_content in result.stdout


@pytest.mark.asyncio
async def test_instance_metadata(test_instance, morph_client):
    """Test setting and retrieving instance metadata."""
    # Set metadata
    test_metadata = {"test_key": "test_value", "environment": "testing"}
    await test_instance.aset_metadata(test_metadata)
    
    # Verify metadata was set
    assert test_instance.metadata.get("test_key") == "test_value"
    assert test_instance.metadata.get("environment") == "testing"
    
    # List instances by metadata and verify our instance is found
    instances = await morph_client.instances.alist(metadata={"environment": "testing"})
    assert any(i.id == test_instance.id for i in instances)