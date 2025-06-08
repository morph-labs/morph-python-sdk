"""
Tests using session-scoped fixtures to avoid event loop issues.
"""
import pytest
import logging
import uuid

logger = logging.getLogger("morph-tests")

# Mark all tests as asyncio tests
pytestmark = pytest.mark.asyncio

async def test_instance_command(session_instance):
    """Test executing a command on the shared instance."""
    logger.info(f"Testing command execution on instance {session_instance.id}")
    
    # Execute a simple command
    result = await session_instance.aexec("echo 'hello world'")
    
    # Verify command output
    assert result.exit_code == 0, "Command should execute successfully"
    assert "hello world" in result.stdout, "Command output should contain 'hello world'"
    
    logger.info(f"Command executed successfully: {result.stdout}")

async def test_file_operations(session_instance, create_test_file):
    """Test file operations using the test file created in the fixture."""
    file_info = create_test_file
    logger.info(f"Testing file operations on {file_info['path']}")
    
    # Read the file content
    result = await session_instance.aexec(f"cat {file_info['path']}")
    
    # Verify file content
    assert result.exit_code == 0, "File should exist and be readable"
    assert file_info['content'] in result.stdout, "File content should match what was written"
    
    # Append to the file
    append_text = f"additional-content-{uuid.uuid4()}"
    append_result = await session_instance.aexec(f"echo '{append_text}' >> {file_info['path']}")
    assert append_result.exit_code == 0, "Should be able to append to file"
    
    # Verify appended content
    read_result = await session_instance.aexec(f"cat {file_info['path']}")
    assert read_result.exit_code == 0
    assert file_info['content'] in read_result.stdout, "Original content should still be there"
    assert append_text in read_result.stdout, "Appended content should be in the file"
    
    logger.info("File operations completed successfully")

async def test_metadata(session_instance, morph_client):
    """Test setting and retrieving instance metadata."""
    # Set metadata
    test_key = f"test-key-{uuid.uuid4()}"
    test_value = f"test-value-{uuid.uuid4()}"
    test_metadata = {test_key: test_value}
    
    logger.info(f"Setting metadata on instance {session_instance.id}")
    await session_instance.aset_metadata(test_metadata)
    
    # Verify metadata was set
    assert session_instance.metadata.get(test_key) == test_value
    
    # List instances by metadata and verify our instance is found
    logger.info(f"Listing instances with metadata filter: {test_key}={test_value}")
    filter_metadata = {test_key: test_value}
    instances = await morph_client.instances.alist(metadata=filter_metadata)
    
    # Verify instance is in the filtered list
    assert any(i.id == session_instance.id for i in instances), "Instance should be found when filtering by its metadata"
    
    logger.info("Metadata operations completed successfully")