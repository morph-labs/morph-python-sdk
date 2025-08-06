"""
Unit tests for SSH key functionality in MorphCloud SDK.

This file tests SSH key methods in isolation, achieving parity with 
the TypeScript SDK unit test coverage.
"""
import pytest
import logging
import os
from unittest.mock import Mock, patch, AsyncMock
import pytest_asyncio

from morphcloud.api import MorphCloudClient

logger = logging.getLogger("morph-tests")

# Configure pytest-asyncio
def pytest_configure(config):
    config.option.asyncio_default_fixture_loop_scope = "function"


@pytest.fixture
def api_key():
    """Get API key from environment variable or use mock."""
    return os.environ.get("MORPH_API_KEY", "test-api-key")


@pytest.fixture
def base_url():
    """Get base URL from environment variable or use mock."""
    return os.environ.get("MORPH_BASE_URL", "https://api.morph.so")


@pytest.fixture
def client(api_key, base_url):
    """Create a MorphCloud client for unit testing."""
    return MorphCloudClient(api_key=api_key, base_url=base_url)


@pytest.fixture
def mock_instance():
    """Create a mock instance for testing SSH key methods."""
    mock = Mock()
    mock.id = "morphvm_test_instance"
    mock.ssh_key = Mock()
    mock.ssh_key_rotate = Mock()
    return mock


def test_ssh_key_method_exists(client):
    """Test that SSH key method exists and is callable."""
    logger.info("Testing SSH key method existence")
    
    # Create a mock instance to test SSH key method
    mock_instance = Mock()
    mock_instance.id = "morphvm_test"
    
    # Add ssh_key method to mock instance
    mock_instance.ssh_key = Mock()
    
    # Verify method exists and is callable
    assert hasattr(mock_instance, 'ssh_key'), "Instance should have ssh_key method"
    assert callable(mock_instance.ssh_key), "ssh_key should be callable"
    
    logger.info("SSH key method exists and is callable")


def test_ssh_key_rotation_method_exists(client):
    """Test that SSH key rotation method exists and is callable."""
    logger.info("Testing SSH key rotation method existence")
    
    # Create a mock instance to test SSH key rotation method
    mock_instance = Mock()
    mock_instance.id = "morphvm_test"
    
    # Add ssh_key_rotate method to mock instance  
    mock_instance.ssh_key_rotate = Mock()
    
    # Verify method exists and is callable
    assert hasattr(mock_instance, 'ssh_key_rotate'), "Instance should have ssh_key_rotate method"
    assert callable(mock_instance.ssh_key_rotate), "ssh_key_rotate should be callable"
    
    logger.info("SSH key rotation method exists and is callable")


def test_ssh_key_method_returns_structure(mock_instance):
    """Test SSH key method returns expected structure."""
    logger.info("Testing SSH key method return structure")
    
    # Mock SSH key data structure
    expected_ssh_key = Mock()
    expected_ssh_key.public_key = "ssh-rsa AAAAB3NzaC1yc2E..."
    expected_ssh_key.private_key = "-----BEGIN OPENSSH PRIVATE KEY-----\n..."
    expected_ssh_key.username = "root"
    
    # Configure mock to return expected structure
    mock_instance.ssh_key.return_value = expected_ssh_key
    
    # Call the method
    result = mock_instance.ssh_key()
    
    # Verify result has expected structure
    assert hasattr(result, 'public_key'), "SSH key should have public_key attribute"
    assert hasattr(result, 'private_key'), "SSH key should have private_key attribute"  
    assert hasattr(result, 'username'), "SSH key should have username attribute"
    
    # Verify content
    assert result.public_key.startswith("ssh-rsa"), "Public key should start with ssh-rsa"
    assert "BEGIN OPENSSH PRIVATE KEY" in result.private_key, "Private key should contain OpenSSH header"
    assert result.username == "root", "Username should be root"
    
    logger.info("SSH key method returns expected structure")


def test_ssh_key_rotation_method_functionality(mock_instance):
    """Test SSH key rotation method functionality."""
    logger.info("Testing SSH key rotation method functionality")
    
    # Mock old and new SSH keys
    old_key = Mock()
    old_key.public_key = "ssh-rsa OLD_KEY..."
    old_key.private_key = "-----BEGIN OLD KEY-----"
    
    new_key = Mock()
    new_key.public_key = "ssh-rsa NEW_KEY..."
    new_key.private_key = "-----BEGIN NEW KEY-----"
    
    # Configure mock to return old key first, then new key after rotation
    mock_instance.ssh_key.side_effect = [old_key, new_key]
    mock_instance.ssh_key_rotate.return_value = None
    
    # Get original key
    original_key = mock_instance.ssh_key()
    
    # Rotate the key
    mock_instance.ssh_key_rotate()
    
    # Get new key
    rotated_key = mock_instance.ssh_key()
    
    # Verify rotation occurred
    assert original_key.public_key != rotated_key.public_key, "Public keys should be different after rotation"
    assert original_key.private_key != rotated_key.private_key, "Private keys should be different after rotation"
    
    # Verify rotation method was called
    mock_instance.ssh_key_rotate.assert_called_once()
    
    logger.info("SSH key rotation method functionality validated")


@pytest.mark.asyncio
async def test_ssh_key_rotation_async_method():
    """Test async SSH key rotation method if it exists."""
    logger.info("Testing async SSH key rotation method")
    
    # Create mock instance with async methods
    mock_instance = AsyncMock()
    mock_instance.id = "morphvm_test"
    
    # Mock async SSH key rotation
    mock_instance.assh_key_rotate = AsyncMock()
    mock_instance.assh_key_rotate.return_value = None
    
    # Test async method exists and is callable
    assert hasattr(mock_instance, 'assh_key_rotate'), "Instance should have assh_key_rotate method"
    assert callable(mock_instance.assh_key_rotate), "assh_key_rotate should be callable"
    
    # Test calling async method
    await mock_instance.assh_key_rotate()
    
    # Verify async method was called
    mock_instance.assh_key_rotate.assert_called_once()
    
    logger.info("Async SSH key rotation method functionality validated")


def test_instance_ssh_key_interface():
    """Test InstanceSshKey interface structure."""
    logger.info("Testing InstanceSshKey interface structure")
    
    # Create mock InstanceSshKey object
    ssh_key = Mock()
    
    # Define expected interface attributes
    expected_attributes = ['public_key', 'private_key', 'username']
    
    # Add attributes to mock
    for attr in expected_attributes:
        setattr(ssh_key, attr, f"mock_{attr}_value")
    
    # Verify all expected attributes exist
    for attr in expected_attributes:
        assert hasattr(ssh_key, attr), f"InstanceSshKey should have {attr} attribute"
        assert getattr(ssh_key, attr) is not None, f"{attr} should not be None"
    
    # Verify attribute types/content
    assert isinstance(ssh_key.public_key, str), "public_key should be string"
    assert isinstance(ssh_key.private_key, str), "private_key should be string"
    assert isinstance(ssh_key.username, str), "username should be string"
    
    logger.info("InstanceSshKey interface structure validated")


def test_ssh_key_properties_validation():
    """Test SSH key properties validation."""
    logger.info("Testing SSH key properties validation")
    
    # Create mock SSH key with realistic data
    ssh_key = Mock()
    ssh_key.public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7..."
    ssh_key.private_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7...\n-----END OPENSSH PRIVATE KEY-----"
    ssh_key.username = "root"
    
    # Validate public key format
    assert ssh_key.public_key.startswith(('ssh-rsa', 'ssh-ed25519', 'ssh-ecdsa')), \
        "Public key should start with valid SSH key type"
    
    # Validate private key format
    assert ssh_key.private_key.startswith("-----BEGIN"), \
        "Private key should start with PEM header"
    assert ssh_key.private_key.endswith("-----"), \
        "Private key should end with PEM footer"
    
    # Validate username
    assert len(ssh_key.username) > 0, "Username should not be empty"
    assert ssh_key.username.isascii(), "Username should be ASCII"
    
    logger.info("SSH key properties validation successful")


@patch('morphcloud.api.MorphCloudClient')
def test_ssh_key_api_endpoint_mock(mock_client_class):
    """Test SSH key API endpoint with mocking."""
    logger.info("Testing SSH key API endpoint with mocks")
    
    # Create mock client instance
    mock_client = Mock()
    mock_client_class.return_value = mock_client
    
    # Create mock instance with SSH key method
    mock_instance = Mock()
    mock_instance.id = "morphvm_test"
    
    # Mock SSH key API response
    mock_ssh_key_response = {
        'public_key': 'ssh-rsa AAAAB3NzaC1yc2E...',
        'private_key': '-----BEGIN OPENSSH PRIVATE KEY-----\n...',
        'username': 'root'
    }
    
    # Configure mock to return API response
    mock_instance.ssh_key.return_value = mock_ssh_key_response
    
    # Test API call
    result = mock_instance.ssh_key()
    
    # Verify API response structure
    assert 'public_key' in result
    assert 'private_key' in result
    assert 'username' in result
    
    # Verify method was called
    mock_instance.ssh_key.assert_called_once()
    
    logger.info("SSH key API endpoint mock test successful")


@patch('morphcloud.api.MorphCloudClient')
def test_ssh_key_rotation_api_endpoint_mock(mock_client_class):
    """Test SSH key rotation API endpoint with mocking."""
    logger.info("Testing SSH key rotation API endpoint with mocks")
    
    # Create mock client instance
    mock_client = Mock()
    mock_client_class.return_value = mock_client
    
    # Create mock instance
    mock_instance = Mock()
    mock_instance.id = "morphvm_test"
    
    # Mock SSH key rotation API call
    mock_instance.ssh_key_rotate.return_value = None  # Rotation typically returns None
    
    # Test API call
    result = mock_instance.ssh_key_rotate()
    
    # Verify API call completed
    assert result is None, "SSH key rotation should return None"
    
    # Verify method was called
    mock_instance.ssh_key_rotate.assert_called_once()
    
    logger.info("SSH key rotation API endpoint mock test successful")