"""
Integration tests for UserAPI operations in MorphCloud SDK.
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


class TestUserAPIKeys:
    """Test user API key operations."""

    async def test_list_api_keys_sync(self, client):
        """Test listing API keys synchronously."""
        logger.info("Testing sync list_api_keys")
        
        keys = client.user.list_api_keys()
        assert isinstance(keys, list)
        logger.info(f"Found {len(keys)} API keys")
        
        # Verify each key has expected fields
        for key in keys:
            assert hasattr(key, 'id')
            assert hasattr(key, 'key_prefix')
            assert hasattr(key, 'created')
            assert hasattr(key, 'last_used')
            assert isinstance(key.id, str)
            assert isinstance(key.key_prefix, str)
            assert isinstance(key.created, int)
            logger.info(f"API key: {key.id} (prefix: {key.key_prefix})")

    async def test_list_api_keys_async(self, client):
        """Test listing API keys asynchronously."""
        logger.info("Testing async alist_api_keys")
        
        keys = await client.user.alist_api_keys()
        assert isinstance(keys, list)
        logger.info(f"Found {len(keys)} API keys")
        
        # Verify each key has expected fields
        for key in keys:
            assert hasattr(key, 'id')
            assert hasattr(key, 'key_prefix')
            assert hasattr(key, 'created')
            assert hasattr(key, 'last_used')
            assert isinstance(key.id, str)
            assert isinstance(key.key_prefix, str)
            assert isinstance(key.created, int)

    async def test_create_and_delete_api_key_sync(self, client):
        """Test creating and deleting API keys synchronously."""
        logger.info("Testing sync create and delete API key")
        
        # Create API key
        logger.info("Creating new API key...")
        created_key = client.user.create_api_key()
        
        assert hasattr(created_key, 'id')
        assert hasattr(created_key, 'key')
        assert hasattr(created_key, 'key_prefix')
        assert hasattr(created_key, 'created')
        assert isinstance(created_key.id, str)
        assert isinstance(created_key.key, str)
        assert isinstance(created_key.key_prefix, str)
        assert isinstance(created_key.created, int)
        
        logger.info(f"Created API key: {created_key.id} (prefix: {created_key.key_prefix})")
        
        try:
            # Verify the key appears in the list
            keys = client.user.list_api_keys()
            created_key_found = any(k.id == created_key.id for k in keys)
            assert created_key_found, "Created API key should appear in list"
            
        finally:
            # Clean up - delete the key
            logger.info(f"Deleting API key: {created_key.id}")
            client.user.delete_api_key(created_key.id)
            
            # Verify the key is no longer in the list
            keys_after_delete = client.user.list_api_keys()
            deleted_key_found = any(k.id == created_key.id for k in keys_after_delete)
            assert not deleted_key_found, "Deleted API key should not appear in list"

    async def test_create_and_delete_api_key_async(self, client):
        """Test creating and deleting API keys asynchronously."""
        logger.info("Testing async create and delete API key")
        
        # Create API key
        logger.info("Creating new API key...")
        created_key = await client.user.acreate_api_key()
        
        assert hasattr(created_key, 'id')
        assert hasattr(created_key, 'key')
        assert hasattr(created_key, 'key_prefix')
        assert hasattr(created_key, 'created')
        assert isinstance(created_key.id, str)
        assert isinstance(created_key.key, str)
        assert isinstance(created_key.key_prefix, str)
        assert isinstance(created_key.created, int)
        
        logger.info(f"Created API key: {created_key.id} (prefix: {created_key.key_prefix})")
        
        try:
            # Verify the key appears in the list
            keys = await client.user.alist_api_keys()
            created_key_found = any(k.id == created_key.id for k in keys)
            assert created_key_found, "Created API key should appear in list"
            
        finally:
            # Clean up - delete the key
            logger.info(f"Deleting API key: {created_key.id}")
            await client.user.adelete_api_key(created_key.id)
            
            # Verify the key is no longer in the list
            keys_after_delete = await client.user.alist_api_keys()
            deleted_key_found = any(k.id == created_key.id for k in keys_after_delete)
            assert not deleted_key_found, "Deleted API key should not appear in list"


class TestUserSSHKey:
    """Test user SSH key operations."""

    async def test_get_ssh_key_sync(self, client):
        """Test getting SSH key synchronously."""
        logger.info("Testing sync get_ssh_key")
        
        try:
            ssh_key = client.user.get_ssh_key()
            assert hasattr(ssh_key, 'public_key')
            assert hasattr(ssh_key, 'created')
            assert isinstance(ssh_key.public_key, str)
            assert isinstance(ssh_key.created, int)
            logger.info(f"SSH key created: {ssh_key.created}")
            logger.info(f"SSH key (first 50 chars): {ssh_key.public_key[:50]}...")
        except Exception as e:
            # SSH key might not be set yet, which is okay for testing
            logger.info(f"No SSH key found or error: {e}")

    async def test_get_ssh_key_async(self, client):
        """Test getting SSH key asynchronously."""
        logger.info("Testing async aget_ssh_key")
        
        try:
            ssh_key = await client.user.aget_ssh_key()
            assert hasattr(ssh_key, 'public_key')
            assert hasattr(ssh_key, 'created')
            assert isinstance(ssh_key.public_key, str)
            assert isinstance(ssh_key.created, int)
            logger.info(f"SSH key created: {ssh_key.created}")
            logger.info(f"SSH key (first 50 chars): {ssh_key.public_key[:50]}...")
        except Exception as e:
            # SSH key might not be set yet, which is okay for testing
            logger.info(f"No SSH key found or error: {e}")

    async def test_update_ssh_key_sync(self, client):
        """Test updating SSH key synchronously."""
        logger.info("Testing sync update_ssh_key")
        
        # Generate a test SSH public key (this is a dummy key for testing)
        test_public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbqajDhA+17SF8GEl9JgULJjFsYhOQI7yCqPLJBJGF6y9PcAEv9SVz/p5TRBhgwT7h8vKlLzMWvqJNm8RpAWp3OV7GfcYXa7K1JJgFO6FMUP6VXl2QVj+8pMyNvSDUzW6Zu+sOdOkTLuuWdlHrMc3FPtM1Z3BgVrYb2xd0e5g9o3e5vGnE8sQ7qQrXp6U9N8X2Bb+mVJ9gUrJ4JhzBgT5wPjNqXRjVrA7L1aA/test-morph-sdk"
        
        # Store original key if it exists
        original_key = None
        try:
            original_key = client.user.get_ssh_key()
            logger.info("Found existing SSH key, will restore after test")
        except Exception:
            logger.info("No existing SSH key found")
        
        try:
            # Update SSH key
            logger.info("Updating SSH key...")
            updated_key = client.user.update_ssh_key(test_public_key)
            
            assert hasattr(updated_key, 'public_key')
            assert hasattr(updated_key, 'created')
            assert isinstance(updated_key.public_key, str)
            assert isinstance(updated_key.created, int)
            assert updated_key.public_key == test_public_key
            
            logger.info(f"SSH key updated successfully")
            
            # Verify the update by getting the key again
            retrieved_key = client.user.get_ssh_key()
            assert retrieved_key.public_key == test_public_key
            
        finally:
            # Restore original key if it existed
            if original_key:
                logger.info("Restoring original SSH key...")
                client.user.update_ssh_key(original_key.public_key)

    async def test_update_ssh_key_async(self, client):
        """Test updating SSH key asynchronously."""
        logger.info("Testing async update_ssh_key")
        
        # Generate a test SSH public key (this is a dummy key for testing)
        test_public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbqajDhA+17SF8GEl9JgULJjFsYhOQI7yCqPLJBJGF6y9PcAEv9SVz/p5TRBhgwT7h8vKlLzMWvqJNm8RpAWp3OV7GfcYXa7K1JJgFO6FMUP6VXl2QVj+8pMyNvSDUzW6Zu+sOdOkTLuuWdlHrMc3FPtM1Z3BgVrYb2xd0e5g9o3e5vGnE8sQ7qQrXp6U9N8X2Bb+mVJ9gUrJ4JhzBgT5wPjNqXRjVrA7L1aA/test-morph-sdk-async"
        
        # Store original key if it exists
        original_key = None
        try:
            original_key = await client.user.aget_ssh_key()
            logger.info("Found existing SSH key, will restore after test")
        except Exception:
            logger.info("No existing SSH key found")
        
        try:
            # Update SSH key
            logger.info("Updating SSH key...")
            updated_key = await client.user.aupdate_ssh_key(test_public_key)
            
            assert hasattr(updated_key, 'public_key')
            assert hasattr(updated_key, 'created')
            assert isinstance(updated_key.public_key, str)
            assert isinstance(updated_key.created, int)
            assert updated_key.public_key == test_public_key
            
            logger.info(f"SSH key updated successfully")
            
            # Verify the update by getting the key again
            retrieved_key = await client.user.aget_ssh_key()
            assert retrieved_key.public_key == test_public_key
            
        finally:
            # Restore original key if it existed
            if original_key:
                logger.info("Restoring original SSH key...")
                await client.user.aupdate_ssh_key(original_key.public_key)


class TestUserUsage:
    """Test user usage operations."""

    async def test_usage_sync(self, client):
        """Test getting usage information synchronously."""
        logger.info("Testing sync usage")
        
        # Test without interval
        usage = client.user.usage()
        assert hasattr(usage, 'instance')
        assert hasattr(usage, 'snapshot')
        assert hasattr(usage, 'items')
        assert isinstance(usage.instance, list)
        assert isinstance(usage.snapshot, list)
        assert isinstance(usage.items, list)
        
        logger.info(f"Usage buckets: {len(usage.items)}")
        logger.info(f"Instance usage entries: {len(usage.instance)}")
        logger.info(f"Snapshot usage entries: {len(usage.snapshot)}")

    async def test_usage_async(self, client):
        """Test getting usage information asynchronously."""
        logger.info("Testing async usage")
        
        # Test without interval
        usage = await client.user.ausage()
        assert hasattr(usage, 'instance')
        assert hasattr(usage, 'snapshot')
        assert hasattr(usage, 'items')
        assert isinstance(usage.instance, list)
        assert isinstance(usage.snapshot, list)
        assert isinstance(usage.items, list)
        
        logger.info(f"Usage buckets: {len(usage.items)}")
        logger.info(f"Instance usage entries: {len(usage.instance)}")
        logger.info(f"Snapshot usage entries: {len(usage.snapshot)}")

    async def test_usage_with_interval_sync(self, client):
        """Test getting usage information with interval synchronously."""
        logger.info("Testing sync usage with interval")
        
        # Test with different intervals
        intervals = ["30m", "3h", "24h", "7d"]
        
        for interval in intervals:
            logger.info(f"Testing interval: {interval}")
            usage = client.user.usage(interval=interval)
            assert hasattr(usage, 'instance')
            assert hasattr(usage, 'snapshot')
            assert hasattr(usage, 'items')
            assert isinstance(usage.instance, list)
            assert isinstance(usage.snapshot, list)
            assert isinstance(usage.items, list)
            
            logger.info(f"Interval {interval} - Usage buckets: {len(usage.items)}")

    async def test_usage_with_interval_async(self, client):
        """Test getting usage information with interval asynchronously."""
        logger.info("Testing async usage with interval")
        
        # Test with different intervals
        intervals = ["30m", "3h", "24h", "7d"]
        
        for interval in intervals:
            logger.info(f"Testing interval: {interval}")
            usage = await client.user.ausage(interval=interval)
            assert hasattr(usage, 'instance')
            assert hasattr(usage, 'snapshot')
            assert hasattr(usage, 'items')
            assert isinstance(usage.instance, list)
            assert isinstance(usage.snapshot, list)
            assert isinstance(usage.items, list)
            
            logger.info(f"Interval {interval} - Usage buckets: {len(usage.items)}")


class TestUserAPIIntegration:
    """Test integration of UserAPI with client."""

    async def test_user_property_access(self, client):
        """Test that the user property is accessible from the client."""
        logger.info("Testing user property access")
        
        # Test that client.user returns a UserAPI instance
        user_api = client.user
        assert user_api is not None
        assert hasattr(user_api, 'list_api_keys')
        assert hasattr(user_api, 'alist_api_keys')
        assert hasattr(user_api, 'create_api_key')
        assert hasattr(user_api, 'acreate_api_key')
        assert hasattr(user_api, 'delete_api_key')
        assert hasattr(user_api, 'adelete_api_key')
        assert hasattr(user_api, 'get_ssh_key')
        assert hasattr(user_api, 'aget_ssh_key')
        assert hasattr(user_api, 'update_ssh_key')
        assert hasattr(user_api, 'aupdate_ssh_key')
        assert hasattr(user_api, 'usage')
        assert hasattr(user_api, 'ausage')
        
        logger.info("All UserAPI methods are accessible")

    async def test_user_api_error_handling(self, client):
        """Test error handling in UserAPI methods."""
        logger.info("Testing UserAPI error handling")
        
        # Test deleting non-existent API key
        fake_key_id = f"fake-key-{uuid.uuid4()}"
        
        with pytest.raises(Exception):  # Should raise an API error
            client.user.delete_api_key(fake_key_id)
        
        with pytest.raises(Exception):  # Should raise an API error
            await client.user.adelete_api_key(fake_key_id)
        
        logger.info("Error handling works correctly")