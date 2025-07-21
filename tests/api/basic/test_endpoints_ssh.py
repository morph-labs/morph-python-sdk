"""
Test all SSH key management API endpoints.

This module tests the 2 SSH endpoints:
- GET /instance/{id}/ssh/key - Get SSH key for instance
- POST /instance/{id}/ssh/key - Rotate SSH key for instance
"""
import pytest
import logging
import time
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger("morph-api-tests")

# Performance tracking
PERFORMANCE_LOG_FILE = Path(__file__).parent.parent.parent / "performance_log.jsonl"

# Mark all tests as asyncio tests
pytestmark = pytest.mark.asyncio


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


async def test_get_ssh_key(client, base_image):
    """Test GET /instance/{id}/ssh/key - Get SSH key for instance."""
    logger.info("Testing SSH key retrieval")
    
    snapshot = None
    instance = None
    
    try:
        # Create snapshot and start instance
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=1024,
            disk_size=8*1024
        )
        
        instance = await client.instances.astart(snapshot.id)
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} ready for SSH key test")
        
        # Get SSH key for instance (timed)
        ssh_key, get_duration = await timed_operation(
            "ssh_key_get",
            lambda: instance.assh_key()
        )
        logger.info(f"Retrieved SSH key for instance {instance.id}")
        
        # Verify SSH key structure
        assert ssh_key is not None, "SSH key should not be None"
        
        # Check for expected SSH key fields
        if hasattr(ssh_key, 'public_key'):
            assert ssh_key.public_key, "SSH public key should not be empty"
            # SSH keys can start with ssh-rsa, ssh-dss, ecdsa-sha2-*, ssh-ed25519, etc.
            key_prefixes = ("ssh-", "ecdsa-sha2-", "ssh-ed25519")
            assert any(ssh_key.public_key.startswith(prefix) for prefix in key_prefixes), f"Public key should start with valid SSH key prefix, got: {ssh_key.public_key[:30]}..."
            key_type = ssh_key.public_key.split()[0]
            logger.info(f"Public key format: {key_type}")
        
        if hasattr(ssh_key, 'private_key'):
            assert ssh_key.private_key, "SSH private key should not be empty"
            assert "PRIVATE KEY" in ssh_key.private_key, "Private key should contain 'PRIVATE KEY'"
            logger.info("Private key format validated")
        
        if hasattr(ssh_key, 'password'):
            if ssh_key.password:
                logger.info(f"SSH key has password protection")
            else:
                logger.info("SSH key has no password protection")
        
        logger.info(f"📊 SSH Key Get Performance: {get_duration:.2f}s")
        
    finally:
        # Clean up resources
        if instance:
            try:
                await instance.astop()
                logger.info("Instance stopped")
            except Exception as e:
                logger.error(f"Error stopping instance: {e}")
                
        if snapshot:
            try:
                await snapshot.adelete()
                logger.info("Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")


async def test_ssh_key_rotation(client, base_image):
    """Test POST /instance/{id}/ssh/key - Rotate SSH key for instance."""
    logger.info("Testing SSH key rotation")
    
    snapshot = None
    instance = None
    
    try:
        # Create snapshot and start instance
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=1024,
            disk_size=8*1024
        )
        
        instance = await client.instances.astart(snapshot.id)
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} ready for SSH key rotation test")
        
        # Get original SSH key (timed)
        original_key, get_original_duration = await timed_operation(
            "ssh_key_get_original",
            lambda: instance.assh_key()
        )
        logger.info("Retrieved original SSH key")
        
        # Store original key details for comparison
        original_public_key = getattr(original_key, 'public_key', None)
        original_private_key = getattr(original_key, 'private_key', None)
        
        # Rotate SSH key (timed)
        new_key, rotate_duration = await timed_operation(
            "ssh_key_rotate",
            lambda: instance.assh_key_rotate()
        )
        logger.info("SSH key rotated")
        
        # Verify new key is different from original
        if original_public_key and hasattr(new_key, 'public_key'):
            assert new_key.public_key != original_public_key, "New public key should be different from original"
            logger.info("✓ New public key is different from original")
        
        if original_private_key and hasattr(new_key, 'private_key'):
            assert new_key.private_key != original_private_key, "New private key should be different from original"
            logger.info("✓ New private key is different from original")
        
        # Verify new key has valid format
        if hasattr(new_key, 'public_key'):
            key_prefixes = ("ssh-", "ecdsa-sha2-", "ssh-ed25519")
            assert any(new_key.public_key.startswith(prefix) for prefix in key_prefixes), f"New public key should start with valid SSH key prefix, got: {new_key.public_key[:30]}..."
            logger.info("✓ New public key has valid format")
        
        if hasattr(new_key, 'private_key'):
            assert "PRIVATE KEY" in new_key.private_key, "New private key should contain 'PRIVATE KEY'"
            logger.info("✓ New private key has valid format")
        
        # Verify we can retrieve the new key (should match what rotate returned)
        retrieved_key, get_new_duration = await timed_operation(
            "ssh_key_get_after_rotate",
            lambda: instance.assh_key()
        )
        
        if hasattr(new_key, 'public_key') and hasattr(retrieved_key, 'public_key'):
            assert retrieved_key.public_key == new_key.public_key, "Retrieved key should match rotated key"
            logger.info("✓ Retrieved key matches rotated key")
        
        logger.info(f"📊 SSH Key Rotation Performance:")
        logger.info(f"   Get Original: {get_original_duration:.2f}s")
        logger.info(f"   Rotate:       {rotate_duration:.2f}s")
        logger.info(f"   Get New:      {get_new_duration:.2f}s")
        logger.info(f"   Total:        {get_original_duration + rotate_duration + get_new_duration:.2f}s")
        
    finally:
        # Clean up resources
        if instance:
            try:
                await instance.astop()
                logger.info("Instance stopped")
            except Exception as e:
                logger.error(f"Error stopping instance: {e}")
                
        if snapshot:
            try:
                await snapshot.adelete()
                logger.info("Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")


async def test_multiple_ssh_key_rotations(client, base_image):
    """Test multiple SSH key rotations to ensure uniqueness."""
    logger.info("Testing multiple SSH key rotations")
    
    snapshot = None
    instance = None
    
    try:
        # Create snapshot and start instance
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=1024,
            disk_size=8*1024
        )
        
        instance = await client.instances.astart(snapshot.id)
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} ready for multiple SSH key rotation test")
        
        # Perform multiple rotations and collect keys
        keys = []
        rotation_times = []
        
        for i in range(3):  # Test 3 rotations
            logger.info(f"Performing rotation {i+1}/3")
            
            new_key, rotate_duration = await timed_operation(
                f"ssh_key_rotate_{i+1}",
                lambda: instance.assh_key_rotate()
            )
            
            keys.append(new_key)
            rotation_times.append(rotate_duration)
            
            logger.info(f"Rotation {i+1} completed in {rotate_duration:.2f}s")
        
        # Verify all keys are unique
        public_keys = []
        private_keys = []
        
        for i, key in enumerate(keys):
            if hasattr(key, 'public_key') and key.public_key:
                public_keys.append(key.public_key)
            if hasattr(key, 'private_key') and key.private_key:
                private_keys.append(key.private_key)
        
        # Check public key uniqueness
        if public_keys:
            unique_public_keys = set(public_keys)
            assert len(unique_public_keys) == len(public_keys), f"All public keys should be unique. Got {len(unique_public_keys)} unique out of {len(public_keys)}"
            logger.info(f"✓ All {len(public_keys)} public keys are unique")
        
        # Check private key uniqueness
        if private_keys:
            unique_private_keys = set(private_keys)
            assert len(unique_private_keys) == len(private_keys), f"All private keys should be unique. Got {len(unique_private_keys)} unique out of {len(private_keys)}"
            logger.info(f"✓ All {len(private_keys)} private keys are unique")
        
        # Performance analysis
        avg_rotation_time = sum(rotation_times) / len(rotation_times)
        min_rotation_time = min(rotation_times)
        max_rotation_time = max(rotation_times)
        
        logger.info(f"📊 Multiple Rotation Performance:")
        logger.info(f"   Average: {avg_rotation_time:.2f}s")
        logger.info(f"   Min:     {min_rotation_time:.2f}s")
        logger.info(f"   Max:     {max_rotation_time:.2f}s")
        logger.info(f"   Times:   {', '.join([f'{t:.2f}s' for t in rotation_times])}")
        
    finally:
        # Clean up resources
        if instance:
            try:
                await instance.astop()
                logger.info("Instance stopped")
            except Exception as e:
                logger.error(f"Error stopping instance: {e}")
                
        if snapshot:
            try:
                await snapshot.adelete()
                logger.info("Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")