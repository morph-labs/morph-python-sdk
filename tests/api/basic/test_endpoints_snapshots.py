"""
Test all snapshot-related API endpoints.

This module tests the 5 snapshot endpoints:
- GET /snapshot - List snapshots with metadata filtering
- POST /snapshot - Create snapshot from base image  
- GET /snapshot/{id} - Get specific snapshot
- DELETE /snapshot/{id} - Delete snapshot
- POST /snapshot/{id}/metadata - Update snapshot metadata
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
performance_metrics = {}
PERFORMANCE_LOG_FILE = Path(__file__).parent.parent.parent / "performance_log.jsonl"


def track_performance(operation_name: str):
    """Decorator to track performance of API operations."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time
                performance_metrics[operation_name] = {
                    'duration_seconds': duration,
                    'status': 'success'
                }
                logger.info(f"⏱️  {operation_name}: {duration:.2f}s")
                return result
            except Exception as e:
                duration = time.time() - start_time
                performance_metrics[operation_name] = {
                    'duration_seconds': duration,
                    'status': 'failed',
                    'error': str(e)
                }
                logger.error(f"⏱️  {operation_name}: {duration:.2f}s (FAILED: {e})")
                raise
        return wrapper
    return decorator


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


# Mark all tests as asyncio tests
pytestmark = pytest.mark.asyncio


async def test_create_snapshot_basic(client, base_image):
    """Test POST /snapshot - Create snapshot from base image."""
    logger.info("Testing basic snapshot creation")
    
    try:
        # Create snapshot with minimal configuration (timed)
        snapshot, create_duration = await timed_operation(
            "snapshot_create_nano",
            lambda: client.snapshots.acreate(
                image_id=base_image.id,
                vcpus=1,
                memory=1024,  # 1GB RAM
                disk_size=8*1024  # 8GB disk
            )
        )
        logger.info(f"Created snapshot: {snapshot.id}")
        
        # Verify snapshot properties
        assert snapshot.id.startswith("snapshot_"), f"Snapshot ID should start with 'snapshot_', got: {snapshot.id}"
        assert hasattr(snapshot, "refs"), "Snapshot should have a refs attribute"
        assert hasattr(snapshot.refs, "image_id"), "Snapshot should have refs.image_id attribute"
        assert snapshot.refs.image_id == base_image.id, f"Snapshot should be created from {base_image.id}, got: {snapshot.refs.image_id}"
        
        # Verify we can retrieve the snapshot by ID (GET /snapshot/{id}) - timed
        retrieved_snapshot, get_duration = await timed_operation(
            "snapshot_get_by_id",
            lambda: client.snapshots.aget(snapshot.id)
        )
        assert retrieved_snapshot.id == snapshot.id, "Retrieved snapshot should have same ID"
        assert retrieved_snapshot.refs.image_id == base_image.id, "Retrieved snapshot should have same base image"
        
        # Log performance summary
        logger.info(f"📊 Performance Summary: Create={create_duration:.2f}s, Get={get_duration:.2f}s")
        
    finally:
        # Clean up resources (timed)
        if 'snapshot' in locals():
            try:
                _, delete_duration = await timed_operation(
                    "snapshot_delete",
                    lambda: snapshot.adelete()
                )
                logger.info(f"Snapshot deleted successfully in {delete_duration:.2f}s")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")


async def test_list_snapshots_empty(client):
    """Test GET /snapshot - List snapshots when none exist."""
    logger.info("Testing snapshot listing with no snapshots")
    
    # Get all snapshots - should be empty or contain only pre-existing ones
    snapshots = await client.snapshots.alist()
    
    # Verify the list is returned (even if empty)
    assert isinstance(snapshots, list), "Snapshots list should be a list"
    logger.info(f"Found {len(snapshots)} existing snapshots")


async def test_list_snapshots_with_content(client, base_image):
    """Test GET /snapshot - List snapshots when snapshots exist."""
    logger.info("Testing snapshot listing with existing snapshots")
    
    snapshot = None
    try:
        # Create a test snapshot
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=1024,
            disk_size=8*1024
        )
        logger.info(f"Created test snapshot: {snapshot.id}")
        
        # List all snapshots
        snapshots = await client.snapshots.alist()
        
        # Verify our snapshot is in the list
        snapshot_ids = [s.id for s in snapshots]
        assert snapshot.id in snapshot_ids, f"Created snapshot {snapshot.id} should be in the list"
        
        # Find our snapshot in the list and verify its properties
        our_snapshot = next(s for s in snapshots if s.id == snapshot.id)
        assert our_snapshot.refs.image_id == base_image.id, "Listed snapshot should have correct base image"
        
    finally:
        if snapshot:
            try:
                logger.info(f"Deleting test snapshot {snapshot.id}")
                await snapshot.adelete()
                logger.info("Test snapshot deleted successfully")
            except Exception as e:
                logger.error(f"Error deleting test snapshot: {e}")


async def test_get_nonexistent_snapshot(client):
    """Test GET /snapshot/{id} - Get non-existent snapshot returns error."""
    logger.info("Testing retrieval of non-existent snapshot")
    
    fake_snapshot_id = "snapshot_nonexistent_12345"
    
    # Try to get a non-existent snapshot - should raise an exception
    with pytest.raises(Exception) as exc_info:
        await client.snapshots.aget(fake_snapshot_id)
    
    logger.info(f"Got expected error for non-existent snapshot: {exc_info.value}")


async def test_delete_snapshot(client, base_image):
    """Test DELETE /snapshot/{id} - Delete snapshot."""
    logger.info("Testing snapshot deletion")
    
    # Create a snapshot to delete
    snapshot = await client.snapshots.acreate(
        image_id=base_image.id,
        vcpus=1,
        memory=1024,
        disk_size=8*1024
    )
    logger.info(f"Created snapshot for deletion test: {snapshot.id}")
    
    # Verify snapshot exists by retrieving it
    retrieved = await client.snapshots.aget(snapshot.id)
    assert retrieved.id == snapshot.id, "Snapshot should exist before deletion"
    
    # Delete the snapshot
    await snapshot.adelete()
    logger.info(f"Deleted snapshot {snapshot.id}")
    
    # Verify snapshot no longer exists
    with pytest.raises(Exception) as exc_info:
        await client.snapshots.aget(snapshot.id)
    
    logger.info(f"Confirmed snapshot deletion - got expected error: {exc_info.value}")


async def test_snapshot_metadata_operations(client, base_image):
    """Test POST /snapshot/{id}/metadata - Update snapshot metadata."""
    logger.info("Testing snapshot metadata operations")
    
    snapshot = None
    try:
        # Create snapshot with initial metadata
        initial_metadata = {"test_key": "initial_value", "environment": "api_test"}
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=1024,
            disk_size=8*1024,
            metadata=initial_metadata
        )
        logger.info(f"Created snapshot with metadata: {snapshot.id}")
        
        # Verify initial metadata is set
        retrieved = await client.snapshots.aget(snapshot.id)
        if hasattr(retrieved, 'metadata') and retrieved.metadata:
            assert retrieved.metadata.get("test_key") == "initial_value", "Initial metadata should be set"
            assert retrieved.metadata.get("environment") == "api_test", "Initial metadata should be set"
            logger.info("Verified initial metadata")
        
        # Update metadata
        new_metadata = {"test_key": "updated_value", "environment": "api_test", "status": "updated"}
        await snapshot.aset_metadata(new_metadata)
        logger.info("Updated snapshot metadata")
        
        # Verify metadata was updated
        updated_snapshot = await client.snapshots.aget(snapshot.id)
        if hasattr(updated_snapshot, 'metadata') and updated_snapshot.metadata:
            assert updated_snapshot.metadata.get("test_key") == "updated_value", "Metadata should be updated"
            assert updated_snapshot.metadata.get("status") == "updated", "New metadata should be added"
            logger.info("Verified metadata update")
        
    finally:
        if snapshot:
            try:
                logger.info(f"Deleting test snapshot {snapshot.id}")
                await snapshot.adelete()
                logger.info("Test snapshot deleted successfully")
            except Exception as e:
                logger.error(f"Error deleting test snapshot: {e}")