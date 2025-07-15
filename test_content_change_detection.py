#!/usr/bin/env python3
"""
Test case to validate that the file copy cache fix works correctly.
This test verifies that modified files trigger new snapshots instead of returning stale cached data.
"""

import os
import tempfile
import time
from pathlib import Path

def test_content_change_detection():
    """Test that content changes are detected and don't return stale cache hits."""
    
    # Skip this test if we don't have proper environment setup
    try:
        from morphcloud.experimental import Snapshot
    except ImportError:
        print("⚠️  Skipping test - morphcloud not available")
        return
    
    # Create a temporary test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        test_file_path = f.name
        f.write("print('version 1')")
    
    try:
        # Create a base snapshot for testing
        base = Snapshot.create("test-content-change-detection")
        
        # First copy - should create new snapshot
        print("📝 First copy with initial content...")
        snap1 = base.copy_(test_file_path, "/app/test_file.py")
        print(f"✅ First snapshot created: {snap1.id}")
        
        # Modify file content (same path)
        time.sleep(0.1)  # Ensure different timestamp
        with open(test_file_path, 'w') as f:
            f.write("print('version 2')")
        
        # Second copy - should create NEW snapshot (not return cached)
        print("📝 Second copy with modified content...")
        snap2 = base.copy_(test_file_path, "/app/test_file.py")
        print(f"✅ Second snapshot created: {snap2.id}")
        
        # Verify different snapshots were created
        if snap1.id != snap2.id:
            print("✅ SUCCESS: Content change detection works! Different snapshots created.")
            print(f"   - First snapshot:  {snap1.id}")
            print(f"   - Second snapshot: {snap2.id}")
            return True
        else:
            print("❌ FAILURE: Same snapshot returned - stale cache hit detected!")
            print(f"   - Both calls returned snapshot: {snap1.id}")
            return False
            
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        return False
    finally:
        # Clean up test file
        os.unlink(test_file_path)

def test_unchanged_file_cache_hit():
    """Test that unchanged files still use cached snapshots (performance maintained)."""
    
    try:
        from morphcloud.experimental import Snapshot
    except ImportError:
        print("⚠️  Skipping test - morphcloud not available")
        return
    
    # Create a temporary test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        test_file_path = f.name
        f.write("print('unchanged content')")
    
    try:
        # Create a base snapshot for testing
        base = Snapshot.create("test-unchanged-cache-hit")
        
        # First copy
        print("📝 First copy...")
        snap1 = base.copy_(test_file_path, "/app/unchanged_file.py")
        print(f"✅ First snapshot created: {snap1.id}")
        
        # Second copy without changes - should return same snapshot
        print("📝 Second copy (no changes)...")
        snap2 = base.copy_(test_file_path, "/app/unchanged_file.py")
        print(f"✅ Second snapshot: {snap2.id}")
        
        # Verify same snapshot was returned (cache hit)
        if snap1.id == snap2.id:
            print("✅ SUCCESS: Cache hit works! Same snapshot returned for unchanged file.")
            print(f"   - Both calls returned snapshot: {snap1.id}")
            return True
        else:
            print("❌ FAILURE: Different snapshots created for unchanged file!")
            print(f"   - First snapshot:  {snap1.id}")
            print(f"   - Second snapshot: {snap2.id}")
            return False
            
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        return False
    finally:
        # Clean up test file
        os.unlink(test_file_path)

def test_content_hash_computation():
    """Test the _compute_content_hash method directly."""
    
    try:
        from morphcloud.experimental import Snapshot
    except ImportError:
        print("⚠️  Skipping test - morphcloud not available")
        return
    
    # Create a temporary test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        test_file_path = f.name
        f.write("print('test content')")
    
    try:
        # Create a snapshot instance to test the method
        base = Snapshot.create("test-hash-computation")
        
        # Get initial hash
        hash1 = base._compute_content_hash(test_file_path)
        print(f"📝 Initial content hash: {hash1}")
        
        # Modify file content
        time.sleep(0.1)  # Ensure different timestamp
        with open(test_file_path, 'w') as f:
            f.write("print('modified content')")
        
        # Get hash after modification
        hash2 = base._compute_content_hash(test_file_path)
        print(f"📝 Modified content hash: {hash2}")
        
        # Verify hashes are different
        if hash1 != hash2:
            print("✅ SUCCESS: Content hash changes when file is modified!")
            return True
        else:
            print("❌ FAILURE: Content hash unchanged after file modification!")
            return False
            
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        return False
    finally:
        # Clean up test file
        os.unlink(test_file_path)

if __name__ == "__main__":
    print("🧪 Testing file copy cache content change detection...")
    print("=" * 60)
    
    success_count = 0
    total_tests = 3
    
    print("\n1. Testing content change detection...")
    if test_content_change_detection():
        success_count += 1
    
    print("\n2. Testing unchanged file cache hit...")
    if test_unchanged_file_cache_hit():
        success_count += 1
    
    print("\n3. Testing content hash computation...")
    if test_content_hash_computation():
        success_count += 1
    
    print("\n" + "=" * 60)
    print(f"🧪 Test Results: {success_count}/{total_tests} tests passed")
    
    if success_count == total_tests:
        print("✅ All tests passed! File copy cache fix is working correctly.")
        exit(0)
    else:
        print("❌ Some tests failed. Please check the implementation.")
        exit(1)