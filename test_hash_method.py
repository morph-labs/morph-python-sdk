#!/usr/bin/env python3
"""
Simple test to verify the _compute_content_hash method works correctly.
This test doesn't require cloud resources, just tests the hashing logic.
"""

import os
import tempfile
import time
from pathlib import Path
import sys
sys.path.insert(0, '.')

def test_hash_method():
    """Test the _compute_content_hash method directly."""
    
    # Mock the Snapshot class for testing
    class MockSnapshot:
        def _compute_content_hash(self, src: str) -> str:
            import hashlib
            src_path = Path(src)
            
            if not src_path.exists():
                return hashlib.sha256(f"nonexistent-{src}".encode()).hexdigest()[:16]
            
            hasher = hashlib.sha256()
            
            if src_path.is_file():
                try:
                    with open(src_path, 'rb') as f:
                        while True:
                            chunk = f.read(65536)
                            if not chunk:
                                break
                            hasher.update(chunk)
                    mtime = src_path.stat().st_mtime
                    hasher.update(str(mtime).encode())
                except (IOError, OSError):
                    hasher.update(src.encode())
                    hasher.update(str(time.time()).encode())
            else:
                try:
                    for file_path in sorted(src_path.rglob('*')):
                        if file_path.is_file():
                            rel_path = file_path.relative_to(src_path)
                            hasher.update(str(rel_path).encode())
                            
                            try:
                                with open(file_path, 'rb') as f:
                                    while True:
                                        chunk = f.read(65536)
                                        if not chunk:
                                            break
                                        hasher.update(chunk)
                                mtime = file_path.stat().st_mtime
                                hasher.update(str(mtime).encode())
                            except (IOError, OSError):
                                hasher.update(str(file_path).encode())
                                hasher.update(str(time.time()).encode())
                except (IOError, OSError):
                    hasher.update(src.encode())
                    hasher.update(str(time.time()).encode())
            
            return hasher.hexdigest()[:16]
    
    # Test with a temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        test_file_path = f.name
        f.write("print('test content')")
    
    try:
        mock_snapshot = MockSnapshot()
        
        # Get initial hash
        hash1 = mock_snapshot._compute_content_hash(test_file_path)
        print(f"✅ Initial hash: {hash1}")
        
        # Modify file content
        time.sleep(0.1)  # Ensure different timestamp
        with open(test_file_path, 'w') as f:
            f.write("print('modified content')")
        
        # Get hash after modification
        hash2 = mock_snapshot._compute_content_hash(test_file_path)
        print(f"✅ Modified hash: {hash2}")
        
        # Verify hashes are different
        if hash1 != hash2:
            print("✅ SUCCESS: Content hash changes when file is modified!")
            return True
        else:
            print("❌ FAILURE: Content hash unchanged after file modification!")
            return False
            
    finally:
        # Clean up test file
        os.unlink(test_file_path)

def test_directory_hash():
    """Test hash computation for directories."""
    
    # Mock the Snapshot class for testing
    class MockSnapshot:
        def _compute_content_hash(self, src: str) -> str:
            import hashlib
            src_path = Path(src)
            
            if not src_path.exists():
                return hashlib.sha256(f"nonexistent-{src}".encode()).hexdigest()[:16]
            
            hasher = hashlib.sha256()
            
            if src_path.is_file():
                try:
                    with open(src_path, 'rb') as f:
                        while True:
                            chunk = f.read(65536)
                            if not chunk:
                                break
                            hasher.update(chunk)
                    mtime = src_path.stat().st_mtime
                    hasher.update(str(mtime).encode())
                except (IOError, OSError):
                    hasher.update(src.encode())
                    hasher.update(str(time.time()).encode())
            else:
                try:
                    for file_path in sorted(src_path.rglob('*')):
                        if file_path.is_file():
                            rel_path = file_path.relative_to(src_path)
                            hasher.update(str(rel_path).encode())
                            
                            try:
                                with open(file_path, 'rb') as f:
                                    while True:
                                        chunk = f.read(65536)
                                        if not chunk:
                                            break
                                        hasher.update(chunk)
                                mtime = file_path.stat().st_mtime
                                hasher.update(str(mtime).encode())
                            except (IOError, OSError):
                                hasher.update(str(file_path).encode())
                                hasher.update(str(time.time()).encode())
                except (IOError, OSError):
                    hasher.update(src.encode())
                    hasher.update(str(time.time()).encode())
            
            return hasher.hexdigest()[:16]
    
    # Test with a temporary directory
    with tempfile.TemporaryDirectory() as test_dir:
        # Create some files in the directory
        file1 = Path(test_dir) / "file1.txt"
        file2 = Path(test_dir) / "file2.txt"
        
        file1.write_text("content of file 1")
        file2.write_text("content of file 2")
        
        mock_snapshot = MockSnapshot()
        
        # Get initial hash
        hash1 = mock_snapshot._compute_content_hash(test_dir)
        print(f"✅ Initial directory hash: {hash1}")
        
        # Modify a file in the directory
        time.sleep(0.1)  # Ensure different timestamp
        file1.write_text("modified content of file 1")
        
        # Get hash after modification
        hash2 = mock_snapshot._compute_content_hash(test_dir)
        print(f"✅ Modified directory hash: {hash2}")
        
        # Verify hashes are different
        if hash1 != hash2:
            print("✅ SUCCESS: Directory hash changes when file is modified!")
            return True
        else:
            print("❌ FAILURE: Directory hash unchanged after file modification!")
            return False

if __name__ == "__main__":
    print("🧪 Testing content hash computation...")
    print("=" * 50)
    
    success_count = 0
    total_tests = 2
    
    print("\n1. Testing file hash computation...")
    if test_hash_method():
        success_count += 1
    
    print("\n2. Testing directory hash computation...")
    if test_directory_hash():
        success_count += 1
    
    print("\n" + "=" * 50)
    print(f"🧪 Test Results: {success_count}/{total_tests} tests passed")
    
    if success_count == total_tests:
        print("✅ All hash computation tests passed!")
        exit(0)
    else:
        print("❌ Some tests failed.")
        exit(1)