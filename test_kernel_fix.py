#!/usr/bin/env python3
"""
Test script to verify the kernel persistence fix works correctly.
"""

import os
import sys
sys.path.insert(0, '/workspace/project')

from morphcloud.sandbox import Sandbox, SandboxAPI
from morphcloud.api import MorphCloudClient

def test_kernel_persistence_fix():
    """Test that the fix preserves kernel state when getting a sandbox instance."""
    print("Testing kernel persistence fix...")
    
    # Create a client and sandbox API
    client = MorphCloudClient()
    sandbox_api = SandboxAPI(client)
    
    # Start a new sandbox
    print("1. Starting new sandbox...")
    sandbox1 = Sandbox.new(client=client, ttl_seconds=1200)
    print(f"   Sandbox ID: {sandbox1._instance.id}")
    
    # Connect to it
    print("2. Connecting to sandbox...")
    sandbox1.connect()
    
    # Run some code to set a variable
    print("3. Setting variable x = 42...")
    result1 = sandbox1.run_code("x = 42", language="python")
    print(f"   Result success: {result1.success}")
    if not result1.success:
        print(f"   Error: {result1.error}")
        return False
    
    # Get the kernel ID for reference
    python_kernel_id = sandbox1._kernel_ids.get("python")
    print(f"   Python kernel ID: {python_kernel_id}")
    
    # Now use .get() to retrieve the same sandbox
    print("4. Getting same sandbox using .get()...")
    sandbox2 = sandbox_api.get(sandbox1._instance.id)
    print(f"   Retrieved sandbox ID: {sandbox2._instance.id}")
    
    # Connect to the retrieved sandbox (this should now discover existing kernels)
    print("5. Connecting to retrieved sandbox (should discover existing kernels)...")
    sandbox2.connect()
    
    # Check if kernel ID was discovered
    python_kernel_id2 = sandbox2._kernel_ids.get("python")
    print(f"   Original kernel ID: {python_kernel_id}")
    print(f"   Retrieved kernel ID: {python_kernel_id2}")
    print(f"   Kernel IDs match: {python_kernel_id == python_kernel_id2}")
    
    # Try to print the variable we set earlier
    print("6. Attempting to print x (should be 42 if kernel state preserved)...")
    result2 = sandbox2.run_code("print(x)", language="python")
    print(f"   Result success: {result2.success}")
    print(f"   Output: {result2.text}")
    if result2.error:
        print(f"   Error: {result2.error}")
    
    # Test the expected behavior
    success = False
    if result2.success and "42" in result2.text:
        print("\n✅ SUCCESS: Kernel state was preserved!")
        print("   The fix is working correctly!")
        success = True
    else:
        print("\n❌ ISSUE STILL EXISTS: Kernel state was NOT preserved!")
        if python_kernel_id == python_kernel_id2:
            print("   Kernel IDs match but variable not found - possible WebSocket issue")
        else:
            print("   Kernel discovery failed - different kernel IDs")
    
    # Clean up
    print("7. Cleaning up...")
    try:
        sandbox1.close()
        sandbox2.close()
        sandbox1.shutdown()
    except Exception as e:
        print(f"   Cleanup error: {e}")
    
    return success

if __name__ == "__main__":
    success = test_kernel_persistence_fix()
    sys.exit(0 if success else 1)