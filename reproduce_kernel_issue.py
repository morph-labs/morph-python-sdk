#!/usr/bin/env python3
"""
Reproduction script to demonstrate the kernel persistence issue.
This script shows that .get() creates a new kernel instead of preserving state.
"""

import os
import sys
sys.path.insert(0, '/workspace/project')

from morphcloud.sandbox import Sandbox, SandboxAPI
from morphcloud.api import MorphCloudClient

def test_kernel_persistence():
    """Test if kernel state is preserved when getting a sandbox instance."""
    print("Testing kernel persistence issue...")
    
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
    
    # Get the kernel ID for reference
    python_kernel_id = sandbox1._kernel_ids.get("python")
    print(f"   Python kernel ID: {python_kernel_id}")
    
    # Now use .get() to retrieve the same sandbox
    print("4. Getting same sandbox using .get()...")
    sandbox2 = sandbox_api.get(sandbox1._instance.id)
    print(f"   Retrieved sandbox ID: {sandbox2._instance.id}")
    
    # Connect to the retrieved sandbox
    print("5. Connecting to retrieved sandbox...")
    sandbox2.connect()
    
    # Try to print the variable we set earlier
    print("6. Attempting to print x (should be 42 if kernel state preserved)...")
    result2 = sandbox2.run_code("print(x)", language="python")
    print(f"   Result success: {result2.success}")
    print(f"   Output: {result2.text}")
    print(f"   Error: {result2.error}")
    
    # Check if kernel IDs are the same
    python_kernel_id2 = sandbox2._kernel_ids.get("python")
    print(f"   Original kernel ID: {python_kernel_id}")
    print(f"   Retrieved kernel ID: {python_kernel_id2}")
    print(f"   Kernel IDs match: {python_kernel_id == python_kernel_id2}")
    
    # Test the expected behavior
    if result2.success and "42" in result2.text:
        print("\n✅ SUCCESS: Kernel state was preserved!")
    else:
        print("\n❌ ISSUE CONFIRMED: Kernel state was NOT preserved!")
        print("   This demonstrates the bug - .get() creates a new kernel instead of reusing existing ones.")
    
    # Clean up
    print("7. Cleaning up...")
    try:
        sandbox1.close()
        sandbox2.close()
        sandbox1.shutdown()
    except Exception as e:
        print(f"   Cleanup error: {e}")

if __name__ == "__main__":
    test_kernel_persistence()