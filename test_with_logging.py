import logging
import os
import sys

# Configure logging to see our experimental module output
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

from morphcloud.experimental import Snapshot

if __name__ == "__main__":
    print("=== Testing with visible logging ===")
    
    # Test basic snapshot creation
    snapshot = Snapshot.create("test-with-logging", vcpus=1, memory=1024)
    print(f"Created snapshot: {snapshot.id}")
    
    # Test run command
    snapshot = snapshot.run("echo 'Hello logging world!'")
    print("Command completed")