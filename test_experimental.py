import logging
from morphcloud.experimental import Snapshot

# Configure logging to see the output
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

# Test basic functionality
try:
    # This will test the logging system
    snap = Snapshot.create("test-snapshot", vcpus=1, memory=1024)
    print("✅ Snapshot.create() works with logging")
    
    # Test logging output
    print("✅ Import and basic functionality successful")
except Exception as e:
    print(f"❌ Error: {e}")