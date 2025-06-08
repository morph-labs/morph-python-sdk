#!/bin/bash
# Run the integration tests with appropriate timeouts

cd "$(dirname "$0")"

# Install required pytest plugins
uv pip install pytest pytest-asyncio pytest-timeout

# Run all tests with a longer timeout
echo "Running all tests..."
python -m pytest . -v --timeout=600

# Or run specific test categories (uncomment as needed)
# echo "Running HTTP service tests..."
# python -m pytest test_http_service.py -v --timeout=300

# echo "Running command execution tests..."
# python -m pytest test_command_execution.py -v --timeout=300

# echo "Running snapshot operation tests..."
# python -m pytest test_snapshot_operations.py -v --timeout=300

# echo "Running TTL and auto-cleanup tests..."
# python -m pytest test_ttl.py -v --timeout=300

# echo "Running branching and parallel operations tests..."
# python -m pytest test_branching.py -v --timeout=300

# echo "Running instance lifecycle tests..."
# python -m pytest test_instance_lifecycle.py -v --timeout=300

# echo "Running resource lifecycle tests..."
# python -m pytest test_resource_lifecycle.py -v --timeout=300

# echo "Running session tests..."
# python -m pytest test_session.py -v --timeout=300

# echo "Running simple tests..."
# python -m pytest test_simple.py -v --timeout=300

# echo "Running metadata tests..."
# python -m pytest test_metadata.py -v --timeout=300

# echo "Running file operations tests..."
# python -m pytest test_file_operations.py -v --timeout=300

# End of test categories