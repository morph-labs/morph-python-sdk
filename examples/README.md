# Morph Python SDK Examples

This directory contains working examples that demonstrate the capabilities of the Morph Python SDK.

## Available Examples

### 1. Browser Example (`browser_example.py`)
Demonstrates how to use the MorphBrowser API to create remote browser sessions and interact with web pages.

**Usage:**
```bash
python examples/browser_example.py
python examples/browser_example.py --rebuild    # Force fresh snapshot creation
python examples/browser_example.py --verbose    # Enable verbose output
```

### 2. Red Team Demo (`red_team_demo.py`)
Shows how to perform security testing and red team operations using the SDK.

### 3. Advanced Security Demo (`advanced_security_demo.py`)
Demonstrates advanced security features and configurations.

**Configuration:**
- Uses `advanced_security_config.yaml` for security settings

## MCP (Model Context Protocol) Usage

The Morph Python SDK includes built-in MCP support through the Computer class. You can use MCP functionality in two ways:

### 1. CLI Command
```bash
morphcloud instance computer-mcp <instance-id>
```

### 2. Programmatically
```python
from morphcloud.computer import Computer

computer = Computer.new(ttl_seconds=3600)

# Get MCP server
mcp_server = computer.mcp()

# Start MCP server with SSE transport
computer.start_mcp_server(transport="sse")

# Or get the command for stdio transport
stdio_cmd = computer.get_mcp_stdio_command()
```

## Dependencies

All examples use only the dependencies included in the project's `requirements.txt` and `pyproject.toml`. No external packages are required.

## Notes

- The examples demonstrate actual SDK functionality
- All code is tested and working
- Examples follow the project's API specifications
- MCP functionality is integrated directly into the SDK
