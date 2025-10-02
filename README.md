# Morph Cloud Python SDK 

## Overview

[Morph Cloud](https://cloud.morph.so) is a powerful platform for creating, managing, and interacting with remote AI development environments called runtimes. It provides a comprehensive Python SDK and CLI to:

- Create and manage VM snapshots
- Start, stop, pause, and resume VM instances
- Execute commands via SSH
- Transfer files between local and remote environments
- Expose HTTP services with optional authentication
- Create Docker containers within instances
- Cache and reuse computational results with snapshot chains

### Documentation

For comprehensive documentation, visit the [Morph Cloud Documentation](https://cloud.morph.so/docs/documentation/overview)

### Getting Your API Key

1. Go to [https://cloud.morph.so/web/keys](https://cloud.morph.so/web/keys)
2. Log in with your credentials
3. Create a new API key

## Setup Guide

### Prerequisites

- Python 3.10 or higher
- An account on [Morph Cloud](https://cloud.morph.so)

### Environment Setup with `uv`

[`uv`](https://github.com/astral-sh/uv) is a fast, modern Python package installer and resolver that works great with Morph Cloud.

#### Installing `uv`

```bash
# On macOS and Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# On Windows
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

#### Setting Up a Project Environment

```bash
# Create a new project directory
mkdir my-morph-project
cd my-morph-project

# Create a virtual environment with uv
uv venv

# Activate the environment
# On macOS/Linux:
source .venv/bin/activate
# On Windows (cmd):
.venv\Scripts\activate
# On Windows (PowerShell):
.\.venv\Scripts\Activate.ps1

# Now you're ready to install packages like `morphcloud`
```

### Installation

```bash
# Using uv (recommended)
uv pip install morphcloud --upgrade

# Or using traditional pip
pip install morphcloud --upgrade
```

## Command Line Interface

The SDK includes a comprehensive command-line interface.

### Global Options

```bash
# Display version
morphcloud --version

# Get help
morphcloud --help
```

### Images

```bash
# List available images
morphcloud image list [--json]
```

### Snapshots

```bash
# List all snapshots
morphcloud snapshot list [--json] [--metadata KEY=VALUE]

# Create a new snapshot
morphcloud snapshot create --image-id <id> --vcpus <n> --memory <mb> --disk-size <mb> [--digest <hash>] [--metadata KEY=VALUE]

# Get detailed snapshot information
morphcloud snapshot get <snapshot-id>

# Delete a snapshot
morphcloud snapshot delete <snapshot-id>

# Set metadata on a snapshot
morphcloud snapshot set-metadata <snapshot-id> KEY1=VALUE1 [KEY2=VALUE2...]
```

### Instances

```bash
# List all instances
morphcloud instance list [--json] [--metadata KEY=VALUE]

# Start a new instance from snapshot
morphcloud instance start <snapshot-id> [--json] [--metadata KEY=VALUE] [--ttl-seconds <seconds>] [--ttl-action stop|pause]

# Pause an instance
morphcloud instance pause <instance-id>

# Resume a paused instance
morphcloud instance resume <instance-id>

# Stop an instance
morphcloud instance stop <instance-id>

# Get instance details
morphcloud instance get <instance-id>

# Create snapshot from instance
morphcloud instance snapshot <instance-id> [--digest <hash>] [--json]

# Create multiple instances from an instance (branching)
morphcloud instance branch <instance-id> [--count <n>] [--json]

# Set metadata on an instance
morphcloud instance set-metadata <instance-id> KEY1=VALUE1 [KEY2=VALUE2...]
```

### Instance Management

```bash
# Execute command on instance
morphcloud instance exec <instance-id> <command>

# SSH into instance
morphcloud instance ssh <instance-id> [--rm] [--snapshot] [command]

# Port forwarding
morphcloud instance port-forward <instance-id> <remote-port> [local-port]

# Expose HTTP service
morphcloud instance expose-http <instance-id> <name> <port> [--auth-mode none|api_key]

# Hide HTTP service
morphcloud instance hide-http <instance-id> <name>
```

### File Transfer

```bash
# Copy files to/from an instance
morphcloud instance copy <source> <destination> [--recursive]

# Examples:
# Local to remote
morphcloud instance copy ./local_file.txt inst_123:/remote/path/
# Remote to local
morphcloud instance copy inst_123:/remote/file.log ./local_dir/
# Copy directory recursively
morphcloud instance copy -r ./local_dir inst_123:/remote/dir
```

### Interactive Tools

```bash
# Start an interactive chat session with an instance
# Note: Requires ANTHROPIC_API_KEY environment variable
morphcloud instance chat <instance-id> [instructions]

# Start a computer MCP session with an instance
# Note: Requires "morphcloud[computer]" installation
morphcloud instance computer-mcp <instance-id>
```

### Development Installation

For developers who want to contribute to Morph Cloud:

```bash
# Clone the repository
git clone https://github.com/your-org/morphcloud.git
cd morphcloud

# Install in development mode with dev dependencies
uv pip install -e ".[dev]"

# To also include Computer SDK for development
uv pip install -e ".[dev,computer]"
```

### Configuration

Set your API key as an environment variable:

```bash
# On macOS/Linux
export MORPH_API_KEY="your-api-key"

# On Windows (PowerShell)
$env:MORPH_API_KEY="your-api-key"

# On Windows (cmd)
set MORPH_API_KEY=your-api-key
```

## Python API

### Basic Usage

```python
from morphcloud.api import MorphCloudClient

# Initialize the client
client = MorphCloudClient()

# List available base images
print("\n\nAvailable base images:")
images = client.images.list()
for image in images:
    print(f"  {image.id}:\t{image.name}")

# Create a snapshot from a base image
print("\nCreating snapshot from base image...", end="")
snapshot = client.snapshots.create(
    image_id="morphvm-minimal",
    vcpus=1,
    memory=512,
    disk_size=1024
)
print("done")

# Start an instance from the snapshot
print("Starting instance from snapshot.....", end="")
instance = client.instances.start(snapshot_id=snapshot.id)
print("done")


# Wait for the instance to be ready
print("Waiting until instance is ready.....", end="")
instance.wait_until_ready()
print("done")


# Stop the instance when done
print("Stopping the instance...............", end="")
instance.stop()
print("done\n")
```

### Working with SSH

```python
from morphcloud.api import MorphCloudClient

client = MorphCloudClient()
snapshot = client.snapshots.create(vcpus=1, memory=512, disk_size=1024, image_id="morphvm-minimal")

# Using context managers for automatic cleanup
with client.instances.start(snapshot_id=snapshot.id) as instance:
    instance.wait_until_ready()
    
    # Connect via SSH and run commands
    with instance.ssh() as ssh:
        # Run a basic command
        result = ssh.run("echo 'Hello from MorphCloud!'")
        print(result.stdout)
        
        # Install packages
        ssh.run("apt-get update && apt-get install -y python3-pip").raise_on_error()
        
        # Upload a local file to the instance
        ssh.copy_to("./local_script.py", "/home/user/remote_script.py")
        
        # Execute the uploaded script
        ssh.run("python3 /home/user/remote_script.py")
        
        # Download a file from the instance
        ssh.copy_from("/home/user/results.txt", "./local_results.txt")
```

### HTTP Services and Port Forwarding

```python
import time
import requests
from morphcloud.api import MorphCloudClient

client = MorphCloudClient()
snapshot = client.snapshots.get("your_snapshot_id")  # Use an existing snapshot

with client.instances.start(snapshot_id=snapshot.id) as instance:
    instance.wait_until_ready()
    
    with instance.ssh() as ssh:
        # Start a simple HTTP server on the instance
        ssh.run("python3 -m http.server 8080 &")
        
        # Method 1: Expose as HTTP service with public URL
        service_url = instance.expose_http_service("my-service", 8080)
        print(f"Service available at: {service_url}")
        
        # Method 2: Create an SSH tunnel for local port forwarding
        with ssh.tunnel(local_port=8888, remote_port=8080):
            time.sleep(1)  # Give the tunnel time to establish
            response = requests.get("http://localhost:8888")
            print(response.text)
```

### Advanced: Snapshot Chains and Caching

One of Morph Cloud's powerful features is the ability to create chains of snapshots with cached operations:

```python
from morphcloud.api import MorphCloudClient

client = MorphCloudClient()
base_snapshot = client.snapshots.get("your_base_snapshot_id")

# Each exec operation creates a new snapshot that includes the changes
# If you run the same command again, it will use the cached snapshot
python_snapshot = base_snapshot.exec("apt-get update && apt-get install -y python3 python3-pip")
numpy_snapshot = python_snapshot.exec("pip install numpy pandas matplotlib")

# Upload local files to a snapshot and create a new snapshot with those files
data_snapshot = numpy_snapshot.upload("./data/", "/home/user/data/", recursive=True)

# Run your analysis on the data
results_snapshot = data_snapshot.exec("python3 /home/user/data/analyze.py")

# Start an instance from the final snapshot with all changes applied
instance = client.instances.start(snapshot_id=results_snapshot.id)
```

### Docker Container Integration

Set up instances that automatically redirect to Docker containers:

```python
from morphcloud.api import MorphCloudClient

client = MorphCloudClient()
base_snapshot = client.snapshots.get("your_base_snapshot_id")

# Create a snapshot with a PostgreSQL container
postgres_snapshot = base_snapshot.as_container(
    image="postgres:13",
    container_name="postgres",
    env={"POSTGRES_PASSWORD": "example"},
    ports={5432: 5432}
)

# When you start an instance from this snapshot, all SSH sessions
# will automatically connect to the container instead of the host
with client.instances.start(snapshot_id=postgres_snapshot.id) as instance:
    instance.wait_until_ready()
    
    # This SSH session will connect directly to the container
    with instance.ssh() as ssh:
        ssh.run("psql -U postgres")
```

### Experimental: Computer SDK

The Computer SDK provides advanced browser automation and interactive capabilities for instances. Contact the [Morph team](mailto:jesse@morph.so) for preview access to the Morph Cloud Computer snapshot. This requires installing the `computer` extra:

```python
# First ensure you've installed: uv pip install "morphcloud[computer]"

from morphcloud.api import MorphCloudClient
from morphcloud.computer import Computer

# Initialize the client
client = MorphCloudClient()

# Use an existing instance
instance = client.instances.get("your_instance_id")

# Convert to a Computer instance
computer = Computer(instance)

# Use the browser automation
browser = computer.browser
browser.connect()
browser.goto("https://example.com")
screenshot = browser.screenshot()
browser.click(100, 200)
browser.type("Hello World")

# Clean up when done
browser.close()
```

### Asynchronous API

Morph Cloud also provides asynchronous versions of all methods:

```python
import asyncio
from morphcloud.api import MorphCloudClient

async def main():
    client = MorphCloudClient()
    
    # Async list images
    images = await client.images.alist()
    
    # Async create snapshot
    snapshot = await client.snapshots.acreate(
        image_id="morphvm-minimal", 
        vcpus=1, 
        memory=512, 
        disk_size=1024
    )
    
    # Async start instance
    instance = await client.instances.astart(snapshot_id=snapshot.id)
    
    # Async wait for ready
    await instance.await_until_ready()
    
    # Async stop instance
    await instance.astop()

asyncio.run(main())
```

### User

Minimal examples for managing your account:

```
# List your API keys
morphcloud user api-key list

# Create a new API key (shows the key once)
morphcloud user api-key create

# Delete an API key
morphcloud user api-key delete <api_key_id>

# Get your SSH public key
morphcloud user ssh-key get

# Set/update your SSH public key
morphcloud user ssh-key set --public-key "ssh-rsa AAAA..."

# View usage (3-hour lookback by default; supports 30m, 3h, 7d, etc.)
morphcloud user usage --interval 3h
```

## Advanced Features

### Environment Variables

- `MORPH_API_KEY`: Your Morph Cloud API key
- `MORPH_BASE_URL`: Override the default API URL (defaults to "https://cloud.morph.so/api")
- `MORPH_SSH_HOSTNAME`: Override the SSH hostname (defaults to "ssh.cloud.morph.so")
- `MORPH_SSH_PORT`: Override the SSH port (defaults to 22)

## Support

For issues, questions, or feature requests, please contact us at:
[contact@morph.so](mailto:contact@morph.so)
