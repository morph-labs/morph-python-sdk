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
morphcloud snapshot create --image-id <id> --vcpus <n> --memory <mb> --disk-size <mb> [--digest <hash>] [--ttl-seconds <seconds>] [--metadata KEY=VALUE]

# Get detailed snapshot information
morphcloud snapshot get <snapshot-id>

# Delete a snapshot
morphcloud snapshot delete <snapshot-id>

# Set metadata on a snapshot
morphcloud snapshot set-metadata <snapshot-id> KEY1=VALUE1 [KEY2=VALUE2...]

# Set or clear snapshot retention
morphcloud snapshot set-ttl <snapshot-id> --ttl-seconds <seconds|-1>
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

# Reboot an instance
morphcloud instance reboot <instance-id>

# Stop an instance
morphcloud instance stop <instance-id>

# Get instance details
morphcloud instance get <instance-id>

# Create snapshot from instance
morphcloud instance snapshot <instance-id> [--digest <hash>] [--ttl-seconds <seconds>] [--json]

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
```

### Devboxes

Devboxes are remote development environments managed by Morph Cloud (separate from instances).

```bash
# List devboxes
morphcloud devbox list [--json]

# Start a devbox from a template (instant start)
morphcloud devbox start <template-id> [--name <name>] [--metadata KEY=VALUE] [--json]

# SSH into a devbox
morphcloud devbox ssh <devbox-id> [command...]
```

#### Devbox Template Workflows

`morphcloud devbox template run` drives the full template workflow from the terminal. Targets that begin with `tpl_` resolve as template ids. Any other target resolves as a shared/public alias. If you omit the target entirely, the runner opens an interactive browser for owned templates plus shared-alias search.

```bash
# Run an owned template directly
morphcloud devbox template run tpl_123

# Run a shared/public alias directly
morphcloud devbox template run demo-alias

# Browse owned templates and search aliases interactively
morphcloud devbox template run

# Pass workflow params and runtime secrets for this run
morphcloud devbox template run tpl_123 --param BRANCH=main --secret OPENAI_API_KEY=... --force

# Attach to an in-flight workflow run
morphcloud devbox template run tpl_123 --attach run_123

# Script-friendly output modes
morphcloud devbox template run tpl_123 --plain
morphcloud devbox template run tpl_123 --json
```

When an `exportSecret` step pauses the workflow, the runner can:

- use an already-saved Morph secret,
- accept a one-off value for the current run,
- save a newly entered value to your Morph secrets and continue,
- or skip an optional secret immediately.

Optional secrets surface the backend countdown in the TUI/plain prompt, and the completion view prints the created devbox id, exposed service URLs, and next-step commands such as `morphcloud devbox ssh ...` and `morphcloud devbox terminal connect ...`.

Shared/public templates can be launched without `MORPH_API_KEY` as long as you provide a devbox-service key via `MNW_DEVBOX_SERVICE_API_KEY` or `MORPH_DEVBOX_SERVICE_API_KEY`. Anonymous runs still support per-run `--secret KEY=VALUE` overrides, but saved Morph secrets remain available only to authenticated user runs.

`--experimental-run-locally` executes a local template YAML file with the same TUI/plain presenter stack. If `TARGET` is not a local file, the CLI fetches `https://morph.new/{alias}/yaml` and runs that YAML locally instead.

```bash
# Execute a local template YAML in the template TUI
morphcloud devbox template run ./template.yaml --experimental-run-locally

# Or execute a shared alias by fetching morph.new/{alias}/yaml first
morphcloud devbox template run opengauss --experimental-run-locally

# Local mode supports params and per-run secret values too
morphcloud devbox template run ./template.yaml --experimental-run-locally --param BRANCH=main --secret TOKEN=abc123
```

#### Devbox Terminals (tmux)

Devbox "terminals" are durable tmux sessions managed via the devbox service.

```bash
# List terminals (tmux sessions)
morphcloud devbox terminal list <devbox-id> [--json]

# Start a new terminal (auto-installs tmux if needed)
morphcloud devbox terminal start <devbox-id> [--name <session-name>] [--json]

# Connect to a terminal over SSH (requires a TTY)
morphcloud devbox terminal connect <devbox-id> <session-name-or-id> [--command '<cmd>']
```

```python
from morphcloud.api import MorphCloudClient

client = MorphCloudClient()

# List devboxes
devboxes = client.devbox.devboxes_core.list_devboxes()
print(devboxes)

# Start a devbox from a template (instant start)
devbox = client.devbox.start(template_id="tpl_123", name="my-devbox")
print(devbox.id)

# List terminals (tmux sessions)
terminals = client.devbox.terminals.list(devbox.id)
print(terminals.tmux_installed, terminals.sessions)

# Start a terminal (tmux session)
started = client.devbox.terminals.start(devbox.id, name="my-session")
print(started.session.name)
```

### Development Installation

For developers who want to contribute to Morph Cloud:

```bash
# Clone the repository
git clone https://github.com/your-org/morphcloud.git
cd morphcloud

# Install in development mode with dev dependencies
uv pip install -e ".[dev]"


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

### Snapshot TTL

```python
from morphcloud.api import MorphCloudClient

client = MorphCloudClient()

snapshot = client.snapshots.create(
    image_id="morphvm-minimal",
    vcpus=1,
    memory=512,
    disk_size=1024,
    ttl_seconds=3600,  # auto-delete after 1 hour of inactivity
)

print(snapshot.ttl.ttl_seconds)
print(snapshot.ttl.ttl_expire_at)

# Update an existing snapshot TTL
snapshot.set_ttl(7200)

# Clear the snapshot TTL entirely
snapshot.set_ttl(None)
```

CLI equivalents:

```bash
morphcloud snapshot create \
  --image-id morphvm-minimal \
  --vcpus 1 \
  --memory 512 \
  --disk-size 1024 \
  --ttl-seconds 3600

morphcloud snapshot set-ttl snapshot_123 --ttl-seconds 7200
morphcloud snapshot set-ttl snapshot_123 --ttl-seconds -1
morphcloud instance snapshot instance_123 --ttl-seconds 3600
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

### Profiles

The CLI/SDK support named profiles for switching between prod/stage/dev environments
without constantly exporting env vars.

```bash
# Create a profile
morphcloud profile set stage \
  --api-key "$MORPH_API_KEY" \
  --api-host "stage.morph.so"

# Use it for one command (kubectl-style)
morphcloud --profile stage instance list

# Or set it as the active profile
morphcloud profile use stage
```

To export env vars for other services/scripts:
```bash
eval "$(morphcloud profile env stage)"
```

### Environment Variables

- `MORPH_API_KEY`: Your Morph Cloud API key
- `MORPH_ENV`: Convenience switch for `prod`/`stage` defaults when no explicit host/base URL is provided
- `MORPH_PROFILE`: Select a named profile
- `MORPH_BASE_URL`: Override the default API URL (defaults to "https://cloud.morph.so/api")
- `MORPH_API_HOST`: Override API host used to derive defaults (e.g., "stage.morph.so")
- `MORPH_SSH_HOSTNAME`: Override the SSH hostname (defaults to "ssh.cloud.morph.so")
- `MORPH_SSH_PORT`: Override the SSH port (defaults to 22)
- `MORPH_SERVICE_BASE_URL`: Override the services API base URL
- `MORPH_DEVBOX_BASE_URL`: Override the devbox service base URL (defaults to "https://devbox.svc.<api_host>")
- `MORPH_ADMIN_BASE_URL`: Override the admin API base URL
- `MORPH_DB_BASE_URL`: Override the db API base URL

## Support

For issues, questions, or feature requests, please contact us at:
[contact@morph.so](mailto:contact@morph.so)
