# MorphCloud Python SDK 

## Overview

MorphCloud is a platform designed to spin up remote AI devboxes we call runtimes.
It provides a suite of code intelligence tools and a Python SDK to manage, create, delete, and interact with runtime instances.

## Setup Guide

### Prerequisites

Python 3.11 or higher

Go to [https://cloud.morph.so](https://cloud.morph.so/web/api-keys), log in with the provided credentials and create an API key.

Set the API key as an environment variable  `MORPH_API_KEY`.

### Installation

```
pip install morphcloud
```

Export the API key:

```
export MORPH_API_KEY="your-api-key"
```

## Python API

The SDK provides a Python API to interact with the MorphCloud API.

The following example creates a minimal vm snapshot, starts and instance then sets up a simple HTTP server and makes an HTTP request to it.

```py
import time
import requests
import tempfile
from morphcloud.api import MorphCloudClient

# Connect to the MorphCloud API
# The API key can be set through the client or as an environment variable MORPH_API_KEY
client = MorphCloudClient()

# Create a snapshot with 1 vCPU, 128MB memory, 700MB disk size, and the image "morphvm-minimal"
snapshot = client.snapshots.create(vcpus=1, memory=128, disk_size=700, image_id="morphvm-minimal")

# Start an instance from the snapshot and open an SSH connection
with client.instances.start(snapshot_id=snapshot.id) as instance, instance.ssh() as ssh:
    # Install uv and python using the ssh connection
    ssh.run(["curl -LsSf https://astral.sh/uv/install.sh | sh"]).raise_on_error()
    ssh.run(["echo 'source $HOME/.local/bin/env' >> $HOME/.bashrc"]).raise_on_error()
    ssh.run(["uv", "python", "install"]).raise_on_error()

    # Create an index.html file locally and copy it to the instance
    with tempfile.NamedTemporaryFile(mode="w") as f:
        f.writelines("<h1>Hello, World!</h1>")
        f.flush()
        ssh.copy_to(f.name, "index.html")

    # Start an HTTP server on the instance with a tunnel to the local machine and run it in the background
    with ssh.run(["uv", "run", "python3", "-m", "http.server", "8080", "--bind", "127.0.0.1"], background=True) as http_server, \
         ssh.tunnel(local_port=8888, remote_port=8080) as tunnel:

        # Wait for the HTTP server to start
        time.sleep(1)

        print("HTTP Server:", http_server.stdout)

        print("Making HTTP request")
        response = requests.get("http://127.0.0.1:8888", timeout=10)
        print("HTTP Response:", response.status_code)
        print(response.text)
```

## Command Line Interface

The SDK also provides a command line interface to interact with the MorphCloud API.
You can use the CLI to create, delete, and manage runtime instances.

### Images

List available images:
```bash
morphcloud image list [--json]
```

### Snapshots

```bash
# List all snapshots
morphcloud snapshot list [--json]

# Create a new snapshot
morphcloud snapshot create --image-id <id> --vcpus <n> --memory <mb> --disk-size <mb> [--digest <hash>]

# Delete a snapshot
morphcloud snapshot delete <snapshot-id>
```

### Instances

```bash
# List all instances
morphcloud instance list [--json]

# Start a new instance from snapshot
morphcloud instance start <snapshot-id> [--json]

# Pause an instance (suspends the instance and saves its state in a new snapshot)
morphcloud instance pause <instance-id>

# Resume a paused instance
morphcloud instance resume <instance-id>

# Stop an instance
morphcloud instance stop <instance-id>

# Get instance details
morphcloud instance get <instance-id>

# Create snapshot from instance
morphcloud instance snapshot <instance-id> [--json]

# Clone an instance
morphcloud instance branch <instance-id> [--count <n>]
```

### Instance Management

```bash
# Execute command on instance
morphcloud instance exec <instance-id> <command>

# SSH into instance
morphcloud instance ssh <instance-id> [command]

# Direct SSH access (alternative method)
# You can also SSH directly into a MorphVM instance using:
ssh <instance-id>@ssh.cloud.morph.so

# Port forwarding
morphcloud instance port-forward <instance-id> <remote-port> [local-port]

# Expose HTTP service
morphcloud instance expose-http <instance-id> <name> <port> [--auth-mode <mode>]
# Use --auth-mode=api_key to require API key authentication for access

# Hide HTTP service
morphcloud instance hide-http <instance-id> <name>
```

### File Transfer and Synchronization

```bash
# Copy files to/from an instance
morphcloud instance copy <source> <destination> [--recursive]

# Synchronize directories
morphcloud instance sync <source> <destination> [--delete] [--dry-run] [-v]
```

### Interactive Chat

Start an interactive chat session with an instance:

**Note:** You'll need to set `ANTHROPIC_API_KEY` environment variable to use this command.

```bash
morphcloud instance chat <instance-id> [instructions]
```
