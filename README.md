# MorphCloud Python SDK 

## Overview

MorphCloud is a platform designed to spin up remote AI devboxes we call runtimes. It provides a suite of code intelligence tools and a Python SDK to manage, create, delete, and interact with runtime instances.

## Setup Guide

### Prerequisites

Python 3.8 or higher

Go to [https//:cloud.morph.so](http://cloud.morph.so), log in with the provided credentials and create an API key.

Set the API key as an environment variable  MORPH\_API\_KEY.

### Installation

```
   git clone https://github.com/morph-labs/morph-python-sdk.git  
   cd morphcloud  
```
   (activate any python environment as needed)...  
``` 
   pip install -e .  
```

export MORPH\_API\_KEY=your\_api\_key\_here

## Quick Start

To start using MorphCloud, you can create and manage runtime instances using the provided classes and methods. Here's a basic example to create a runtime instance:

```py
from morphcloud import Runtime

runtime = Runtime.create() # This will print a url allowing you to view the runtime remote desktop url

# The runtime instance is stopped and deleted upon script termination.

# Alternatively you could create a runtime only for a specific function using:

with Runtime.create() as runtime:
     # You can perform any actions inside of the environment in here.
     # .....
     result = runtime.execute.semantic_search (query="a function that ...", max_results=5)
)
print(result) # {success:True, result: {results: [...]}}
func_refs = results [0]['refs']

linter_result = runtime.execute.lint(files = ["my_repo/file1.py", "my_repo/file2.py"])
   

# Outside of the with scope the runtime instance is stopped and deleted.
```

## Configure the Runtime

You can create a runtime environment that automatically executes a setup script in two ways:

```py
runtime = Runtime.create(setup="/local_path/to/setup_script")
# Alternatively
runtime = Runtime.create(setup=[
		"sudo apt update",
		"sudo apt install -y tmux git build-essential",		
"git clone my_public_repo_url.git"
]
```

You can also customize the VM configurations:

```py
runtime = Runtime.create(
	vcpus=2, # number of cpus
	memory=2048, # mb
)
```

## Connecting to a Runtime

If you created a runtime instance from the web UI and you wish to connect to it:

```py
from morphcloud import Runtime

runtime = Runtime.create(id=YOUR_RUNTIME_ID)

# Stop it manually on cloud.morph.so or using
runtime.stop()
```

## Saving a Runtime

To save the state of the remote runtime for future use:

```py
from morphcloud import Runtime

with Runtime.create() as runtime:
     # You can perform any actions inside of the environment in here.
     # .....
     result = runtime.execute.terminal_command(command="npm start", terminal_name="optional_name")) # This will run async on the runtime environment.
terminal_status = runtime.execute.observe_terminals() # This will return a dict with the most recent outputs of all active terminals in the runtime.
snapshot_id = runtime.snapshot.create()


Runtime.snapshot.list() # returns a list of all snapshot_ids 

```

To create a new runtime instance from the same point where `npm start` is running:

```py
runtime = Runtime.create(snapshot_id = YOUR_SNAPSHOT_ID)

# To delete a snapshot
_ = Runtime.snapshot.delete(YOUR_SNAPSHOT_ID)
```

### Cloning

If you would like to run multiple instances in parallel to do a task in the same environment:

```py
from morphcloud import Runtime

runtime = Runtime.create()
# You can perform any actions inside of the environment in here.
# .....
runtimes = runtime.clone(5) # creates a list of 5 runtime objects.

for r in runtimes:
	# do stuff...

# all runtime instances are terminated upon script completion. 
```

## AI Integration

MorphCloud provides built-in support for integrating with AI models through standardized tool formats. You can easily convert runtime actions to formats compatible with popular AI models:

```python
from morphcloud import Runtime

runtime = Runtime.create()

# Get tools in Anthropic's format
anthropic_tools = runtime.actions.as_anthropic_tools()

# Get tools in OpenAI's function calling format
openai_tools = runtime.actions.as_openai_tools()

```

## Examples

There are several examples in the `examples` directory. Notably, there are two key examples: [search.py](https://github.com/morph-labs/morphcloud/blob/main/examples/search.py), which showcases repository cloning, semantic code search, and function analysis, and [agent_skeleton.py](https://github.com/morph-labs/morphcloud/blob/main/examples/agent_skeleton.py), which provides a good starting point to create simple AI agents that interact with the cloud development environment. 
