# Copyright (c) 2024 Morph Labs
# All rights reserved.
# This source code is licensed under the terms found in the
# LICENSE file in the root directory of this source tree.

# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "morphcloud",
#     "anthropic",
#     "pydantic",
#     "pyyaml",
#     "dataclasses",
#     "fire",
#     "enum34",
# ]
# ///

import asyncio
import io
import json
# Standard library imports
import os
import signal
import sys
import time
import uuid
from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, Set, Tuple, Union

import anthropic
import fire
import yaml
from anthropic import Anthropic, AsyncAnthropic
# Third-party imports
from pydantic import BaseModel

# Client imports
from morphcloud.api import Instance, MorphCloudClient


# Type Definitions
@dataclass
class Image:
    """Represents an image for multimodal LLM communication."""

    data: str  # Base64-encoded image data
    mime_type: str
    size: Optional[Dict[str, int]] = None  # width and height if available


@dataclass
class Message:
    """Enhanced message interface for LLM communication with image support."""

    role: str
    content: str
    images: Optional[List[Image]] = None
    tools: Optional[List[Dict[str, Any]]] = None

    def dict(self) -> Dict[str, Any]:
        """Convert message to dictionary representation."""
        return {
            "role": self.role,
            "content": self.content,
            "images": [img.__dict__ for img in self.images] if self.images else None,
            "tools": self.tools,
        }


@dataclass
class LLMResponse:
    """Enhanced LLM response interface with image support."""

    content: str
    tool_calls: Optional[List[Dict[str, Any]]] = None
    image_references: Optional[List[str]] = (
        None  # References to images discussed in response
    )


class ParameterType(str, Enum):
    STRING = "string"
    NUMBER = "number"
    BOOLEAN = "boolean"
    OBJECT = "object"
    ARRAY = "array"
    INTEGER = "integer"
    NULL = "null"


@dataclass(frozen=True)
class ToolParameter:
    """Describes a single parameter for a tool."""

    name: str
    type: ParameterType
    description: str
    optional: bool = False
    default: Any = None


@dataclass(frozen=True)
class PropertySchema:
    """Describes a property in a return type schema."""

    type: ParameterType
    description: Optional[str] = None
    properties: Optional[Dict[str, "PropertySchema"]] = None


@dataclass(frozen=True)
class ReturnSchema:
    """Describes the return type of a tool."""

    type: ParameterType
    properties: Optional[Dict[str, PropertySchema]] = None
    description: Optional[str] = None


@dataclass(frozen=True)
class Tool:
    """
    Enhanced tool representation with detailed schema information.
    """

    name: str
    description: str
    parameters: List[ToolParameter]
    returns: ReturnSchema
    examples: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert tool to dictionary format for LLM API consumption."""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    param.name: {
                        "type": param.type.value,
                        "description": param.description,
                    }
                    for param in self.parameters
                },
                "required": [
                    param.name for param in self.parameters if not param.optional
                ],
            },
        }

    def as_anthropic_tool(self) -> Dict[str, Any]:
        """
        Returns a dictionary formatted for Anthropic's function calling API.

        The description field includes a formatted summary of:
        - Tool description
        - Return type information
        - Usage examples

        The parameters field contains the JSON Schema of the function inputs.

        Returns:
            Dict[str, Any]: Dictionary with 'name', 'description', and 'parameters' keys
        """
        # Build the complete description starting with the tool's main description
        description_parts = [
            self.description.strip(),
        ]

        # Add return type information
        description_parts.append("\nReturns:")
        if self.returns.properties:
            description_parts.append(f"Object with properties:")
            for prop_name, prop in self.returns.properties.items():
                description_parts.append(
                    f"- {prop_name}: {prop.type.value}"
                    + (f"\n  {prop.description}" if prop.description else "")
                )
        else:
            description_parts.append(
                f"{self.returns.type.value}"
                + (f": {self.returns.description}" if self.returns.description else "")
            )

        # Add examples if available
        if self.examples:
            description_parts.append("\nExamples:")
            for example in self.examples:
                description_parts.append(f"- {example}")

        # Construct the input schema according to Anthropic's tool-use API
        parameters_schema = {"type": "object", "properties": {}, "required": []}

        for param in self.parameters:
            # Add parameter to properties
            param_schema = {"type": param.type.value, "description": param.description}

            # Add default value if present
            if param.default is not None:
                param_schema["default"] = param.default

            parameters_schema["properties"][param.name] = param_schema

            # Add to required list if parameter is not optional
            if not param.optional:
                parameters_schema["required"].append(param.name)

        return {
            "name": self.name,
            "description": "\n".join(description_parts),
            "input_schema": parameters_schema,
        }


class TaskStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class Task:
    """
    Immutable task representation with dependency tracking.
    """

    name: str
    description: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: TaskStatus = TaskStatus.PENDING
    parent_id: Optional[str] = None
    subtasks: List["Task"] = field(default_factory=list)
    dependencies: Set[str] = field(
        default_factory=set
    )  # Set of task IDs this task depends on

    def with_status(self, status: TaskStatus) -> "Task":
        """Create new task with updated status."""
        return dataclasses.replace(self, status=status)

    def with_subtask(self, subtask: "Task") -> "Task":
        """Create new task with additional subtask."""
        return dataclasses.replace(self, subtasks=[*self.subtasks, subtask])

    def with_dependency(self, dependency_id: str) -> "Task":
        """Create new task with additional dependency."""
        return dataclasses.replace(
            self, dependencies={*self.dependencies, dependency_id}
        )

    def with_dependencies(self, dependency_ids: Set[str]) -> "Task":
        """Create new task with a set of dependencies."""
        return dataclasses.replace(
            self, dependencies={*self.dependencies, *dependency_ids}
        )

    def remove_dependency(self, dependency_id: str) -> "Task":
        """Create new task with a dependency removed."""
        new_dependencies = self.dependencies - {dependency_id}
        return dataclasses.replace(self, dependencies=new_dependencies)

    def is_ready(self, completed_tasks: Set[str]) -> bool:
        """
        Check if task is ready to be executed based on its dependencies.

        Args:
            completed_tasks: Set of task IDs that have been completed

        Returns:
            bool: True if all dependencies are satisfied, False otherwise
        """
        return self.dependencies.issubset(completed_tasks)


@dataclass(frozen=True)
class Result:
    """
    Immutable result of tool execution.
    """

    success: bool
    data: Any = None
    error: Optional[Exception] = None


@dataclass(frozen=True)
class Observation:
    """
    Immutable snapshot of environment state.
    """

    screenshot: Optional[str]
    workspace_state: Dict[str, Any]
    available_tools: List[Tool]


# Core Configuration
MODEL_NAME = "claude-3-5-sonnet-20241022"
ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]
MAX_TOKENS = 4096

COLORS = {
    "PRIMARY": "\033[32m",
    "HIGHLIGHT": "\033[31m",
    "TEXT": "\033[39m",
    "SECONDARY": "\033[90m",
    "OUTPUT_HEADER": "\033[34m",
    "SUCCESS": "\033[32m",
    "ERROR": "\033[31m",
    "RESET": "\033[0m",
}

# Initialize client that's used throughout
CLIENT = MorphCloudClient()

##############################################################################
# Message Processing Helper Functions
##############################################################################


def maybe_truncate_text(text: str, max_length: int = 2000) -> str:
    """
    Truncate the text if it exceeds max_length to avoid prompt overflow.
    You could also do summarization instead of a hard cut.
    """
    if len(text) > max_length:
        return text[:max_length] + "...[truncated]"
    return text


def maybe_truncate_text_from_left(text: str, max_length: int = 32768) -> str:
    """
    Truncate the text if it exceeds max_length to avoid prompt overflow.
    You could also do summarization instead of a hard cut.
    """
    if len(text) > max_length:
        return "[truncated]...\n\n" + text[-max_length:]
    return text


def add_cache_control_to_last_content(
    messages, cache_control={"type": "ephemeral"}, max_cache_controls=4
):
    import copy

    if not messages:
        return messages

    new_messages = copy.deepcopy(messages)

    cache_control_count = sum(
        1
        for msg in new_messages
        for content in (
            msg["content"]
            if isinstance(msg.get("content"), list)
            else [msg.get("content")]
        )
        if isinstance(content, dict) and "cache_control" in content
    )

    if cache_control_count >= max_cache_controls:
        return new_messages

    last_message = new_messages[-1]
    if isinstance(last_message.get("content"), list) and last_message["content"]:
        last_content = last_message["content"][-1]
        if (
            isinstance(last_content, dict)
            and "type" in last_content
            and "cache_control" not in last_content
        ):
            last_content["cache_control"] = cache_control
    elif isinstance(last_message.get("content"), dict):
        if "cache_control" not in last_message["content"]:
            last_message["content"]["cache_control"] = cache_control

    return new_messages


def count_tokens(
    client: Anthropic, system: str, messages: List[Dict], tools: List[Dict]
) -> int:
    """
    Count tokens
    """
    return client.messages.count_tokens(
        model=MODEL_NAME,
        system=system,
        messages=add_cache_control_to_last_content(messages),
        tools=tools,  # type: ignore
    )["input_tokens"]


def maybe_truncate_messages(
    messages: List[Dict], threshold: int = 175_000, chunk_size: int = 25_000
) -> List[Dict]:
    """
    Truncates the message history if it exceeds a token threshold by removing older messages.

    Args:
        messages: List of message dictionaries containing role and potentially usage information
        threshold: Token count threshold that triggers truncation
        chunk_size: Minimum number of tokens to remove when truncating

    Returns:
        List[Dict]: Truncated message list if threshold was exceeded, original list otherwise
    """
    # Create a list to store (position, input_tokens) pairs for assistant messages
    token_positions: List[Tuple[int, int]] = []

    # Scan messages backwards to find assistant messages with token usage info
    for i in range(len(messages) - 1, -1, -1):
        msg = messages[i]
        if (
            msg.get("role") == "assistant"
            and isinstance(msg.get("usage"), dict)
            and isinstance(msg["usage"].get("input_tokens"), int)
        ):
            token_positions.append((i, msg["usage"]["input_tokens"]))

    # If no valid assistant messages found or last message doesn't exceed threshold, return original
    if not token_positions or token_positions[0][1] <= threshold:
        return messages

    # Calculate token differences between positions to determine how many messages to drop
    token_diffs = []
    for i in range(len(token_positions) - 1):
        diff = token_positions[i][1] - token_positions[i + 1][1]
        token_diffs.append((token_positions[i + 1][0], diff))

    # Find position to truncate from that removes at least chunk_size tokens
    cumulative_tokens = 0
    truncate_pos = 0

    for pos, diff in token_diffs:
        cumulative_tokens += diff
        if cumulative_tokens >= chunk_size:
            truncate_pos = pos
            break

    # If we couldn't find a position that removes enough tokens,
    # truncate from the earliest assistant message position we found
    if cumulative_tokens < chunk_size and token_positions:
        truncate_pos = token_positions[-1][0]

    # Return truncated message list
    return messages[truncate_pos + 1 :]


async def call_model(
    client: AsyncAnthropic, system: str, messages: List[Dict], tools: List[Dict]
):
    """
    Calls Anthropic's streaming API with the given messages and tools.
    """
    return await client.messages.create(
        model=MODEL_NAME,
        system=system,
        messages=add_cache_control_to_last_content(messages),
        max_tokens=MAX_TOKENS,
        tools=tools,  # type: ignore
        stream=True,
        extra_headers={"anthropic-beta": "prompt-caching-2024-07-31"},
    )  # type: ignore


async def process_assistant_message(
    response_stream, chunk_callback=None
) -> Tuple[Dict, bool]:
    """
    Consumes a streaming response from Claude, reconstructs the final assistant message,
    and returns (assistant_message, tool_use_active).
    """
    response_msg = {"role": "assistant", "content": []}
    content_block_type = None
    content_acc = io.StringIO()

    # Previously was a global; now local only
    current_tool_block = None

    def flush_content():
        nonlocal current_tool_block, content_block_type
        if content_block_type == "text":
            text_block = content_acc.getvalue()
            if text_block.strip():
                response_msg["content"].append({"type": "text", "text": text_block})

        elif content_block_type == "tool_use":
            tool_input_json = content_acc.getvalue()
            tool_input = {}
            if tool_input_json.strip():
                try:
                    # Graceful parse
                    tool_input = json.loads(tool_input_json)
                except json.JSONDecodeError:
                    # Fall back to empty input
                    tool_input = {}
            if current_tool_block is not None:
                current_tool_block["input"] = tool_input
                response_msg["content"].append(current_tool_block)

        # Reset accumulators
        content_acc.seek(0)
        content_acc.truncate()
        current_tool_block = None
        content_block_type = None

    tool_use_active = False

    async for chunk in response_stream:
        if chunk.type == "message_start":
            continue
        elif chunk.type == "content_block_start":
            # flush any previous content
            flush_content()

            block_type = chunk.content_block.type
            if block_type == "tool_use":
                tool_use_active = True
                current_tool_block = {
                    "type": "tool_use",
                    "name": chunk.content_block.name,
                    "id": chunk.content_block.id,
                }

            content_block_type = block_type

        elif chunk.type == "content_block_delta":
            if content_block_type == "text":
                text_delta = chunk.delta.text
                if chunk_callback:
                    chunk_callback(text_delta)
                content_acc.write(text_delta)
            elif content_block_type == "tool_use":
                content_acc.write(chunk.delta.partial_json)

        elif chunk.type == "content_block_stop":
            flush_content()

    # Flush at the end in case there's any leftover text
    flush_content()

    return response_msg, tool_use_active


##############################################################################
# Tool Definitions & Runtime Implementation
##############################################################################

done_command = Tool(
    name="done",
    description="Signal that you're done.",
    parameters=[],
    returns=ReturnSchema(type=ParameterType.NULL, description="null"),
)

run_command = Tool(
    name="run_command",
    description="Execute a command on a remote MorphVM instance via SSH.",
    parameters=[
        ToolParameter(
            name="command",
            description="The shell command to execute on the remote MorphVM instance.",
            type=ParameterType.STRING,
            optional=False,
        )
    ],
    returns=ReturnSchema(
        type=ParameterType.OBJECT,
        description="Object containing the outcome of the remote command execution.",
        properties={
            "exit_code": ToolParameter(
                name="exit_code",
                description="Numeric exit code returned by the command.",
                type=ParameterType.INTEGER,
            ),
            "stdout": ToolParameter(
                name="stdout",
                description="Standard output captured from the command.",
                type=ParameterType.STRING,
            ),
            "stderr": ToolParameter(
                name="stderr",
                description="Standard error captured from the command.",
                type=ParameterType.STRING,
            ),
        },
    ),
    examples=[
        # These examples illustrate how the model might invoke this tool.
        '{"command": "ls -al"}',
        '{"command": "cat /etc/os-release"}',
        '{"command": "echo Hello && uname -a"}',
    ],
)


def ssh_connect_and_run(instance: Instance, command: str) -> Dict[str, Any]:
    """Execute a command over SSH with real-time output streaming"""
    with instance.ssh() as ssh:
        # Get ANSI color codes ready
        OUTPUT_HEADER = COLORS["OUTPUT_HEADER"]
        print(f"\n{COLORS['SECONDARY']}{'─' * 50}{COLORS['RESET']}")
        print(f"\n{OUTPUT_HEADER}Output:{COLORS['RESET']}")

        last_stdout = ""
        last_stderr = ""

        # Run the command in background to get real-time output
        with ssh.run(command, background=True, get_pty=True) as process:
            while True:
                # Print stdout in real-time
                current_stdout = process.stdout
                if current_stdout != last_stdout:
                    new_output = current_stdout[len(last_stdout) :]
                    print(
                        f"{COLORS['TEXT']}{new_output}{COLORS['RESET']}",
                        end="",
                        flush=True,
                    )
                    last_stdout = current_stdout

                # Print stderr in real-time
                current_stderr = process.stderr
                if current_stderr != last_stderr:
                    new_stderr = current_stderr[len(last_stderr) :]
                    print(
                        f"{COLORS['HIGHLIGHT']}[stderr] {new_stderr}{COLORS['RESET']}",
                        end="",
                        flush=True,
                    )
                    last_stderr = current_stderr

                # Check if process is done
                if process.completed:
                    break

                time.sleep(0.01)

            # Get final output from the process
            final_stdout = process.stdout
            final_stderr = process.stderr

            # Get returncode from the channel
            returncode = process.channel.recv_exit_status()

            # Print status
            SUCCESS_COLOR = COLORS["SUCCESS"]
            ERROR_COLOR = COLORS["ERROR"]
            status_color = SUCCESS_COLOR if returncode == 0 else ERROR_COLOR

            print(f"\n{OUTPUT_HEADER}Status:{COLORS['RESET']}")
            print(
                f"{status_color}{'✓ Command succeeded' if returncode == 0 else '✗ Command failed'} (exit code: {returncode}){COLORS['RESET']}"
            )
            if final_stderr:
                print(
                    f"{ERROR_COLOR}Command produced error output - see [stderr] messages above{COLORS['RESET']}"
                )
            print(f"\n{COLORS['SECONDARY']}{'─' * 50}{COLORS['RESET']}")

            # Reset terminal settings
            print(
                "\033[?25h"  # Show cursor
                "\033[?7h"  # Enable line wrapping
                "\033[?47l"  # Restore screen
                "\033[!p"  # Soft reset
                "\033[?1l"  # Reset cursor keys to default
                "\033[?12l"  # Stop blinking cursor
                "\033[?25h",  # Ensure cursor is visible
                end="",
                flush=True,
            )

            return {
                "exit_code": returncode,
                "stdout": final_stdout,
                "stderr": final_stderr,
            }


##############################################################################
# Core Classes
##############################################################################

CLIENT = MorphCloudClient()


@dataclass
class RuntimeInterface:
    """
    Provide rendering (observation + available tools), call_tool, etc.
    """

    morphvm_id: str
    keep_alive: bool = False
    instance: Optional[Instance] = None
    should_cleanup: bool = False
    done: bool = False
    morph_client: Optional[MorphCloudClient] = None

    def __post_init__(self):
        """Initialize the MorphCloud client and set up the instance."""
        self.morph_client = MorphCloudClient()

        # Handle instance creation/connection
        if self.morphvm_id.startswith("snapshot_"):
            print(f"Starting instance from snapshot {self.morphvm_id}")
            self.instance = self.morph_client.instances.start(self.morphvm_id)
            self.should_cleanup = not self.keep_alive
            print(f"Started instance {self.instance.id}")
        else:
            # Connect to existing instance first
            print(f"Connecting to existing instance {self.morphvm_id}")
            self.instance = self.morph_client.instances.get(self.morphvm_id)
            self.should_cleanup = False  # Don't cleanup existing instances

        # Wait for instance to be ready
        print("Waiting for instance to be ready...")
        self.instance.wait_until_ready()
        print(f"Instance {self.instance.id} is ready")

    async def render(self, vision: bool = False) -> Observation:
        """Get the current state of the environment."""
        return Observation(None, dict(), [run_command, done_command])

    async def call_tool(self, namespace: str, tool_name: str, **kwargs):
        """Execute a tool command on the instance."""
        if tool_name == "run_command":
            cmd = kwargs.get("command", "")
            print(
                f"{COLORS['SECONDARY']}[DEBUG]{COLORS['RESET']} Running SSH command: {COLORS['TEXT']}{cmd}{COLORS['RESET']}"
            )
            result = ssh_connect_and_run(self.instance, cmd)
            return result
        elif tool_name == "done":
            self.done = True
            return {"stdout": "", "stderr": "", "exit_code": 0}
        else:
            return {"error": f"Unknown tool '{tool_name}'"}

    def is_done(self) -> bool:
        """Check if the agent has completed its task."""
        return self.done


@dataclass
class MorphAgent:
    """
    A headless agent that repeatedly calls the model, handles tool use,
    and can stop if `runtime_interface.is_done()` is True or if max_tries is reached.
    """

    runtime_interface: RuntimeInterface

    @staticmethod
    def from_instance(instance: Instance) -> "MorphAgent":
        return MorphAgent(RuntimeInterface(instance.id))

    async def run(self, instruction: str, max_tries: Optional[int] = 3) -> List[Dict]:
        anthropic_client = AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
        messages: List[Dict] = []
        attempt_count = 0

        while True:
            if max_tries is not None and attempt_count >= max_tries:
                break
            if self.runtime_interface.is_done():
                break

            observation = await self.runtime_interface.render()
            anthropic_tools = [
                t.as_anthropic_tool() for t in observation.available_tools
            ]

            truncated_obs = maybe_truncate_text(
                observation.workspace_state, max_length=2000
            )

            user_prompt = (
                f"Please accomplish this task:\n{instruction}.\n"
                f"I cannot provide more information than the above. "
                f"Use whatever tools are necessary.\n"
            )
            RUN_SYSTEM_MESSAGE = SYSTEM_MESSAGE + f"\n\n# Instruction\n{user_prompt}"

            messages.append(
                {"role": "user", "content": "Please accomplish the objective."}
            )
            messages = maybe_truncate_messages(messages)

            while True:
                try:
                    response_stream = await call_model(
                        client=anthropic_client,
                        system=RUN_SYSTEM_MESSAGE,
                        messages=messages,
                        tools=anthropic_tools,
                    )
                    response_msg, tool_use_active = await process_assistant_message(
                        response_stream
                    )
                    break
                except anthropic.APIStatusError:
                    print("retrying")
                    continue
                except Exception as e:
                    break

            print("\n--- ASSISTANT MESSAGE ---")
            print(json.dumps(response_msg, indent=2))

            messages.append({"role": "assistant", "content": response_msg["content"]})

            while tool_use_active:
                tool_use_blocks = [
                    c for c in response_msg["content"] if c["type"] == "tool_use"
                ]
                if not tool_use_blocks:
                    tool_use_active = False
                    break

                for tool_block in tool_use_blocks:
                    tool_name = tool_block["name"]
                    tool_input = tool_block.get("input", {})

                    tool_result_content = await self.runtime_interface.call_tool(
                        namespace="", tool_name=tool_name, **tool_input
                    )

                    tool_result_content["stdout"] = maybe_truncate_text_from_left(
                        tool_result_content["stdout"]
                    )
                    tool_result_content["stderr"] = maybe_truncate_text_from_left(
                        tool_result_content["stderr"]
                    )

                    yaml_string = yaml.dump(tool_result_content)

                    tool_result_msg = {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": tool_block["id"],
                                "content": f"```yaml\n{yaml_string}\n```",
                            }
                        ],
                    }

                    print("\n--- BEGIN TOOL RESULT MESSAGE ---")
                    print(yaml_string)
                    print("\n--- END TOOL RESULT MESSAGE ---")

                    messages.append(tool_result_msg)
                    messages = maybe_truncate_messages(messages)

                    while True:
                        try:
                            second_response_stream = await call_model(
                                client=anthropic_client,
                                system=RUN_SYSTEM_MESSAGE,
                                messages=messages,
                                tools=anthropic_tools,
                            )
                            response_msg, tool_use_active = (
                                await process_assistant_message(second_response_stream)
                            )
                            break
                        except anthropic.APIStatusError:
                            print("retrying")
                            continue
                        except Exception as e:
                            break

                    print("\n--- ASSISTANT MESSAGE ---")
                    print(json.dumps(response_msg, indent=2))

                    messages.append(
                        {"role": "assistant", "content": response_msg["content"]}
                    )

            attempt_count += 1

        return messages


SYSTEM_MESSAGE = """
<SYSTEM_CAPABILITY>
You are a Morph Virtual Machine, an AI-enabled cloud environment for accomplishing tasks within a minimal Debian-based operating system. You are very resourceful, capable of high-level planning and adapting. You are independent and thrive at being self-sufficient on well-scoped tasks.

To control the operating system, use the tool calls which are available to you. If a command fails, read the error message. Try to find a way around the failures. Think a little before you act.

Before starting work on the task, analyze the instructions you have been given, do some preliminary research on the VM, and then write a tasklist for yourself with checkboxes in a plain text file at /tmp/morphvm-plan.txt

While working, please begin every message by calling out the task from your tasklist you are working on. Begin your message with [active_task="{$DESC}"]. Whenever you have accomplished a task, please call out that you have finished that task, and then use the morphos-edit-file tool to edit /tmp/morphvm-plan.txt so that it's always up to date. You should always know what task you're tackling.

When you believe that you have accomplished your plan, please call the "done" tool. Before doing so, please VERIFY that the task has been accomplished. Before you call 'done', please DOUBLE-CHECK /tmp/morphvm-plan.txt, did you finish everything?

DO NOT LET ANY OBSTACLES BLOCK YOU FROM ACCOMPLISHING YOUR GOAL. This is the prime directive. No excuses. Your ONLY mission is to accomplish the task.
</SYSTEM_CAPABILITY>

<ADVICE>
# Quick Heredoc Guide

## Basic Usage

### Unquoted - Variables Expand
```bash
cat << EOF
Your home is: $HOME
Current time: $(date)
EOF
```

### Quoted - Literal Text
```bash
cat << 'EOF'
$HOME stays as $HOME
$(date) stays as $(date)
EOF
```

## Essential Rules
- Closing delimiter must be alone on its line (no spaces after!)
- Use <<- to allow indentation with tabs (not spaces)
- Quoted delimiters ('EOF') prevent all expansion
- Unquoted delimiters (EOF) allow variable/command expansion

## Nesting Heredocs
```bash
cat << EOF1
Outer heredoc
$(cat << EOF2
  Inner heredoc
  Use different delimiters!
EOF2
)
EOF1
```

## Common Mistakes
```bash
# WRONG - space after EOF
cat << EOF
text
EOF

# WRONG - indented EOF
cat << EOF
text
    EOF

# RIGHT
cat << EOF
text
EOF
```

# morphos-edit-file guide
Apply structured edits to files with smart matching.

Recommended Usage:
  The recommended way to use this tool is with heredoc syntax:

  $ morphos-edit-file apply src/service.js - << 'EOF'
  <<<<<<< SEARCH
  function getData() {
      return db.query('SELECT * FROM data');
  }
  =======
  async function getData() {
      return await db.query('SELECT * FROM data');
  }
  >>>>>>> REPLACE
  EOF

More Examples:
  1. Multiple edits in one operation (recommended):
     $ morphos-edit-file apply src/user.js - << 'EOF'
     <<<<<<< SEARCH
     class User {
         getName() { return this.name; }
     }
     =======
     class User {
         getName() { return this.name || 'Anonymous'; }
     }
     >>>>>>> REPLACE

     <<<<<<< SEARCH
     function createUser(data) {
         return new User(data);
     }
     =======
     async function createUser(data) {
         const validated = await validateUserData(data);
         return new User(validated);
     }
     >>>>>>> REPLACE
     EOF

  2. With dry-run to preview changes:
     $ morphos-edit-file apply --dry-run src/user.js - << 'EOF'
     <<<<<<< SEARCH
     const config = {
         port: 3000
     };
     =======
     const config = {
         port: process.env.PORT || 3000
     };
     >>>>>>> REPLACE
     EOF

Alternative Methods:
  While heredoc is recommended, you can also:
  - Use a file:            morphos-edit-file apply src/file.js edits.txt
  - Use process subst:     morphos-edit-file apply file.js <(echo "...")
  - Pipe content:          echo "..." | morphos-edit-file apply file.js -

Features:
  - Smart matching with fuzzy search capability
  - Handles whitespace variations automatically
  - Creates automatic backups before changes (.bak files)
  - Multiple edit blocks supported in one edit
  - Returns exit code 0 on success, 1 on failure

# Use `tmux` to run background and non-interactive processes like development servers

## Starting Sessions
```bash
# Always start your sessions as detached
tmux new-session -d -s myprocess 'command'

# Start multiple processes
tmux new-session -d -s mysession 'process1'; \
  split-window -h 'process2'; \
  split-window -v 'process3'
```

## Managing Sessions
```bash
### List sessions
tmux ls

### Kill session
tmux kill-session -t myprocess
```

## Process Interaction
```bash
# View last 120 lines of scrollback
tmux capture-pane -t myprocess -S -120 -p

# Send command to process
tmux send-keys -t myprocess 'command' Enter

# Monitor output in real-time
tmux pipe-pane -t myprocess 'cat >> logfile'

# List all panes
tmux list-panes -a
```

## Process Lifecycle Commands
```bash
# Start new process in existing session
tmux send-keys -t myprocess 'command' Enter

# Terminate process (send SIGINT)
tmux send-keys -t myprocess C-c

# Force kill session
tmux kill-session -t myprocess

# Restart process
tmux respawn-pane -t myprocess -k 'command'
```

## Practical Examples
```bash
# Launch monitoring process
tmux new-session -d -s monitor 'top'

# Check its output
tmux capture-pane -t monitor -S -120 -p

# Send command to running process
tmux send-keys -t monitor 'k' # Kill process in top

# Create session with multiple log monitors
tmux new-session -d -s logs \; \
  send-keys 'tail -f /var/log/syslog' Enter \; \
  split-window -v 'tail -f /var/log/auth.log'

# launch a webserver
tmux new-session -d -s webserver 'uvicorn app:app --host 0.0.0.0 --port 8000'
```

# Misc advice

YOU'RE NOT IN A FULL TTY SO USE TMUX IF YOU EXPECT ANY TUI INTERACTION

- In general don't run any commands that might drop you into an interactive TUI because you're not in a full TTY. When using `run_command`, try to use the "no confirm" or "yes | " pattern for everything since you can't interactively confirm. This applies for things like npx create-react-app or npx babel src ..., in which case you should use yes 'y' | ...

- If you use systemctl or journalctl use --no-pager.

- To edit files, please try to use `morphos-edit-file` using the heredoc syntax.

- When you need to specify your identity to use git, please use the name "Morph Labs" and the email "hello@morph.so".
</ADVICE>
"""

DEFAULT_INSTRUCTION = """
Debug and fix the files in /root/webserver
if you have any concerns about what the intended behavior is, use your best judgement and infer from the provided files

Please document everything clearly and organize your findings in a way that would be helpful for a system administrator.
Create your plan in /tmp/morphvm-plan.txt and update it as you work through the debugging process.
"""


def _main(
    resource_id: str,
    instruction_file: str = None,
    instruction: str = None,
    keep_alive: bool = False,  # Add keep_alive parameter
):
    """
    Run the Morph Agent on a specified MorphVM instance or snapshot.

    Args:
        resource_id: Either a snapshot ID or MorphVM instance ID
        instruction_file: Path to a file containing instructions (optional)
        instruction: Direct instruction string (optional)
        keep_alive: If True, keeps instances created from snapshots running (default: False)
    """
    rt = None
    instance = None
    final_snapshot_id = None

    try:
        if instruction_file:
            with open(instruction_file, "r") as f:
                instructions = f.read().strip()
        elif instruction:
            instructions = instruction
        else:
            instructions = DEFAULT_INSTRUCTION

        print(
            f"\n{COLORS['PRIMARY']}Starting session with resource: {resource_id}{COLORS['RESET']}"
        )
        print(
            f"{COLORS['SECONDARY']}Using instruction:{COLORS['RESET']}\n{instructions}\n"
        )

        rt = RuntimeInterface(morphvm_id=resource_id, keep_alive=keep_alive)
        instance = rt.instance  # Keep a reference to the instance
        agent = MorphAgent(rt)

        asyncio.run(agent.run(instructions, 3))

    except KeyboardInterrupt:
        print("\nCtrl+C detected")
    except Exception as e:
        print(f"\nError occurred: {e}")
        raise
    finally:
        if rt and rt.instance:
            try:
                print("\nCreating final snapshot...")
                final_snapshot = rt.instance.snapshot()
                final_snapshot_id = final_snapshot.id
                print(f"Created final snapshot: {final_snapshot_id}")
            except Exception as e:
                print(f"Failed to create final snapshot: {e}")

            # Handle cleanup based on configuration
            if rt.should_cleanup:
                try:
                    print(f"\nStopping instance {rt.instance.id}")
                    rt.instance.stop()
                    print("Instance stopped successfully")
                except Exception as e:
                    print(f"Failed to stop instance: {e}")

            # Print summary of what happened and next steps
            print("\nSession Summary:")
            print(f"- Resource ID: {resource_id}")
            print(f"- Final snapshot: {final_snapshot_id}")
            print(f"- Instance ID: {rt.instance.id}")

            if resource_id.startswith("snapshot_"):
                if keep_alive:
                    print(
                        f"\nInstance {rt.instance.id} is still running (--keep-alive was specified)"
                    )
                else:
                    print(
                        f"\nInstance was stopped. To continue working, start a new instance from snapshot: {final_snapshot_id}"
                    )
            else:
                print(f"\nInstance {rt.instance.id} remains running.")


if __name__ == "__main__":
    fire.Fire(_main)
