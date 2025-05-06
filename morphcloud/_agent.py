# MCP
# API key scoping
# agent that can only work on some 'projects', can only manage resources with pause/resume, can't exec/delete


import copy
import io
import json
import os
import sys
import time
import threading
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.json import JSON
from rich.table import Table

# Debug mode flag - set to True to enable detailed debug messages
DEBUG_MODE = False

from ._scramble import SCRAMBLE_TEXT, scramble_print

# Initialize Rich console
rich_console = Console()

try:
    import gnureadline as readline  # type: ignore
except ImportError:
    try:
        import readline
    except ImportError:
        readline = None

if readline:
    readline.parse_and_bind("tab: complete")

import anthropic
from pydantic import BaseModel

from morphcloud.api import MorphCloudClient


def _get_anthropic_api_key():
    key = os.environ["ANTHROPIC_API_KEY"]
    assert key, "Anthropic API key cannot be an empty string"
    return key


MODEL_NAME = "claude-3-7-sonnet-20250219"


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

# Create prompts using ANSI codes
if readline:
    USER_PROMPT = f"\001{COLORS['HIGHLIGHT']}\002[user]:\001{COLORS['RESET']}\002 "
else:
    USER_PROMPT = f"{COLORS['HIGHLIGHT']}[user]:{COLORS['RESET']} "
MORPH_AGENT_PROMPT = f"{COLORS['PRIMARY']}[agent]:{COLORS['RESET']} "

MAX_TOKENS = 4096


class ToolCall(BaseModel):
    name: str
    input: dict


def add_cache_control_to_last_content(
    messages, cache_control={"type": "ephemeral"}, max_cache_controls=4
):
    """
    Add cache_control to the last content block of the last message in the list,
    without mutating the original list and respecting the maximum cache_control limit.
    """
    if not messages:
        return messages

    # Create a deep copy of the messages list
    new_messages = copy.deepcopy(messages)

    # Count existing cache_control blocks
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

    # If we've already reached the maximum, return the copy without changes
    if cache_control_count >= max_cache_controls:
        return new_messages

    last_message = new_messages[-1]

    if isinstance(last_message.get("content"), list):
        if last_message["content"]:
            last_content = last_message["content"][-1]
            if isinstance(last_content, dict) and "type" in last_content:
                if "cache_control" not in last_content:
                    last_content["cache_control"] = cache_control
    elif isinstance(last_message.get("content"), dict):
        if "cache_control" not in last_message["content"]:
            last_message["content"]["cache_control"] = cache_control

    return new_messages


def call_model(
    client: anthropic.Anthropic, system: str, messages: List[Dict], tools: List[Dict]
):
    return client.messages.create(
        model=MODEL_NAME,
        system=system,
        messages=add_cache_control_to_last_content(messages),
        max_tokens=MAX_TOKENS,
        tools=tools,  # type: ignore
        stream=True,
        extra_headers={"anthropic-beta": "prompt-caching-2024-07-31"},
    )  # type: ignore


def process_assistant_message(response_stream):
    response_msg = {"role": "assistant", "content": []}
    content_block_type = None
    content_acc = io.StringIO()

    def flush_content():
        if content_block_type == "text":
            text_block = content_acc.getvalue()
            if text_block.strip():
                response_msg["content"].append({"type": "text", "text": text_block})
        elif content_block_type == "tool_use":
            tool_input_json = content_acc.getvalue()
            try:
                tool_input = json.loads(tool_input_json) if tool_input_json else {}
                assert current_tool_block is not None
                current_tool_block["input"] = tool_input
                response_msg["content"].append(current_tool_block)
            except json.JSONDecodeError as e:
                print(f"\n{COLORS['HIGHLIGHT']}Error parsing tool input JSON: {str(e)}{COLORS['RESET']}")
                tool_input = {}
                assert current_tool_block is not None
                current_tool_block["input"] = tool_input
                response_msg["content"].append(current_tool_block)

        content_acc.seek(0)
        content_acc.truncate()

    print()
    sys.stdout.write(MORPH_AGENT_PROMPT)
    sys.stdout.flush()

    tool_use_active = False
    global current_tool_block
    current_tool_block = None

    first_text_chunk = True

    for chunk in response_stream:
        if chunk.type == "message_start":
            continue
        elif chunk.type == "content_block_start":
            if content_block_type:
                flush_content()
            content_block_type = chunk.content_block.type
            content_acc.seek(0)
            content_acc.truncate()
            if content_block_type == "tool_use":
                tool_use_active = True
                current_tool_block = {
                    "type": "tool_use",
                    "name": chunk.content_block.name,
                    "id": chunk.content_block.id,
                }
            elif content_block_type == "text":
                first_text_chunk = True

        elif chunk.type == "content_block_delta":
            if content_block_type in ["text", "tool_use"]:
                if content_block_type == "text":
                    text_to_print = chunk.delta.text
                    if first_text_chunk:
                        text_to_print = text_to_print.lstrip("\n")
                        first_text_chunk = False
                    sys.stdout.write(COLORS["TEXT"] + text_to_print + COLORS["RESET"])
                    sys.stdout.flush()
                    content_acc.write(text_to_print)
                else:
                    content_acc.write(chunk.delta.partial_json)

        elif chunk.type == "content_block_stop":
            flush_content()
            content_block_type = None

    sys.stdout.write("\n")
    sys.stdout.flush()

    return response_msg, tool_use_active


# Function removed since we're now using direct json.dumps approach


def ssh_connect_and_run(instance, command: str, timeout: Optional[int] = 60) -> Dict[str, Any]:
    """Execute a command over SSH with real-time output streaming and timeout support (default: 60s)"""
    with instance.ssh() as ssh:
        # Get ANSI color codes ready
        OUTPUT_HEADER = COLORS["OUTPUT_HEADER"]
        print(f"\n{COLORS['SECONDARY']}{'─' * 50}{COLORS['RESET']}")
        print(f"\n{OUTPUT_HEADER}Output:{COLORS['RESET']}")

        last_stdout = ""
        last_stderr = ""
        
        # Flag to track if the command was terminated due to timeout
        timed_out = False
        # Event for signaling timeout
        timeout_event = threading.Event()
        
        # Create a timeout timer if timeout is specified
        timer = None
        if timeout is not None and timeout > 0:
            def handle_timeout():
                nonlocal timed_out
                timed_out = True
                timeout_event.set()
                print(f"\n{COLORS['HIGHLIGHT']}Command timed out after {timeout} seconds. Terminating...{COLORS['RESET']}")
            
            timer = threading.Timer(timeout, handle_timeout)
            timer.daemon = True
            timer.start()

        # Run the command in background to get real-time output
        with ssh.run(command, background=True, get_pty=True) as process:
            try:
                while not timeout_event.is_set() and not process.completed:
                    # Print stdout in real-time
                    current_stdout = process.stdout
                    if current_stdout != last_stdout:
                        new_output = current_stdout[len(last_stdout):]
                        print(
                            f"{COLORS['TEXT']}{new_output}{COLORS['RESET']}",
                            end="",
                            flush=True,
                        )
                        last_stdout = current_stdout

                    # Print stderr in real-time
                    current_stderr = process.stderr
                    if current_stderr != last_stderr:
                        new_stderr = current_stderr[len(last_stderr):]
                        print(
                            f"{COLORS['HIGHLIGHT']}[stderr] {new_stderr}{COLORS['RESET']}",
                            end="",
                            flush=True,
                        )
                        last_stderr = current_stderr

                    time.sleep(0.01)
                
                # Get final output
                final_stdout = process.stdout
                final_stderr = process.stderr
                
                if timed_out:
                    # Command was terminated due to timeout
                    returncode = -1  # Use -1 to indicate timeout
                    status_msg = f"Command timed out after {timeout} seconds"
                else:
                    # Get exit code if process completed normally
                    returncode = process.channel.recv_exit_status() if process.completed else -2
                    status_msg = "Command succeeded" if returncode == 0 else "Command failed"
            
            finally:
                # Cancel the timer if it's still running
                if timer is not None and timer.is_alive():
                    timer.cancel()
                
                # Always try to clean up the process
                process.stop()

        # Print status
        SUCCESS_COLOR = COLORS["SUCCESS"]
        ERROR_COLOR = COLORS["ERROR"]
        status_color = SUCCESS_COLOR if returncode == 0 else ERROR_COLOR

        print(f"\n{OUTPUT_HEADER}Status:{COLORS['RESET']}")
        print(
            f"{status_color}{'✓ ' if returncode == 0 else '✗ '}{status_msg} (exit code: {returncode}){COLORS['RESET']}"
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

        # Debug information about the output
        if DEBUG_MODE:
            print(f"\n{COLORS['SECONDARY']}[DEBUG] SSH command completed.{COLORS['RESET']}")
            print(f"{COLORS['SECONDARY']}[DEBUG] stdout length: {len(final_stdout)}{COLORS['RESET']}")
            print(f"{COLORS['SECONDARY']}[DEBUG] stderr length: {len(final_stderr)}{COLORS['RESET']}")
        
        # Pre-sanitize even at this early stage
        sanitized_stdout = final_stdout.encode('utf-8', 'replace').decode('utf-8')
        sanitized_stderr = final_stderr.encode('utf-8', 'replace').decode('utf-8')
        
        # Return sanitized versions
        return {
            "exit_code": returncode,
            "stdout": sanitized_stdout,
            "stderr": sanitized_stderr,
            "timed_out": timed_out
        }

def run_tool(tool_call: ToolCall, client: MorphCloudClient) -> Dict[str, Any]:
    """Execute a tool call with the MorphCloud API client"""
    tool_name = tool_call.name
    tool_input = tool_call.input
    
    # Use Rich to print the tool execution notice
    rich_console.print(f"[dim]Running tool:[/dim] [bold cyan]{tool_name}[/bold cyan]")
    
    # Show input parameters without special styling
    if tool_input:
        rich_console.print(Panel(
            JSON(json.dumps(tool_input)),
            title="[dim]Tool Input Parameters[/dim]",
            border_style="dim",
            expand=False
        ))
    
    result = {}
    
    try:
        if tool_name == "exec_ssh_command":
            instance_id = tool_input.get("instance_id")
            command = tool_input.get("command")
            timeout = tool_input.get("timeout")  # Optional timeout in seconds
            
            # Get the instance
            instance = client.instances.get(instance_id)
            
            # Run the command on the instance
            result = ssh_connect_and_run(instance, command, timeout)
            
            # Add instance_id to the result for reference
            result["instance_id"] = instance_id
            result["success"] = result.get("exit_code", -1) == 0
            
        elif tool_name == "create_snapshot":
            image_id = tool_input.get("image_id")
            vcpus = tool_input.get("vcpus")
            memory = tool_input.get("memory")
            disk_size = tool_input.get("disk_size")
            digest = tool_input.get("digest")
            metadata = tool_input.get("metadata")
            
            snapshot = client.snapshots.create(
                image_id=image_id,
                vcpus=vcpus,
                memory=memory,
                disk_size=disk_size,
                digest=digest,
                metadata=metadata
            )
            
            result = {
                "success": True,
                "snapshot_id": snapshot.id,
                "status": snapshot.status.value,
                "created": snapshot.created,
                "digest": snapshot.digest
            }
            
        elif tool_name == "start_instance":
            snapshot_id = tool_input.get("snapshot_id")
            metadata = tool_input.get("metadata")
            ttl_seconds = tool_input.get("ttl_seconds")
            ttl_action = tool_input.get("ttl_action")
            
            instance = client.instances.start(
                snapshot_id=snapshot_id,
                metadata=metadata,
                ttl_seconds=ttl_seconds,
                ttl_action=ttl_action
            )
            
            result = {
                "success": True,
                "instance_id": instance.id,
                "status": instance.status.value,
                "created": instance.created
            }
            
        elif tool_name == "snapshot_instance":
            instance_id = tool_input.get("instance_id")
            digest = tool_input.get("digest")
            
            instance = client.instances.get(instance_id)
            snapshot = instance.snapshot(digest=digest)
            
            result = {
                "success": True,
                "snapshot_id": snapshot.id,
                "status": snapshot.status.value,
                "created": snapshot.created,
                "digest": snapshot.digest
            }
            
        elif tool_name == "stop_instance":
            instance_id = tool_input.get("instance_id")
            
            client.instances.stop(instance_id)
            
            result = {
                "success": True,
                "instance_id": instance_id,
                "message": f"Instance {instance_id} stopped successfully"
            }
            
        elif tool_name == "list_images":
            images = client.images.list()
            
            result = {
                "success": True,
                "images": [
                    {
                        "id": image.id,
                        "name": image.name,
                        "description": image.description,
                        "disk_size": image.disk_size,
                        "created": image.created
                    }
                    for image in images
                ]
            }
            
        elif tool_name == "list_snapshots":
            digest = tool_input.get("digest")
            metadata = tool_input.get("metadata")
            limit = tool_input.get("limit", 10)  # Default limit of 10 items
            
            # Get all snapshots matching the criteria
            snapshots = client.snapshots.list(digest=digest, metadata=metadata)
            total_snapshots = len(snapshots)
            
            # Apply limit (but keep full list in memory for agent to count)
            limited_snapshots = snapshots[:limit] if total_snapshots > limit else snapshots
            
            result = {
                "success": True,
                "total_count": total_snapshots,
                "limited": total_snapshots > limit,
                "limit": limit,
                "snapshots": [
                    {
                        "id": snapshot.id,
                        "status": snapshot.status.value,
                        "created": snapshot.created,
                        "digest": snapshot.digest,
                        "metadata": snapshot.metadata,
                        "specs": {
                            "vcpus": snapshot.spec.vcpus,
                            "memory": snapshot.spec.memory,
                            "disk_size": snapshot.spec.disk_size
                        }
                    }
                    for snapshot in limited_snapshots
                ]
            }
            
            # Add a note to the result if we limited the results
            if total_snapshots > limit:
                result["note"] = f"Only showing {limit} of {total_snapshots} snapshots. Use metadata filters or increase the limit to see more."
            
        elif tool_name == "list_instances":
            metadata = tool_input.get("metadata")
            limit = tool_input.get("limit", 10)  # Default limit of 10 items
            
            # Get all instances matching the criteria
            instances = client.instances.list(metadata=metadata)
            total_instances = len(instances)
            
            # Apply limit (but keep full list in memory for agent to count)
            limited_instances = instances[:limit] if total_instances > limit else instances
            
            result = {
                "success": True,
                "total_count": total_instances,
                "limited": total_instances > limit,
                "limit": limit,
                "instances": [
                    {
                        "id": instance.id,
                        "status": instance.status.value,
                        "created": instance.created,
                        "snapshot_id": instance.refs.snapshot_id,
                        "metadata": instance.metadata,
                        "specs": {
                            "vcpus": instance.spec.vcpus,
                            "memory": instance.spec.memory,
                            "disk_size": instance.spec.disk_size
                        }
                    }
                    for instance in limited_instances
                ]
            }
            
            # Add a note to the result if we limited the results
            if total_instances > limit:
                result["note"] = f"Only showing {limit} of {total_instances} instances. Use metadata filters or increase the limit to see more."
            
        elif tool_name == "expose_http_service":
            instance_id = tool_input.get("instance_id")
            name = tool_input.get("name")
            port = tool_input.get("port")
            auth_mode = tool_input.get("auth_mode")
            
            # Get the instance
            instance = client.instances.get(instance_id)
            
            # Expose the HTTP service
            url = instance.expose_http_service(name=name, port=port, auth_mode=auth_mode)
            
            result = {
                "success": True,
                "instance_id": instance_id,
                "service_name": name,
                "port": port,
                "url": url,
                "message": f"HTTP service '{name}' exposed successfully at {url}"
            }
            
        elif tool_name == "hide_http_service":
            instance_id = tool_input.get("instance_id")
            name = tool_input.get("name")
            
            # Get the instance
            instance = client.instances.get(instance_id)
            
            # Hide the HTTP service
            instance.hide_http_service(name=name)
            
            result = {
                "success": True,
                "instance_id": instance_id,
                "service_name": name,
                "message": f"HTTP service '{name}' hidden successfully"
            }
            
        else:
            result = {
                "success": False,
                "error": f"Unknown tool '{tool_name}'"
            }
    
    except Exception as e:
        result = {
            "success": False,
            "error": str(e)
        }
    
    # Display the result to the user in a pretty format using Rich
    
    # Convert result to Rich-formatted JSON, with safety checks
    try:
        json_str = json.dumps(result)
        if len(json_str) > 10000:  # Truncate very large results
            json_str = json_str[:9997] + "..."
    except Exception as e:
        # If JSON serialization fails, create a simple valid JSON string
        print(f"\n{COLORS['HIGHLIGHT']}Error creating display JSON: {str(e)}{COLORS['RESET']}")
        json_str = json.dumps({"error": "Could not display full result due to JSON error", 
                              "tool": tool_name,
                              "success": tool_name != "exec_ssh_command" or result.get("exit_code", -1) == 0})
    
    # Different formatting based on the tool type and success
    if "success" in result and result["success"]:
        panel_title = f"[bold green]✅ {tool_name} - Success[/bold green]"
        panel_border_style = "green"
    else:
        panel_title = f"[bold red]❌ {tool_name} - Failed[/bold red]"
        panel_border_style = "red"
    
    # Define max items to display in tables
    MAX_DISPLAY_ITEMS = 10
    
    # Create specialized displays for different tools
    if tool_name == "list_images" and "images" in result and result["success"]:
        images = result["images"]
        total_images = len(images)
        
        # Create a table for images
        table = Table(
            title=f"Available Images ({total_images} total)" if total_images > MAX_DISPLAY_ITEMS else "Available Images", 
            show_header=True, 
            header_style="bold cyan"
        )
        table.add_column("ID", style="cyan")
        table.add_column("Name")
        table.add_column("Description")
        table.add_column("Disk Size (MB)", justify="right")
        
        # Display images (limit if there are too many)
        display_images = images[:MAX_DISPLAY_ITEMS] if total_images > MAX_DISPLAY_ITEMS else images
        for image in display_images:
            table.add_row(
                image["id"],
                image["name"],
                image.get("description", ""),
                str(image.get("disk_size", ""))
            )
        
        # Create the panel with the table
        rich_console.print(Panel(table, title=panel_title, border_style=panel_border_style))
        
        # Show message if results were limited
        if total_images > MAX_DISPLAY_ITEMS:
            rich_console.print(f"[yellow]Showing {MAX_DISPLAY_ITEMS} of {total_images} images.[/yellow]")
            rich_console.print("[italic]Tip: All images are still available in the result, but display is limited for readability.[/italic]")
        
    elif tool_name == "list_snapshots" and "snapshots" in result and result["success"]:
        snapshots = result["snapshots"]
        total_snapshots = len(snapshots)
        
        # Create a table for snapshots
        table = Table(
            title=f"Available Snapshots ({total_snapshots} total)" if total_snapshots > MAX_DISPLAY_ITEMS else "Available Snapshots", 
            show_header=True, 
            header_style="bold cyan"
        )
        table.add_column("ID", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("VCPUs", justify="right")
        table.add_column("Memory (MB)", justify="right")
        table.add_column("Disk (MB)", justify="right")
        table.add_column("Digest", style="dim", no_wrap=False)
        
        # Display snapshots (limit if there are too many)
        display_snapshots = snapshots[:MAX_DISPLAY_ITEMS] if total_snapshots > MAX_DISPLAY_ITEMS else snapshots
        for snapshot in display_snapshots:
            specs = snapshot.get("specs", {})
            table.add_row(
                snapshot["id"],
                snapshot.get("status", ""),
                str(specs.get("vcpus", "")),
                str(specs.get("memory", "")),
                str(specs.get("disk_size", "")),
                snapshot.get("digest", "")[:15] + "..." if snapshot.get("digest") and len(snapshot.get("digest", "")) > 18 else snapshot.get("digest", "")
            )
        
        # Create the panel with the table
        rich_console.print(Panel(table, title=panel_title, border_style=panel_border_style))
        
        # Show message if results were limited
        if total_snapshots > MAX_DISPLAY_ITEMS:
            rich_console.print(f"[yellow]Showing {MAX_DISPLAY_ITEMS} of {total_snapshots} snapshots.[/yellow]")
            rich_console.print("[italic]Tip: You can use metadata filters to narrow down results. Try: 'Show my snapshots with metadata key=value'[/italic]")
        
    elif tool_name == "list_instances" and "instances" in result and result["success"]:
        instances = result["instances"]
        total_instances = len(instances)
        
        # Create a table for instances
        table = Table(
            title=f"Available Instances ({total_instances} total)" if total_instances > MAX_DISPLAY_ITEMS else "Available Instances", 
            show_header=True, 
            header_style="bold cyan"
        )
        table.add_column("ID", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Snapshot ID")
        table.add_column("VCPUs", justify="right")
        table.add_column("Memory (MB)", justify="right")
        table.add_column("Disk (MB)", justify="right")
        
        # Display instances (limit if there are too many)
        display_instances = instances[:MAX_DISPLAY_ITEMS] if total_instances > MAX_DISPLAY_ITEMS else instances
        for instance in display_instances:
            specs = instance.get("specs", {})
            table.add_row(
                instance["id"],
                instance.get("status", ""),
                instance.get("snapshot_id", ""),
                str(specs.get("vcpus", "")),
                str(specs.get("memory", "")),
                str(specs.get("disk_size", ""))
            )
        
        # Create the panel with the table
        rich_console.print(Panel(table, title=panel_title, border_style=panel_border_style))
        
        # Show message if results were limited
        if total_instances > MAX_DISPLAY_ITEMS:
            rich_console.print(f"[yellow]Showing {MAX_DISPLAY_ITEMS} of {total_instances} instances.[/yellow]")
            rich_console.print("[italic]Tip: You can use metadata filters to narrow down results. Try: 'Show my instances with metadata key=value'[/italic]")
        
    else:
        # Default formatting for other tools or failed operations
        try:
            # Try to use Rich's JSON formatter
            rich_json = JSON(json_str)
            rich_console.print(Panel(rich_json, title=panel_title, border_style=panel_border_style))
        except Exception as e:
            # If Rich JSON fails, fall back to plain text display
            print(f"\n{COLORS['HIGHLIGHT']}Error displaying rich JSON: {str(e)}{COLORS['RESET']}")
            rich_console.print(Panel(json_str, title=panel_title, border_style=panel_border_style))
    
    # No need for a separator - the panel provides visual separation
    
    return result


def agent_loop(client: MorphCloudClient, debug: bool = False, initial_instruction: Optional[str] = None):
    """
    Run the Morph Cloud Agent interactive loop.
    
    Args:
        client: MorphCloudClient instance to use for API calls
        debug: If True, enables verbose debug output for troubleshooting
        initial_instruction: If provided, this will be used as the first user input instead of prompting
    """
    global DEBUG_MODE
    DEBUG_MODE = debug
    SYSTEM_MESSAGE = """# Background
You are a Morph Cloud Agent, a helpful assistant that can manage Morph Cloud resources through the Morph Cloud API.
You can create, manage, and interact with snapshots and instances on Morph Cloud.

# Style
Keep responses concise and to the point.

# Capabilities
You have access to tools that allow you to:
1. Create snapshots from base images
2. Start instances from snapshots
3. Create new snapshots from running instances
4. Stop running instances
5. List available images, snapshots, and instances
6. Execute SSH commands on running instances
7. Expose HTTP services on instances (making them accessible via public URLs)
8. Hide previously exposed HTTP services

# Tools Usage Guidelines
- When creating a snapshot, make sure to always specify the required parameters (image_id, vcpus, memory, disk_size)
- Before starting an instance, make sure the snapshot_id exists
- When starting an instance, ALWAYS recommend using the ttl_seconds parameter to set an expiration time
  - ttl_seconds is the number of seconds until the instance expires (e.g., 3600 for 1 hour, 86400 for 1 day)
  - ttl_action can be "stop" or "pause" to determine what happens when the TTL expires
  - Always suggest appropriate TTL values to users to prevent unnecessary resource usage and costs
- Before stopping an instance, make sure the instance_id exists
- Use the appropriate list tools to check for available resources
- When a user asks for information, use the appropriate list tool to retrieve it
- When executing commands on instances, make sure the instance is in the READY state first

# SSH Command Execution
- You can execute commands on instances using the exec_ssh_command tool
- The tool requires an instance_id and command parameter
- Commands have a default timeout of 60 seconds to prevent hanging
- You can override the timeout by specifying a different value in seconds
- The tool will display command output in real-time and return results when complete
- For server processes or commands that don't terminate normally, use appropriate timeouts
- Example timeouts: file operations (30-60s), package installations (300-600s), simple commands (10-30s)
- If you need to run a background server, use nohup or & to detach the process
- Always check if an instance exists and is in the READY state before executing commands

# HTTP Service Management
- You can expose HTTP services on instances using the expose_http_service tool
- Exposing an HTTP service makes it accessible via a public URL
- The tool requires instance_id, name, and port parameters
- Optional auth_mode parameter can be set to "api_key" to require authentication
- After exposing a service, you'll receive a URL that can be shared with users
- You can hide (unexpose) services using the hide_http_service tool
- Before exposing a service, ensure the service is actually running on that port
- Common ports: web servers (80, 8080, 3000, 8000), databases (5432, 27017), APIs (8080, 3000)
- Always verify that the instance is in the READY state before exposing services

# List Operations
- The list_snapshots and list_instances tools return a MAXIMUM OF 10 ITEMS by default
- For both tools, the full count of matching resources is provided in the "total_count" field
- If there are more items than the limit, a "note" field will be included with guidance
- You have two options when dealing with many resources:
  1. Use metadata filters to narrow the search (preferred)
  2. Increase the "limit" parameter (up to a reasonable value like 50)
- Both list_snapshots and list_instances tools accept a metadata parameter for filtering 
- Format the metadata parameter as a JSON object, like: {"project": "webapp"} or {"environment": "production", "owner": "team1"}
- When a user asks to see snapshots/instances and there are many, ALWAYS inform them of the total count 
- Then ask if they want to filter by metadata or see more results
- Examples:
  - "I found 47 snapshots in total, but I'm only showing the first 10. Would you like to filter by metadata or increase the limit?"
  - "There are 23 instances. I'm showing the first 10. Do you want to see more or apply filters?"
- IMPORTANT: Never leave the user unaware that results were limited - always be transparent about pagination
"""
    tools = [
        {
            "name": "create_snapshot",
            "description": "Create a new snapshot from a base image and specifications",
            "input_schema": {
                "type": "object",
                "properties": {
                    "image_id": {"type": "string", "description": "ID of the base image to use"},
                    "vcpus": {"type": "integer", "description": "Number of virtual CPUs"},
                    "memory": {"type": "integer", "description": "Memory in Megabytes (MB)"},
                    "disk_size": {"type": "integer", "description": "Disk size in Megabytes (MB)"},
                    "digest": {"type": "string", "description": "Optional unique digest for caching/identification"},
                    "metadata": {
                        "type": "object", 
                        "description": "Optional metadata to attach to the snapshot",
                        "additionalProperties": {"type": "string"}
                    }
                },
                "required": ["image_id", "vcpus", "memory", "disk_size"]
            }
        },
        {
            "name": "start_instance",
            "description": "Start a new instance from a snapshot",
            "input_schema": {
                "type": "object",
                "properties": {
                    "snapshot_id": {"type": "string", "description": "ID of the snapshot to start from"},
                    "metadata": {
                        "type": "object", 
                        "description": "Optional metadata to attach to the instance",
                        "additionalProperties": {"type": "string"}
                    },
                    "ttl_seconds": {"type": "integer", "description": "Optional time-to-live in seconds"},
                    "ttl_action": {"type": "string", "enum": ["stop", "pause"], "description": "Action when TTL expires"}
                },
                "required": ["snapshot_id"]
            }
        },
        {
            "name": "snapshot_instance",
            "description": "Create a new snapshot from an instance",
            "input_schema": {
                "type": "object",
                "properties": {
                    "instance_id": {"type": "string", "description": "ID of the instance to snapshot"},
                    "digest": {"type": "string", "description": "Optional unique digest"}
                },
                "required": ["instance_id"]
            }
        },
        {
            "name": "stop_instance",
            "description": "Stop (terminate) a running or paused instance",
            "input_schema": {
                "type": "object",
                "properties": {
                    "instance_id": {"type": "string", "description": "ID of the instance to stop"}
                },
                "required": ["instance_id"]
            }
        },
        {
            "name": "exec_ssh_command",
            "description": "Execute a command on a running instance via SSH, with timeout capability",
            "input_schema": {
                "type": "object",
                "properties": {
                    "instance_id": {"type": "string", "description": "ID of the instance to execute the command on"},
                    "command": {"type": "string", "description": "The command to execute on the instance"},
                    "timeout": {"type": "integer", "description": "Optional timeout in seconds. If the command runs longer than this, it will be terminated."}
                },
                "required": ["instance_id", "command"]
            }
        },
        {
            "name": "list_images",
            "description": "List all available base images",
            "input_schema": {
                "type": "object",
                "properties": {}
            }
        },
        {
            "name": "list_snapshots",
            "description": "List snapshots available to the user. Results are limited to 10 items by default. Use metadata filters to narrow down results or increase the limit parameter.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "digest": {"type": "string", "description": "Optional digest to filter snapshots by"},
                    "metadata": {
                        "type": "object", 
                        "description": "Optional metadata to filter snapshots by. Example: {\"project\": \"webapp\"} or {\"environment\": \"production\"}",
                        "additionalProperties": {"type": "string"}
                    },
                    "limit": {"type": "integer", "description": "Maximum number of snapshots to return (default: 10)"}
                }
            }
        },
        {
            "name": "list_instances",
            "description": "List instances available to the user. Results are limited to 10 items by default. Use metadata filters to narrow down results or increase the limit parameter.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "metadata": {
                        "type": "object", 
                        "description": "Optional metadata to filter instances by. Example: {\"project\": \"webapp\"} or {\"environment\": \"production\"}",
                        "additionalProperties": {"type": "string"}
                    },
                    "limit": {"type": "integer", "description": "Maximum number of instances to return (default: 10)"}
                }
            }
        },
        {
            "name": "expose_http_service",
            "description": "Expose an HTTP service on a running instance, making it accessible via a public URL",
            "input_schema": {
                "type": "object",
                "properties": {
                    "instance_id": {"type": "string", "description": "ID of the instance to expose the service on"},
                    "name": {"type": "string", "description": "Name of the HTTP service"},
                    "port": {"type": "integer", "description": "Port number on which the service is running"},
                    "auth_mode": {"type": "string", "enum": ["api_key"], "description": "Optional authentication mode. Use 'api_key' to require API key authentication."}
                },
                "required": ["instance_id", "name", "port"]
            }
        },
        {
            "name": "hide_http_service",
            "description": "Unexpose a previously exposed HTTP service on an instance",
            "input_schema": {
                "type": "object",
                "properties": {
                    "instance_id": {"type": "string", "description": "ID of the instance where the service is exposed"},
                    "name": {"type": "string", "description": "Name of the HTTP service to hide"}
                },
                "required": ["instance_id", "name"]
            }
        }
    ]

    messages = []

    scramble_print(
        SCRAMBLE_TEXT,
        speed=2.0,
        seed=1,
        step=1,
        scramble=3,
        chance=1.0,
        overflow=True,
    )
    
    # Create a welcome panel with Rich
    welcome_text = """
[bold cyan]Welcome to the Morph Cloud Agent[/bold cyan]

This agent can help you manage your Morph Cloud resources using natural language.
You can ask to:
• Create snapshots from base images
• Start instances from snapshots (with automatic expiration times)
• Create new snapshots from running instances
• Stop instances
• List your available resources
• Execute SSH commands on running instances
• Expose HTTP services on instances (to get public URLs)
• Hide previously exposed HTTP services

[dim]Type 'exit' or 'quit' to stop the agent.[/dim]
    """
    rich_console.print(Panel(welcome_text, title="[bold]Morph Cloud Agent[/bold]", border_style="green", expand=False))
    print("")  # Add a blank line after the panel

    try:
        anthropic_client = anthropic.Anthropic(api_key=_get_anthropic_api_key())
    except KeyError as e:
        print(
            f"{COLORS['HIGHLIGHT']}Error: ANTHROPIC_API_KEY not found.{COLORS['RESET']}"
        )
        raise e

    if readline:

        class SimpleCompleter:
            def complete(self, text, state):
                if state == 0:
                    if text:
                        return text
                    return None
                return None

        readline.set_completer(SimpleCompleter().complete)
    
    
    # Use initial instruction if provided, otherwise enter the input loop
    first_message = True
    
    while True:
        # Get user input - either from initial_instruction or via input()
        if first_message and initial_instruction is not None:
            user_input = initial_instruction.strip()
            # Print it as if the user typed it for clarity
            print(f"{USER_PROMPT}{user_input}")
            first_message = False
        else:
            try:
                while True:
                    user_input = input(USER_PROMPT)
                    user_input = user_input.strip()
                    if user_input:
                        break
            except EOFError:
                print(f"\n{COLORS['HIGHLIGHT']}Exiting...{COLORS['RESET']}")
                break

        if user_input.lower() in ("exit", "quit"):
            print(f"{COLORS['HIGHLIGHT']}Exiting...{COLORS['RESET']}")
            break

        messages.append({"role": "user", "content": user_input})

        anthropic_error_wait_time = 3
        patience = 3
        num_tries = 0
        while num_tries < patience:
            try:
                response_stream = call_model(anthropic_client, SYSTEM_MESSAGE, messages, tools)
                response_msg, tool_use_active = process_assistant_message(
                    response_stream
                )
                break
            except anthropic.APIStatusError as e:
                print(f"Received {e=}, retrying in {anthropic_error_wait_time}s")
                time.sleep(anthropic_error_wait_time)
                num_tries += 1
                continue
            except Exception as e:
                import traceback
                print(f"\n{COLORS['HIGHLIGHT']}Unexpected error calling model: {str(e)}{COLORS['RESET']}")
                print(f"{COLORS['HIGHLIGHT']}Error type: {type(e)}{COLORS['RESET']}")
                print(f"{COLORS['HIGHLIGHT']}Detailed traceback:{COLORS['RESET']}")
                traceback.print_exc()
                break

        messages.append({"role": "assistant", "content": response_msg["content"]})
        
        while tool_use_active:
            tool_use_blocks = [
                c for c in response_msg["content"] if c["type"] == "tool_use"
            ]
            if not tool_use_blocks:
                print(
                    f"{COLORS['HIGHLIGHT']}[ERROR]{COLORS['RESET']} Assistant mentioned a tool but no tool_use block found in content."
                )
                break

            for tool_block in tool_use_blocks:
                tool_name = tool_block["name"]
                tool_input = tool_block.get("input", {})

                print(
                    f"\n{COLORS['SECONDARY']}[DEBUG]{COLORS['RESET']} Tool call received: name='{COLORS['PRIMARY']}{tool_name}{COLORS['RESET']}' input={COLORS['TEXT']}{tool_input}{COLORS['RESET']}"
                )
                tool_call = ToolCall(name=tool_name, input=tool_input)
                tool_result = run_tool(tool_call, client)
                
                # Sanitize stdout and stderr for JSON serialization
                if tool_name == "exec_ssh_command":
                    # For SSH command output, do thorough sanitization
                    if "stdout" in tool_result:
                        # First encode/decode to handle unicode issues
                        stdout = tool_result["stdout"].encode('utf-8', 'replace').decode('utf-8')
                        # Then escape any potentially problematic characters
                        stdout = stdout.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
                        # Truncate if too long (avoid giant responses)
                        if len(stdout) > 50000:
                            stdout = stdout[:50000] + "... [output truncated]"
                        tool_result["stdout"] = stdout
                        
                    if "stderr" in tool_result:
                        stderr = tool_result["stderr"].encode('utf-8', 'replace').decode('utf-8')
                        stderr = stderr.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
                        if len(stderr) > 10000:
                            stderr = stderr[:10000] + "... [output truncated]"
                        tool_result["stderr"] = stderr
                
                # Add debugging before attempting serialization
                if DEBUG_MODE:
                    print(f"\n{COLORS['SECONDARY']}[DEBUG]{COLORS['RESET']} Attempting to serialize tool result...")
                    print(f"{COLORS['SECONDARY']}[DEBUG]{COLORS['RESET']} Tool result keys: {list(tool_result.keys())}")
                    
                    # If it's a command, print more details to help diagnose
                    if tool_name == "exec_ssh_command":
                        print(f"{COLORS['SECONDARY']}[DEBUG]{COLORS['RESET']} stdout length: {len(tool_result.get('stdout', ''))}")
                        if len(tool_result.get('stdout', '')) > 0:
                            print(f"{COLORS['SECONDARY']}[DEBUG]{COLORS['RESET']} stdout sample (first 100 chars): {repr(tool_result.get('stdout', '')[:100])}")
                        print(f"{COLORS['SECONDARY']}[DEBUG]{COLORS['RESET']} stderr length: {len(tool_result.get('stderr', ''))}")
                    
                    # Further sanitize - replace completely by creating new strings
                    if 'stdout' in tool_result:
                        # Create a completely fresh string with only printable characters
                        import string
                        printable = set(string.printable)
                        tool_result['stdout'] = ''.join(c for c in tool_result['stdout'] if c in printable)
                    if 'stderr' in tool_result:
                        printable = set(string.printable)
                        tool_result['stderr'] = ''.join(c for c in tool_result['stderr'] if c in printable)
                
                # Handle SSH command results specially to truncate large outputs
                if tool_name == "exec_ssh_command":
                    # For SSH commands, truncate large outputs to reasonable size
                    stdout = str(tool_result.get("stdout", "")) if tool_result.get("stdout") is not None else ""
                    stderr = str(tool_result.get("stderr", "")) if tool_result.get("stderr") is not None else ""
                    
                    # Remove null bytes which aren't allowed in JSON
                    stdout = stdout.replace('\0', '')
                    stderr = stderr.replace('\0', '')
                    
                    # Truncate long outputs
                    if len(stdout) > 10000:
                        stdout = stdout[:5000] + "\n\n... [output truncated - " + str(len(stdout) - 10000) + " more characters] ...\n\n" + stdout[-5000:]
                    
                    if len(stderr) > 5000:
                        stderr = stderr[:2500] + "\n\n... [error output truncated - " + str(len(stderr) - 5000) + " more characters] ...\n\n" + stderr[-2500:]
                    
                    # Update the tool result with truncated outputs
                    tool_result["stdout"] = stdout
                    tool_result["stderr"] = stderr
                
                # Simple serialization with a single fallback
                try:
                    result_json = json.dumps(tool_result)
                except Exception as e:
                    print(f"\n{COLORS['HIGHLIGHT']}Error serializing tool result: {str(e)}{COLORS['RESET']}")
                    # Create minimal result that will always serialize
                    minimal_result = {
                        "success": False,
                        "error": f"Failed to serialize result: {str(e)}",
                        "tool_name": tool_name
                    }
                    result_json = json.dumps(minimal_result)

                messages.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": tool_block["id"],
                                "content": result_json,
                            }
                        ],
                    }
                )

                while True:
                    try:
                        second_response_stream = call_model(
                            anthropic_client, SYSTEM_MESSAGE, messages, tools
                        )
                        response_msg, tool_use_active = process_assistant_message(
                            second_response_stream
                        )
                        break
                    except anthropic.APIStatusError as e:
                        print(
                            f"Received {e=}, retrying in {anthropic_error_wait_time}s"
                        )
                        time.sleep(anthropic_error_wait_time)
                        continue
                    except Exception as e:
                        import traceback
                        print(f"\n{COLORS['HIGHLIGHT']}Unexpected error calling model: {str(e)}{COLORS['RESET']}")
                        print(f"{COLORS['HIGHLIGHT']}Error type: {type(e)}{COLORS['RESET']}")
                        print(f"{COLORS['HIGHLIGHT']}Detailed traceback:{COLORS['RESET']}")
                        traceback.print_exc()
                        break

                messages.append(
                    {"role": "assistant", "content": response_msg["content"]}
                )

            print()
