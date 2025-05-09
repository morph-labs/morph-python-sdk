import copy
import io
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional
import threading


from rich.console import Console
from rich.panel import Panel
from rich.json import JSON
from rich.table import Table
rich_console = Console()


from ._scramble import SCRAMBLE_TEXT, scramble_print

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
MORPHVM_PROMPT = f"{COLORS['PRIMARY']}[vm]:{COLORS['RESET']} "

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

def render_tool_result(result_data: Dict[str, Any]) -> None:
    """Render a tool result with Rich based on its metadata"""
    # Parse the JSON string if needed
    if isinstance(result_data, str):
        try:
            result_data = json.loads(result_data)
        except json.JSONDecodeError:
            rich_console.print(f"[bold red]Failed to parse JSON:[/bold red] {result_data}")
            return
    
    # Check for display metadata
    metadata = result_data.get("_display_metadata", {})
    
    # Determine display type and styling
    display_type = metadata.get("type", "text")
    title = metadata.get("title", "Tool Result")
    style = metadata.get("style", "white")
    
    # Set title and style based on success
    if "success" in result_data:
        if result_data["success"]:
            panel_title = f"[bold green]✅ {title}[/bold green]"
            panel_style = style if style != "white" else "green"
        else:
            panel_title = f"[bold red]❌ {title}[/bold red]"
            panel_style = "red"
    else:
        panel_title = title
        panel_style = style
    
    # Define max items to display in tables
    MAX_DISPLAY_ITEMS = 10
    
    # Handle different types of displays
    if display_type == "table":
        # Create appropriate table based on content
        if "instances" in result_data:
            # Instance table
            instances = result_data.get("instances", [])
            total_instances = result_data.get("total_count", len(instances))
            
            table = Table(
                title=f"Available Instances ({total_instances} total)" if len(instances) < total_instances else "Available Instances", 
                show_header=True, 
                header_style="bold cyan"
            )
            
            # Add columns based on metadata
            columns = metadata.get("columns", ["ID", "Status", "Snapshot ID", "VCPUs", "Memory", "Disk"])
            for col in columns:
                table.add_column(col)
                
            # Add rows
            for instance in instances:
                specs = instance.get("specs", {})
                table.add_row(
                    instance.get("id", ""),
                    instance.get("status", ""),
                    instance.get("snapshot_id", ""),
                    str(specs.get("vcpus", "")),
                    str(specs.get("memory", "")),
                    str(specs.get("disk_size", ""))
                )
                
            rich_console.print(Panel(table, title=panel_title, border_style=panel_style))
            
            # Show message if results were limited
            if len(instances) < total_instances:
                rich_console.print(f"[yellow]Showing {len(instances)} of {total_instances} instances.[/yellow]")
                
        elif "images" in result_data:
            # Images table
            images = result_data.get("images", [])
            
            table = Table(
                title=f"Available Images ({len(images)})", 
                show_header=True, 
                header_style="bold cyan"
            )
            
            # Add columns based on metadata
            columns = metadata.get("columns", ["ID", "Name", "Description", "Disk Size"])
            for col in columns:
                table.add_column(col)
                
            # Add rows
            for image in images:
                table.add_row(
                    image.get("id", ""),
                    image.get("name", ""),
                    image.get("description", ""),
                    str(image.get("disk_size", ""))
                )
                
            rich_console.print(Panel(table, title=panel_title, border_style=panel_style))
            
        elif "snapshots" in result_data:
            # Snapshots table
            snapshots = result_data.get("snapshots", [])
            total_snapshots = result_data.get("total_count", len(snapshots))
            
            table = Table(
                title=f"Available Snapshots ({total_snapshots} total)" if len(snapshots) < total_snapshots else "Available Snapshots", 
                show_header=True, 
                header_style="bold cyan"
            )
            
            # Add columns based on metadata
            columns = metadata.get("columns", ["ID", "Status", "VCPUs", "Memory", "Disk", "Digest"])
            for col in columns:
                table.add_column(col)
                
            # Add rows
            for snapshot in snapshots:
                specs = snapshot.get("specs", {})
                digest = snapshot.get("digest", "")
                # Truncate digest if too long
                if digest and len(digest) > 15:
                    digest = digest[:12] + "..."
                    
                table.add_row(
                    snapshot.get("id", ""),
                    snapshot.get("status", ""),
                    str(specs.get("vcpus", "")),
                    str(specs.get("memory", "")),
                    str(specs.get("disk_size", "")),
                    digest
                )
                
            rich_console.print(Panel(table, title=panel_title, border_style=panel_style))
            
            # Show message if results were limited
            if len(snapshots) < total_snapshots:
                rich_console.print(f"[yellow]Showing {len(snapshots)} of {total_snapshots} snapshots.[/yellow]")
        
        else:
            # Generic table fallback
            rich_console.print(
                Panel(
                    metadata.get("plaintext", str(result_data)),
                    title=panel_title,
                    border_style=panel_style
                )
            )
    
    elif display_type == "command_output":
        # Command execution output
        stdout = result_data.get("stdout", "")
        stderr = result_data.get("stderr", "")
        exit_code = result_data.get("exit_code", 0)
        timed_out = result_data.get("timed_out", False)
        
        # Handle different cases
        if timed_out:
            rich_console.print(
                Panel(
                    f"[bold yellow]Command timed out[/bold yellow]\n\n"
                    f"Partial stdout:\n{stdout[:1000] + '...' if len(stdout) > 1000 else stdout}"
                    f"\n\nPartial stderr:\n{stderr[:500] + '...' if len(stderr) > 500 else stderr}",
                    title=panel_title,
                    border_style="yellow"
                )
            )
        elif exit_code != 0:
            rich_console.print(
                Panel(
                    f"[bold red]Command failed (exit code: {exit_code})[/bold red]\n\n"
                    f"stdout:\n{stdout[:1000] + '...' if len(stdout) > 1000 else stdout}"
                    f"\n\nstderr:\n{stderr[:500] + '...' if len(stderr) > 500 else stderr}",
                    title=panel_title,
                    border_style="red"
                )
            )
        else:
            # For successful commands, just show the output
            content = stdout
            if len(content) > 2000:
                content = content[:1997] + "..."
                
            rich_console.print(
                Panel(
                    content,
                    title=panel_title,
                    border_style="green"
                )
            )
            
            # Show stderr separately if present
            if stderr:
                rich_console.print(
                    Panel(
                        stderr[:500] + "..." if len(stderr) > 500 else stderr,
                        title="[yellow]Command stderr[/yellow]",
                        border_style="yellow"
                    )
                )
                
    elif display_type == "error":
        # Error display
        error_msg = result_data.get("error", "Unknown error")
        rich_console.print(
            Panel(
                f"[bold red]Error:[/bold red] {error_msg}",
                title=panel_title,
                border_style="red"
            )
        )
        
    elif display_type == "created_resource" or display_type == "action_complete":
        # Resource creation or action completion
        rich_console.print(
            Panel(
                metadata.get("plaintext", str(result_data)),
                title=panel_title,
                border_style=panel_style
            )
        )
        
    elif display_type == "url":
        # URL display (for exposed services)
        url = result_data.get("url", "")
        rich_console.print(
            Panel(
                f"{metadata.get('plaintext', '')}\n\n[bold blue][link={url}]{url}[/link][/bold blue]",
                title=panel_title,
                border_style=panel_style
            )
        )
        
    else:
        # Default fallback - just show the plaintext version
        rich_console.print(
            Panel(
                metadata.get("plaintext", str(result_data)),
                title=panel_title,
                border_style=panel_style
            )
        )

def run_tool(tool_call: ToolCall, client) -> Dict[str, Any]:
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
            ssh_result = ssh_connect_and_run(instance, command, timeout)
            
            # Add instance_id to the result for reference
            result = {
                "success": ssh_result.get("exit_code", -1) == 0,
                "exit_code": ssh_result.get("exit_code", -1),
                "stdout": ssh_result.get("stdout", ""),
                "stderr": ssh_result.get("stderr", ""),
                "instance_id": instance_id,
                "timed_out": ssh_result.get("timed_out", False)
            }
            
            # Add display metadata
            status_msg = "Command succeeded" if result["success"] else "Command failed"
            if result["timed_out"]:
                status_msg = f"Command timed out after {timeout} seconds"
                
            result["_display_metadata"] = {
                "type": "command_output",
                "title": f"{status_msg} (exit code: {result['exit_code']})",
                "style": "green" if result["success"] else "red",
                "plaintext": result["stdout"] + ("\n" + result["stderr"] if result["stderr"] else "")
            }
            
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
                "digest": snapshot.digest,
                "_display_metadata": {
                    "type": "created_resource",
                    "title": "Snapshot Created",
                    "style": "green",
                    "plaintext": f"Created snapshot {snapshot.id} with status {snapshot.status.value}\nDigest: {snapshot.digest or 'None'}"
                }
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
                "created": instance.created,
                "_display_metadata": {
                    "type": "created_resource",
                    "title": "Instance Started",
                    "style": "green",
                    "plaintext": f"Started instance {instance.id} with status {instance.status.value}\nFrom snapshot: {snapshot_id}"
                }
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
                "digest": snapshot.digest,
                "_display_metadata": {
                    "type": "created_resource",
                    "title": "Instance Snapshotted",
                    "style": "green",
                    "plaintext": f"Created snapshot {snapshot.id} from instance {instance_id}\nStatus: {snapshot.status.value}, Digest: {snapshot.digest or 'None'}"
                }
            }
            
        elif tool_name == "stop_instance":
            instance_id = tool_input.get("instance_id")
            
            client.instances.stop(instance_id)
            
            result = {
                "success": True,
                "instance_id": instance_id,
                "message": f"Instance {instance_id} stopped successfully",
                "_display_metadata": {
                    "type": "action_complete",
                    "title": "Instance Stopped",
                    "style": "yellow",
                    "plaintext": f"Instance {instance_id} stopped successfully"
                }
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
            
            # Create plaintext version
            plaintext = "Available Images:\n"
            for image in images:
                plaintext += f"ID: {image.id}, Name: {image.name}\n"
                if image.description:
                    plaintext += f"  Description: {image.description}\n"
            
            result["_display_metadata"] = {
                "type": "table",
                "title": f"Available Images ({len(images)})",
                "style": "blue",
                "columns": ["ID", "Name", "Description", "Disk Size"],
                "plaintext": plaintext
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
            
            # Create plaintext version
            plaintext = f"Available Snapshots ({total_snapshots}):\n"
            for snapshot in limited_snapshots:
                plaintext += f"ID: {snapshot.id}, Status: {snapshot.status.value}\n"
                plaintext += f"  VCPUs: {snapshot.spec.vcpus}, Memory: {snapshot.spec.memory}MB\n"
            
            # Add a note to the plaintext if we limited the results
            if total_snapshots > limit:
                plaintext += f"\nNote: Only showing {limit} of {total_snapshots} snapshots."
            
            result["_display_metadata"] = {
                "type": "table",
                "title": f"Available Snapshots ({total_snapshots})",
                "style": "cyan",
                "columns": ["ID", "Status", "VCPUs", "Memory", "Disk", "Digest"],
                "plaintext": plaintext
            }
            
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
            
            # Create plaintext version
            plaintext = f"Available Instances ({total_instances}):\n"
            for instance in limited_instances:
                plaintext += f"ID: {instance.id}, Status: {instance.status.value}, "
                plaintext += f"Snapshot: {instance.refs.snapshot_id}\n"
            
            # Add a note to the plaintext if we limited the results
            if total_instances > limit:
                plaintext += f"\nNote: Only showing {limit} of {total_instances} instances."
            
            result["_display_metadata"] = {
                "type": "table",
                "title": f"Available Instances ({total_instances})",
                "style": "green",
                "columns": ["ID", "Status", "Snapshot ID", "VCPUs", "Memory", "Disk"],
                "plaintext": plaintext
            }
            
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
                "message": f"HTTP service '{name}' exposed successfully at {url}",
                "_display_metadata": {
                    "type": "url",
                    "title": "HTTP Service Exposed",
                    "style": "green",
                    "plaintext": f"HTTP service '{name}' exposed successfully.\nURL: {url}"
                }
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
                "message": f"HTTP service '{name}' hidden successfully",
                "_display_metadata": {
                    "type": "action_complete",
                    "title": "HTTP Service Hidden",
                    "style": "yellow",
                    "plaintext": f"HTTP service '{name}' hidden successfully."
                }
            }
            
        else:
            result = {
                "success": False,
                "error": f"Unknown tool '{tool_name}'",
                "_display_metadata": {
                    "type": "error",
                    "title": "Unknown Tool",
                    "style": "red",
                    "plaintext": f"Unknown tool '{tool_name}'"
                }
            }
    
    except Exception as e:
        result = {
            "success": False,
            "error": str(e),
            "_display_metadata": {
                "type": "error",
                "title": f"Error Running Tool: {tool_name}",
                "style": "red",
                "plaintext": f"Error executing {tool_name}: {str(e)}"
            }
        }
    
    # Display the result using the render_tool_result function
    render_tool_result(result)
    
    return result


def call_model(
    anthropic_client: anthropic.Anthropic, system: str, messages: List[Dict], tools: List[Dict]
):
    return anthropic_client.messages.create(
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
            tool_input = json.loads(tool_input_json) if tool_input_json else {}
            assert current_tool_block is not None
            current_tool_block["input"] = tool_input
            response_msg["content"].append(current_tool_block)

        content_acc.seek(0)
        content_acc.truncate()

    print()
    sys.stdout.write(MORPHVM_PROMPT)
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

def agent_loop(
    morph_client,  # Change from 'instance' to 'client'
    initial_prompt: Optional[str] = None,
    conversation_file: Optional[str] = None,
    debug: bool = False  # Add debug parameter
):
    """
    Interactive REPL that persists conversation state in YAML and, when
    re-started, replays that state so the user appears to resume the same
    terminal session.
    """
    import yaml  # pip install pyyaml

    SYSTEM_MESSAGE = """# Background
You are a Morph Virtual Machine, a cloud environment for securely executing AI generated code, you are a semi-autonomous agent that can run commands inside of your MorphVM environment.

# Style
Answer user questions and run commands on the MorphVM instance. Answer user questions in the first person as the MorphVM instance. Keep responses concise and to the point. The user can see the output of the command and the exit code so you don't need to repeat this information in your response.
DO NOT REPEAT THE COMMAND OUTPUT IN YOUR RESPONSE.

# Environment
You are running inside of a minimal Debian-based operating system. You have access to an MMDS V2 protocol metadata server accessible at 169.254.169.254 with information about the MorphVM instance. You'll need to grab the X-metadata-token from /latest/api/token to authenticate with the server.

# Interface
You have one tool available: "run_command" which takes a command to run and returns the result. Inspect the stdout, stderr, and exit code of the command's result and provide a response. Note that each command you execute will be run in a separate SSH session so any state changes (e.g. environment variables, directory changes) will not persist between commands. Handle this transparently for the user.
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

    # ------------------------------------------------------------- #
    # Conversation persistence
    # ------------------------------------------------------------- #
    messages: List[Dict[str, Any]] = []

    if conversation_file and os.path.exists(conversation_file):
        try:
            with open(conversation_file, "r") as f:
                loaded = yaml.safe_load(f) or []
                if isinstance(loaded, list):
                    messages = loaded
        except Exception:
            # Broken file → start fresh, but don't disturb stdout.
            messages = []

    def save_conversation() -> None:
        if conversation_file:
            try:
                with open(conversation_file, "w") as f:
                    yaml.safe_dump(messages, f, sort_keys=False, allow_unicode=True)
            except Exception:
                pass  # ignore write errors silently

    # ------------------------------------------------------------- #
    # Helpers for replaying a prior session (preserve layout)       #
    # ------------------------------------------------------------- #
    def _gather_text_blocks(content) -> str:
        """
        Concatenate all text contained in `content` (string or list of blocks).
        Non-text blocks are ignored.
        """
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            return "".join(
                blk.get("text", "")
                for blk in content
                if isinstance(blk, dict) and blk.get("type") == "text"
            )
        return str(content)

    def _render_tool_result(tr: dict) -> None:
        """
        Render the same summary that ssh_connect_and_run prints after a command
        finishes, using exit_code / stdout / stderr from the stored tool_result.
        """
        exit_code = tr.get("exit_code", -1)
        stdout = tr.get("stdout", "")
        stderr = tr.get("stderr", "")

        # Same header / colour choices the live run uses
        print(f"\n{COLORS['SECONDARY']}{'─' * 50}{COLORS['RESET']}")
        print(f"\n{COLORS['OUTPUT_HEADER']}Output:{COLORS['RESET']}")
        if stdout:
            print(f"{COLORS['TEXT']}{stdout.rstrip()}{COLORS['RESET']}")
        if stderr:
            print(f"{COLORS['HIGHLIGHT']}[stderr] {stderr.rstrip()}{COLORS['RESET']}")

        print(f"\n{COLORS['OUTPUT_HEADER']}Status:{COLORS['RESET']}")
        status_colour = COLORS["SUCCESS"] if exit_code == 0 else COLORS["ERROR"]
        status_msg = "✓ Command succeeded" if exit_code == 0 else "✗ Command failed"
        print(f"{status_colour}{status_msg} (exit code: {exit_code}){COLORS['RESET']}")

        if stderr:
            print(
                f"{COLORS['ERROR']}Command produced error output - see [stderr] messages above{COLORS['RESET']}"
            )
        print(f"\n{COLORS['SECONDARY']}{'─' * 50}{COLORS['RESET']}\n")

    def replay_previous_dialogue() -> None:
        """
        Re-emit the stored conversation so the terminal looks exactly as it
        did when the last session ended – correct spacing, debug lines and
        command-output panel. Nothing is re-executed.
        """
        # Build lookup  tool_use_id  ->  parsed tool_result
        tool_results: Dict[str, dict] = {}
        for m in messages:
            if m["role"] == "user" and isinstance(m["content"], list):
                for blk in m["content"]:
                    if isinstance(blk, dict) and blk.get("type") == "tool_result":
                        try:
                            tool_results[blk["tool_use_id"]] = json.loads(
                                blk["content"]
                            )
                        except Exception:
                            pass

        for msg in messages:
            # -------------- USER ----------------------------------------
            if msg["role"] == "user":
                # messages that contain only a tool_result are silent
                if isinstance(msg["content"], list) and all(
                    isinstance(b, dict) and b.get("type") == "tool_result"
                    for b in msg["content"]
                ):
                    continue

                print(
                    f"{USER_PROMPT}{COLORS['TEXT']}{_gather_text_blocks(msg['content'])}{COLORS['RESET']}"
                )
                print()  # <Enter> pressed by the user

            # -------------- ASSISTANT ----------------------------------
            elif msg["role"] == "assistant":
                last_block_was_tool_use = False

                for blk in msg["content"]:
                    # -- text ------------------------------------------------
                    if isinstance(blk, dict) and blk.get("type") == "text":
                        txt = blk.get("text", "")
                        sys.stdout.write(MORPHVM_PROMPT)
                        sys.stdout.write(COLORS["TEXT"] + txt + COLORS["RESET"] + "\n")
                        sys.stdout.flush()
                        last_block_was_tool_use = False

                    # -- tool_use -------------------------------------------
                    elif isinstance(blk, dict) and blk.get("type") == "tool_use":
                        last_block_was_tool_use = True
                        tool_name = blk.get("name")
                        tool_input = blk.get("input", {})

                        print(
                            f"\n{COLORS['SECONDARY']}[DEBUG]{COLORS['RESET']} Tool call received: "
                            f"name='{COLORS['PRIMARY']}{tool_name}{COLORS['RESET']}' "
                            f"input={COLORS['TEXT']}{tool_input}{COLORS['RESET']}"
                        )

                        # Show the command to be executed if it's an SSH command
                        if tool_name == "exec_ssh_command":
                            cmd = tool_input.get("command", "")
                            print(
                                f"{COLORS['SECONDARY']}[DEBUG]{COLORS['RESET']} Running SSH command: "
                                f"{COLORS['TEXT']}{cmd}{COLORS['RESET']}"
                            )

                        # Get the tool result and render it
                        tr = tool_results.get(blk["id"])
                        if tr is not None:
                            render_tool_result(tr)
                        else:
                            # Fallback if no tool result found
                            print(f"\n{COLORS['HIGHLIGHT']}[ERROR]{COLORS['RESET']} No tool result found for {blk['id']}")

                # live session prints ONE blank line after a text-only
                # assistant message, and ZERO after a message that ends in
                # a tool_use block (because the tool-result panel already
                # leaves the cursor on a blank line).  Reproduce that:
                if not last_block_was_tool_use:
                    print()

    # cursor now sits on a fresh line ready for the next prompt


    # ------------------------------------------------------------- #
    # Banner / greeting (unchanged)
    # ------------------------------------------------------------- #
    scramble_print(
        SCRAMBLE_TEXT,
        speed=2.0,
        seed=1,
        step=1,
        scramble=3,
        chance=1.0,
        overflow=True,
    )
    print(f"{COLORS['TEXT']}Welcome to the Morph VM chat cli.{COLORS['RESET']}")
    print(f"{COLORS['SECONDARY']}Type 'exit' or 'quit' to stop.{COLORS['RESET']}\n")

    # Immediately replay any previously-saved conversation so the screen
    # looks identical to where the user left off.
    replay_previous_dialogue()

    # ------------------------------------------------------------- #
    # Model client
    # ------------------------------------------------------------- #
    try:
        anthropic_client = anthropic.Anthropic(api_key=_get_anthropic_api_key())
    except KeyError:
        print(
            f"{COLORS['HIGHLIGHT']}Error: ANTHROPIC_API_KEY not found.{COLORS['RESET']}"
        )
        raise

    if readline:

        class SimpleCompleter:
            def complete(self, text, state):
                if state == 0:
                    return text if text else None

        readline.set_completer(SimpleCompleter().complete)

    # ------------------------------------------------------------- #
    # Optional initial prompt (only if no history loaded)
    # ------------------------------------------------------------- #
    if initial_prompt and not messages:
        messages.append({"role": "user", "content": initial_prompt})
        save_conversation()

    # ------------------------------------------------------------- #
    # Main REPL loop
    # ------------------------------------------------------------- #
    while True:
        # -- input --------------------------------------------------- #
        try:
            while True:
                user_input = input(USER_PROMPT).strip()
                if user_input:
                    break
        except EOFError:
            print(f"\n{COLORS['HIGHLIGHT']}Exiting...{COLORS['RESET']}")
            break

        if user_input.lower() in ("exit", "quit"):
            print(f"{COLORS['HIGHLIGHT']}Exiting...{COLORS['RESET']}")
            break

        messages.append({"role": "user", "content": user_input})
        save_conversation()

        # -- model call --------------------------------------------- #
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

        messages.append({"role": "assistant", "content": response_msg["content"]})
        save_conversation()

        # -- tool handling ------------------------------------------ #
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
                    f"\n{COLORS['SECONDARY']}[DEBUG]{COLORS['RESET']} Tool call received: "
                    f"name='{COLORS['PRIMARY']}{tool_name}{COLORS['RESET']}' "
                    f"input={COLORS['TEXT']}{tool_input}{COLORS['RESET']}"
                )

                tool_call = ToolCall(name=tool_name, input=tool_input)
                tool_result = run_tool(tool_call, morph_client)

                messages.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": tool_block["id"],
                                "content": json.dumps(tool_result),
                            }
                        ],
                    }
                )
                save_conversation()

            while True:
                try:
                    second_stream = call_model(anthropic_client, SYSTEM_MESSAGE, messages, tools)
                    response_msg, tool_use_active = process_assistant_message(
                        second_stream
                    )
                    break
                except anthropic.APIStatusError as e:
                    print(f"Received {e=}, retrying in {anthropic_error_wait_time}s")
                    time.sleep(anthropic_error_wait_time)

            messages.append({"role": "assistant", "content": response_msg["content"]})
            save_conversation()

        print()  # maintain original blank-line behaviour

    save_conversation()  # final flush on exit
