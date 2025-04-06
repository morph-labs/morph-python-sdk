import copy
import io
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

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


def ssh_connect_and_run(instance, command: str) -> Dict[str, Any]:
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


def run_tool(tool_call: ToolCall, instance) -> Dict[str, Any]:
    if tool_call.name == "run_command":
        cmd = tool_call.input.get("command", "")
        print(
            f"{COLORS['SECONDARY']}[DEBUG]{COLORS['RESET']} Running SSH command: {COLORS['TEXT']}{cmd}{COLORS['RESET']}"
        )
        result = ssh_connect_and_run(instance, cmd)
        return result
    else:
        return {"error": f"Unknown tool '{tool_call.name}'"}


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


def agent_loop(instance, initial_prompt: Optional[str] = None):

    SYSTEM_MESSAGE = """# Background
You are a Morph Virtual Machine, a cloud environment for securely executing AI generated code, you are a semi-autonomous agent that can run commands inside of your MorphVM environment.

# Style
Answer user questions and run commands on the MorphVM instance.
Answer user questions in the first person as the MorphVM instance.
Keep responses concise and to the point.
The user can see the output of the command and the exit code so you don't need to repeat this information in your response.
DO NOT REPEAT THE COMMAND OUTPUT IN YOUR RESPONSE.

# Environment
You are running inside of a minimal Debian-based operating system.
You have access to an MMDS V2 protocol metadata server accessible at 169.254.169.254 with information about the MorphVM instance. You'll need to grab the X-metadata-token from /latest/api/token to authenticate with the server.

# Interface
You have one tool available: "run_command" which takes a command to run and returns the result.
Inspect the stdout, stderr, and exit code of the command's result and provide a response.
Note that each command you execute will be run in a separate SSH session so any state changes (e.g. environment variables, directory changes) will not persist between commands. Handle this transparently for the user.
"""
    tools = [
        {
            "name": "run_command",
            "description": "Execute a command on a remote morphvm instance via SSH.",
            "input_schema": {
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"],
            },
        }
    ]

    messages = []

    scramble_print(
        SCRAMBLE_TEXT,
        speed=2.0,
        seed=1,
        step=1,  # Reduced step size from 2 to 1
        scramble=3,  # Increased for more visible effect
        chance=1.0,  # Set to 1.0 for deterministic resolution
        overflow=True,  # Allow full-width ASCII art
    )
    print(f"{COLORS['TEXT']}Welcome to the Morph VM chat cli.{COLORS['RESET']}")
    print(f"{COLORS['SECONDARY']}Type 'exit' or 'quit' to stop.{COLORS['RESET']}\n")

    try:
        client = anthropic.Anthropic(api_key=_get_anthropic_api_key())
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

    while True:
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

        SYSTEM_MESSAGE = SYSTEM_MESSAGE + (
            f"\n# Additional instructions\n\n{initial_prompt}\n"
            if initial_prompt
            else ""
        )

        anthropic_error_wait_time = 3
        patience = 3
        num_tries = 0
        while num_tries < patience:
            try:
                response_stream = call_model(client, SYSTEM_MESSAGE, messages, tools)
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
                tool_result = run_tool(tool_call, instance)

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

                while True:
                    try:
                        second_response_stream = call_model(
                            client, SYSTEM_MESSAGE, messages, tools
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
                        break

                messages.append(
                    {"role": "assistant", "content": response_msg["content"]}
                )

            print()
