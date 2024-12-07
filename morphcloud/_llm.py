import io
import os
import sys
import json
import argparse

from typing import List, Dict, Any

try:
    import gnureadline as readline
except ImportError:
    try:
        import readline
    except ImportError:
        readline = None

if readline:
    readline.parse_and_bind("tab: complete")

import paramiko
from anthropic import Anthropic
from pydantic import BaseModel

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
MODEL_NAME = "claude-3-5-sonnet-20241022"

# Updated color scheme for light background
COLORS = {
    "PRIMARY": "\033[38;2;95;148;23m",      # Darker green for primary text
    "HIGHLIGHT": "\033[38;2;184;52;51m",    # Darker red for highlights
    "TEXT": "\033[38;2;51;51;51m",          # Dark gray for main text
    "SECONDARY": "\033[38;2;102;102;102m",  # Medium gray for secondary text
    "RESET": "\033[0m"
}

# Create prompts
USER_PROMPT = f"{COLORS['HIGHLIGHT']}(user)>{COLORS['RESET']} "
MORPHVM_PROMPT = f"{COLORS['PRIMARY']}(morphvm)>{COLORS['RESET']} "

SYSTEM_MESSAGE = """# Background
You are a Morph Virtual Machine, a cloud environment for securely executing AI generated code, you are a semi-autonomous agent that can run commands inside of your MorphVM environment.

# Style
Answer user questions and run commands on the MorphVM instance.
Anser user questions in the first person.

# Interface
You have one tool available: "run_command" which takes a command to run and returns the result.
Inspect the stdout, stderr, and exit code of the command's result and provide a response.
Note that each command you execute will be run in a separate SSH session so any state changes (e.g. environment variables, directory changes) will not persist between commands. Handle this transparently for the user.

# Misc
The user can see the output of the command and the exit code so you don't need to repeat this information in your response.
DO NOT REPEAT THE COMMAND OUTPUT IN YOUR RESPONSE.
"""

MAX_TOKENS = 1000

class ToolCall(BaseModel):
    name: str
    input: dict


def ssh_connect_and_run(instance_id: str, morph_api_key: str, command: str) -> Dict[str, Any]:
    hostname = "localhost"
    port = 2222
    username = f"{instance_id}:{morph_api_key}"

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, port=port, username=username, password="")

    # Start the command
    stdin, stdout, stderr = ssh.exec_command(command)
    
    # print(f"\n{COLORS['TEXT']}Output:{COLORS['RESET']}")
    OUTPUT_HEADER = "\033[38;2;0;0;128m"    # Dark blue for headers
    print(f"\n{OUTPUT_HEADER}Output:{COLORS['RESET']}")
    
    # Stream output in real-time
    while not stdout.channel.exit_status_ready():
        # Check stdout
        if stdout.channel.recv_ready():
            stdout_data = stdout.channel.recv(1024).decode('utf-8', errors='replace')
            if stdout_data:
                print(f"{COLORS['TEXT']}{stdout_data}{COLORS['RESET']}", end='', flush=True)
        
        # Check stderr
        if stderr.channel.recv_stderr_ready():
            stderr_data = stderr.channel.recv_stderr(1024).decode('utf-8', errors='replace')
            if stderr_data:
                print(f"{COLORS['HIGHLIGHT']}{stderr_data}{COLORS['RESET']}", end='', flush=True)

    # Get any remaining output after command completes
    remaining_stdout = stdout.read().decode('utf-8', errors='replace')
    remaining_stderr = stderr.read().decode('utf-8', errors='replace')
    
    if remaining_stdout:
        print(f"{COLORS['TEXT']}{remaining_stdout}{COLORS['RESET']}", end='', flush=True)
    if remaining_stderr:
        print(f"{COLORS['HIGHLIGHT']}{remaining_stderr}{COLORS['RESET']}", end='', flush=True)

    exit_code = stdout.channel.recv_exit_status()

    # Print command status after all output
    SUCCESS_COLOR = "\033[38;2;0;128;0m"
    ERROR_COLOR = "\033[38;2;196;0;0m"
    status_color = SUCCESS_COLOR if exit_code == 0 else ERROR_COLOR
    print(f"\n{OUTPUT_HEADER}Status:{COLORS['RESET']}")
    print(f"{status_color}{'✓ Command succeeded' if exit_code == 0 else '✗ Command failed'} (exit code: {exit_code}){COLORS['RESET']}")
    print(f"\n{COLORS['SECONDARY']}{'─' * 50}{COLORS['RESET']}")

    ssh.close()
    return {"exit_code": exit_code, "stdout": remaining_stdout, "stderr": remaining_stderr}

def format_command_result(result: Dict[str, Any]) -> None:
    """
    Format and print the result of a command execution with combined stdout/stderr
    under a single Output section, followed by command status.
    """
    # Define additional color codes for specific outputs
    SUCCESS_COLOR = "\033[38;2;0;128;0m"    # Dark green for success
    ERROR_COLOR = "\033[38;2;196;0;0m"      # Dark red for errors
    OUTPUT_HEADER = "\033[38;2;0;0;128m"    # Dark blue for headers

    # Print output header and content
    print(f"\n{OUTPUT_HEADER}Output:{COLORS['RESET']}")
    
    # Print stdout if not empty
    if result['stdout'].strip():
        print(f"{COLORS['TEXT']}{result['stdout'].rstrip()}{COLORS['RESET']}")

    # Print stderr if not empty
    if result['stderr'].strip():
        print(f"{COLORS['HIGHLIGHT']}{result['stderr'].rstrip()}{COLORS['RESET']}")

    # Print command status after output
    exit_code = result['exit_code']
    status_color = SUCCESS_COLOR if exit_code == 0 else ERROR_COLOR
    print(f"\n{status_color}{'✓ Command succeeded' if exit_code == 0 else '✗ Command failed'} (exit code: {exit_code}){COLORS['RESET']}")

    # Print separator for better readability
    print(f"\n{COLORS['SECONDARY']}{'─' * 50}{COLORS['RESET']}")

def run_tool(tool_call: ToolCall, instance_id: str, morph_api_key: str) -> Dict[str, Any]:
    if tool_call.name == "run_command":
        cmd = tool_call.input.get("command", "")
        print(f"{COLORS['SECONDARY']}[DEBUG]{COLORS['RESET']} Running SSH command: {COLORS['TEXT']}{cmd}{COLORS['RESET']}")
        result = ssh_connect_and_run(instance_id, morph_api_key, cmd)
        # format_command_result(result)
        return result
    else:
        return {"error": f"Unknown tool '{tool_call.name}'"}

def add_cache_control_to_last_content(messages: List[Dict]) -> List[Dict]:
    return messages

def call_model(client: Anthropic, system: str, messages: List[Dict], tools: List[Dict]):
    return client.messages.create(
        model=MODEL_NAME,
        system=system,
        messages=add_cache_control_to_last_content(messages),
        max_tokens=MAX_TOKENS,
        tools=tools,
        stream=True
    )

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
                # Reset this flag each time we start a new text block
                first_text_chunk = True

        elif chunk.type == "content_block_delta":
            if content_block_type in ["text", "tool_use"]:
                if content_block_type == "text":
                    text_to_print = chunk.delta.text
                    # Strip leading newlines if this is the first text chunk
                    if first_text_chunk:
                        text_to_print = text_to_print.lstrip('\n')
                        first_text_chunk = False
                    sys.stdout.write(COLORS['TEXT'] + text_to_print + COLORS['RESET'])
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

def agent_loop(instance_id: str, morph_api_key: str):
    client = Anthropic(api_key=ANTHROPIC_API_KEY)

    tools = [
        {
            "name": "run_command",
            "description": "Execute a command on a remote morphvm instance via SSH.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"}
                },
                "required": ["command"]
            }
        }
    ]

    messages = []

    # Print ASCII art with new color scheme
    print(f"{COLORS['PRIMARY']}", end="")
    print("                               __  _    ____  ___")
    print("   ____ ___  ____  _________  / /_| |  / /  |/  /")
    print("  / __ `__ \\/ __ \\/ ___/ __ \\/ __ \\ | / / /|_/ /")
    print(" / / / / / / /_/ / /  / /_/ / / / / |/ / /  / /")
    print("/_/ /_/ /_/\\____/_/  / .___/_/ /_/|___/_/  /_/")
    print("                    /_/")
    print(f"{COLORS['RESET']}")

    print(f"{COLORS['TEXT']}Welcome to the Morph VM CLI SSH chat.{COLORS['RESET']}")
    print(f"{COLORS['SECONDARY']}Type 'exit' or 'quit' to stop.{COLORS['RESET']}\n")

    # Create a custom completer class if needed
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
                if readline:
                    USER_PROMPT = "\001\033[38;2;184;52;51m\002(user)>\001\033[0m\002 "
                    user_input = input(USER_PROMPT)
                else:
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

        response_stream = call_model(client, SYSTEM_MESSAGE, messages, tools)
        response_msg, tool_use_active = process_assistant_message(response_stream)

        messages.append({"role": "assistant", "content": response_msg["content"]})

        while tool_use_active:
            tool_use_blocks = [c for c in response_msg["content"] if c["type"] == "tool_use"]
            if not tool_use_blocks:
                print(f"{COLORS['HIGHLIGHT']}[ERROR]{COLORS['RESET']} Assistant mentioned a tool but no tool_use block found in content.")
                break

            for tool_block in tool_use_blocks:
                tool_name = tool_block["name"]
                tool_input = tool_block.get("input", {})

                print(f"\n{COLORS['SECONDARY']}[DEBUG]{COLORS['RESET']} Tool call received: name='{COLORS['PRIMARY']}{tool_name}{COLORS['RESET']}' input={COLORS['TEXT']}{tool_input}{COLORS['RESET']}")
                tool_call = ToolCall(name=tool_name, input=tool_input)
                tool_result = run_tool(tool_call, instance_id, morph_api_key)

                messages.append({
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": tool_block["id"],
                            "content": json.dumps(tool_result)
                        }
                    ]
                })

                second_response_stream = call_model(client, SYSTEM_MESSAGE, messages, tools)
                response_msg, tool_use_active = process_assistant_message(second_response_stream)
                messages.append({"role": "assistant", "content": response_msg["content"]})

            print()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple SSH CLI chat with Morph VM")
    parser.add_argument("--instance-id", required=True, help="The Morph VM instance ID to connect to")
    parser.add_argument("--morph-api-key", required=False, default=os.environ.get("MORPH_API_KEY", ""), help="Morph API Key")
    args = parser.parse_args()

    agent_loop(args.instance_id, args.morph_api_key)
