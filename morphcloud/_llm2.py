#!/usr/bin/env python
import copy
import io
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, Union

# Import scramble functionality.
from ._scramble import SCRAMBLE_TEXT, scramble_print

try:
    import gnureadline as readline  # type: ignore
except ImportError:
    try:
        import readline  # type: ignore
    except ImportError:
        readline = None

if readline:
    readline.parse_and_bind("tab: complete")

import anthropic
from pydantic import BaseModel

# --------------------------------------------------
# Constants and configuration
# --------------------------------------------------

MODEL_NAME = "claude-3-5-sonnet-20241022"
MAX_TOKENS = 4096
anthropic_error_wait_time = 5  # seconds between retries on intermittent errors

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

# A prompt for legacy terminal output (unused in the TUI)
MORPHVM_PROMPT = f"{COLORS['PRIMARY']}[vm]:{COLORS['RESET']} "

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

# --------------------------------------------------
# Helper functions and tool implementations
# --------------------------------------------------


def _get_anthropic_api_key() -> str:
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    assert key, "Anthropic API key cannot be an empty string"
    return key


def add_cache_control_to_last_content(
    messages: List[Dict],
    cache_control: Dict = {"type": "ephemeral"},
    max_cache_controls: int = 4,
) -> List[Dict]:
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


def ssh_connect_and_run(instance: Any, command: str) -> Dict[str, Any]:
    with instance.ssh() as ssh:
        OUTPUT_HEADER = COLORS["OUTPUT_HEADER"]
        print(f"\n{COLORS['SECONDARY']}{'─' * 50}{COLORS['RESET']}")
        print(f"\n{OUTPUT_HEADER}Output:{COLORS['RESET']}")
        last_stdout = ""
        last_stderr = ""
        with ssh.run(command, background=True, get_pty=True) as process:
            while True:
                current_stdout = process.stdout
                if current_stdout != last_stdout:
                    new_output = current_stdout[len(last_stdout) :]
                    print(
                        f"{COLORS['TEXT']}{new_output}{COLORS['RESET']}",
                        end="",
                        flush=True,
                    )
                    last_stdout = current_stdout
                current_stderr = process.stderr
                if current_stderr != last_stderr:
                    new_stderr = current_stderr[len(last_stderr) :]
                    print(
                        f"{COLORS['HIGHLIGHT']}[stderr] {new_stderr}{COLORS['RESET']}",
                        end="",
                        flush=True,
                    )
                    last_stderr = current_stderr
                if process.completed:
                    break
                time.sleep(0.01)
            final_stdout = process.stdout
            final_stderr = process.stderr
            returncode = process.channel.recv_exit_status()
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
                "\033[?25h"
                "\033[?7h"
                "\033[?47l"
                "\033[!p"
                "\033[?1l"
                "\033[?12l"
                "\033[?25h",
                end="",
                flush=True,
            )
            return {
                "exit_code": returncode,
                "stdout": final_stdout,
                "stderr": final_stderr,
            }


class ToolCall(BaseModel):
    name: str
    input: dict


def run_tool(tool_call: ToolCall, instance: Any) -> Dict[str, Any]:
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


# --------------------------------------------------
# Asynchronous message processing (fixed)
# --------------------------------------------------
async def process_assistant_message(response_stream) -> Dict:
    """
    Consume the streaming response from Anthropic and build the assistant message.
    Bug fixes:
      - Removed direct writes to sys.stdout (which interfered with the TUI).
      - At stream end, flush any remaining accumulated text.
    """
    response_msg = {"role": "assistant", "content": []}
    content_block_type = None
    content_acc = io.StringIO()
    current_tool_block = None

    def flush_content():
        nonlocal content_block_type, content_acc, current_tool_block
        if content_block_type == "text":
            text_block = content_acc.getvalue()
            if text_block.strip():
                response_msg["content"].append({"type": "text", "text": text_block})
        elif content_block_type == "tool_use":
            tool_input_json = content_acc.getvalue()
            tool_input = json.loads(tool_input_json) if tool_input_json else {}
            if current_tool_block is not None:
                current_tool_block["input"] = tool_input
                response_msg["content"].append(current_tool_block)
        content_acc.seek(0)
        content_acc.truncate()

    try:
        async for chunk in response_stream:
            if chunk.type == "message_start":
                continue
            elif chunk.type == "content_block_start":
                if content_block_type:
                    flush_content()
                content_block_type = chunk.content_block.type
                content_acc.seek(0)
                content_acc.truncate()
                if content_block_type == "tool_use":
                    current_tool_block = {
                        "type": "tool_use",
                        "name": chunk.content_block.name,
                        "id": chunk.content_block.id,
                    }
            elif chunk.type == "content_block_delta":
                if content_block_type == "text":
                    # Instead of printing to sys.stdout, we only accumulate text.
                    text_to_append = chunk.delta.text or ""
                    content_acc.write(text_to_append)
                elif content_block_type == "tool_use":
                    content_acc.write(chunk.delta.partial_json or "")
            elif chunk.type == "content_block_stop":
                flush_content()
                content_block_type = None
        # --- Bug fix: flush any pending text if stream ended unexpectedly ---
        if content_acc.getvalue().strip():
            flush_content()
        return {
            "message": response_msg,
            "tool_use_active": any(
                b["type"] == "tool_use" for b in response_msg["content"]
            ),
        }
    except Exception as e:
        # You might log or handle the exception here.
        raise e


# --------------------------------------------------
# TUI Implementation with Textual (with fixes)
# --------------------------------------------------

import asyncio
import signal

# Import Textual modules
from textual.app import App, ComposeResult
from textual.containers import (Container, Horizontal, ScrollableContainer,
                                Vertical)
from textual.reactive import reactive
from textual.widgets import (Button, Footer, Header, Input, Label, ListItem,
                             ListView, Log, Static)


class ChatSession:
    """Represents a chat session (or tab) with its own message history."""

    def __init__(self, name: str, instance: Any):
        self.name = name
        self.messages: List[Dict[str, Union[str, List[Dict]]]] = []
        self.instance = instance

    def append_user_message(self, text: str):
        self.messages.append({"role": "user", "content": text})

    def append_assistant_message(self, content_blocks: List[Dict[str, Any]]):
        self.messages.append({"role": "assistant", "content": content_blocks})


class Sidebar(Static):
    """Sidebar widget listing sessions and providing a new-session button."""

    def __init__(
        self,
        sessions: List[ChatSession],
        on_session_selected,
        on_new_session,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.sessions = sessions
        self.on_session_selected = on_session_selected
        self.on_new_session = on_new_session

    def compose(self) -> ComposeResult:
        yield Label("Sessions", id="sidebar-title")
        with ScrollableContainer():
            self.list_view = ListView(id="sessions-list")
            for idx, session in enumerate(self.sessions):
                self.list_view.append(
                    ListItem(Label(session.name), id=f"session-{idx}")
                )
            yield self.list_view
        yield Button("New Session", id="new-session-btn")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "new-session-btn":
            self.on_new_session()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        selected_id = event.item.id
        if selected_id.startswith("session-"):
            idx = int(selected_id.split("-")[-1])
            self.on_session_selected(idx)


class ChatView(Static):
    """
    Main chat area: shows the conversation history and includes an input field.
    Uses the Log widget (which is already scrollable).
    """

    def __init__(self, on_user_message_entered, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.on_user_message_entered = on_user_message_entered
        self.text_log = Log(
            highlight=True
        )  # Removed markup parameter as it's no longer supported
        self.input_box = Input(
            placeholder="Type your message... (Ctrl-C to interrupt streaming)"
        )

    def compose(self) -> ComposeResult:
        with Vertical():
            with ScrollableContainer(id="chat-scroll"):
                yield self.text_log
            yield self.input_box

    def write_message(self, speaker: str, text: str) -> None:
        if speaker == "user":
            self.text_log.write(f"[bold magenta]{speaker}[/bold magenta]: {text}")
        elif speaker == "assistant":
            self.text_log.write(f"[bold green]{speaker}[/bold green]: {text}")
        else:
            self.text_log.write(f"[bold yellow]{speaker}[/bold yellow]: {text}")
        # Auto-scroll to bottom after writing message
        if hasattr(self, "text_log"):
            self.text_log.scroll_end(animate=False)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        user_text = event.value.strip()
        if user_text:
            self.on_user_message_entered(user_text)
            self.input_box.value = ""


class ChatTUI(App):
    """
    A Textual TUI application that:
      - Maintains multiple chat sessions (tabs) via a sidebar.
      - Streams responses from Anthropic.
      - Supports interrupting streaming (Ctrl-C).
    """

    CSS = """
    Sidebar {
        width: 20%;
        min-width: 20;
        border-right: solid white;
        padding: 1;
    }
    
    ChatView {
        width: 80%;
        padding: 1;
        background: $surface;
    }
    
    #chat-scroll {
        height: 90vh;
        border: solid $accent;
        padding: 1;
    }
    
    #sessions-list {
        height: auto;
        max-height: 80vh;
    }
    
    Input {
        dock: bottom;
        margin: 1;
    }
    
    Label {
        text-align: center;
        width: 100%;
    }

    Log {
        background: $surface-darken-1;
        color: $text;
        padding: 1;
        height: 100%;
        border: none;
    }
    """

    BINDINGS = [
        ("ctrl+c", "handle_ctrl_c", "Interrupt streaming"),
        ("q", "quit", "Quit the application"),
    ]
    current_session_index = reactive(0)

    def __init__(self, instance: Any, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.instance = instance
        self.sessions: List[ChatSession] = []
        self.sidebar: Optional[Sidebar] = None
        self.chat_view: Optional[ChatView] = None
        self.stop_streaming = asyncio.Event()
        self.client = None
        self._stream_task: Optional[asyncio.Task] = None

    def compose(self) -> ComposeResult:
        # Removed scramble_print to avoid interfering with TUI
        with Horizontal():
            self.sidebar = Sidebar(
                sessions=self.sessions,
                on_session_selected=self.switch_session,
                on_new_session=self.create_new_session,
                id="sidebar",
            )
            yield self.sidebar
            self.chat_view = ChatView(
                on_user_message_entered=self.handle_user_message, id="chat-view"
            )
            yield self.chat_view
        yield Header()
        yield Footer()

    async def on_mount(self) -> None:
        try:
            self.client = anthropic.Anthropic(api_key=_get_anthropic_api_key())
        except Exception as e:
            self.chat_view.write_message(
                "system", f"Error: Could not load Anthropic client: {e}"
            )
        self.create_new_session()

    def create_new_session(self):
        new_session_name = f"Session {len(self.sessions) + 1}"
        session = ChatSession(name=new_session_name, instance=self.instance)
        self.sessions.append(session)
        if self.sidebar and self.sidebar.list_view:
            idx = len(self.sessions) - 1
            self.sidebar.list_view.append(
                ListItem(Label(session.name), id=f"session-{idx}")
            )
            self.switch_session(idx)
            # Add an initial system message to show the session is active
            if self.chat_view:
                self.chat_view.write_message(
                    "system",
                    f"New session '{new_session_name}' created. Ready for input.",
                )

    def switch_session(self, session_index: int):
        self.current_session_index = session_index
        self.refresh_chat_view()

    def refresh_chat_view(self):
        if not self.chat_view:
            return
        session = self.get_current_session()
        self.chat_view.text_log.clear()
        if session:
            for msg in session.messages:
                if msg["role"] == "user":
                    # Ensure that user messages are rendered as strings
                    content = (
                        msg["content"]
                        if isinstance(msg["content"], str)
                        else "\n".join(map(str, msg["content"]))
                    )
                    self.chat_view.write_message("user", content)
                elif msg["role"] == "assistant":
                    for block in msg["content"]:
                        if block["type"] == "text":
                            self.chat_view.write_message("assistant", block["text"])
                        elif block["type"] == "tool_use":
                            self.chat_view.write_message(
                                "assistant",
                                f"[Tool request: {block['name']}] -> {block.get('input','')}",
                            )
                        else:
                            self.chat_view.write_message("assistant", str(block))

    def get_current_session(self) -> Optional[ChatSession]:
        if 0 <= self.current_session_index < len(self.sessions):
            return self.sessions[self.current_session_index]
        return None

    def handle_user_message(self, user_text: str):
        session = self.get_current_session()
        if not session:
            return
        session.append_user_message(user_text)
        self.chat_view.write_message("user", user_text)
        if self._stream_task and not self._stream_task.done():
            self._stream_task.cancel()
        self._stream_task = asyncio.create_task(self.run_anthropic(session))

    async def run_anthropic(self, session: ChatSession):
        if not self.client:
            self.chat_view.write_message(
                "system", "Anthropic client is not initialized."
            )
            return
        messages_payload: List[Dict[str, Any]] = []
        for msg in session.messages:
            if msg["role"] == "user":
                messages_payload.append({"role": "user", "content": msg["content"]})
            elif msg["role"] == "assistant":
                messages_payload.append(
                    {"role": "assistant", "content": msg["content"]}
                )
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
        try:
            self.stop_streaming.clear()
            stream_resp = call_model(
                self.client, SYSTEM_MESSAGE, messages_payload, tools
            )
            async for _ in self.handle_incoming_anthropic_stream(session, stream_resp):
                if self.stop_streaming.is_set():
                    break
        except asyncio.CancelledError:
            self.chat_view.write_message("system", "[Streaming interrupted by user]")
        except anthropic.APIStatusError as e:
            self.chat_view.write_message(
                "system", f"Anthropic error, code={e.status_code}, retrying later..."
            )
        except Exception as e:
            self.chat_view.write_message("system", f"Error calling Anthropic: {e}")

    async def handle_incoming_anthropic_stream(
        self, session: ChatSession, response_stream
    ):
        try:
            assistant_result = await process_assistant_message(response_stream)
            assistant_msg = assistant_result.get("message", {})
            session.append_assistant_message(assistant_msg["content"])
            for block in assistant_msg["content"]:
                if block["type"] == "text":
                    self.chat_view.write_message("assistant", block["text"])
                elif block["type"] == "tool_use":
                    tool_result = run_tool(ToolCall(**block), session.instance)
                    session.messages.append(
                        {
                            "role": "user",
                            "content": [
                                {
                                    "type": "tool_result",
                                    "tool_use_id": block["id"],
                                    "content": json.dumps(tool_result),
                                }
                            ],
                        }
                    )
                    async for _ in self.process_tool_result(session):
                        pass
                else:
                    self.chat_view.write_message(
                        "assistant", f"[Unknown block] {block}"
                    )
            yield assistant_msg
        except asyncio.CancelledError:
            raise

    async def process_tool_result(self, session: ChatSession):
        messages_payload: List[Dict[str, Any]] = []
        for msg in session.messages:
            if msg["role"] == "user":
                messages_payload.append({"role": "user", "content": msg["content"]})
            elif msg["role"] == "assistant":
                messages_payload.append(
                    {"role": "assistant", "content": msg["content"]}
                )
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
        try:
            self.stop_streaming.clear()
            stream_resp = call_model(
                self.client, SYSTEM_MESSAGE, messages_payload, tools
            )
            tool_result_data = await process_assistant_message(stream_resp)
            session.append_assistant_message(tool_result_data["message"]["content"])
            for block in tool_result_data["message"]["content"]:
                if block["type"] == "text":
                    self.chat_view.write_message("assistant", block["text"])
                elif block["type"] == "tool_use":
                    tool_result = run_tool(ToolCall(**block), session.instance)
                    session.messages.append(
                        {
                            "role": "user",
                            "content": [
                                {
                                    "type": "tool_result",
                                    "tool_use_id": block["id"],
                                    "content": json.dumps(tool_result),
                                }
                            ],
                        }
                    )
                    async for _ in self.process_tool_result(session):
                        pass
                else:
                    self.chat_view.write_message("assistant", str(block))
            yield tool_result_data
        except asyncio.CancelledError:
            raise

    def action_handle_ctrl_c(self) -> None:
        if self._stream_task and not self._stream_task.done():
            self._stream_task.cancel()
        self.stop_streaming.set()


# --------------------------------------------------
# Main entry point
# --------------------------------------------------


def run_chat_tui(instance: Any):
    """
    Launch the Textual TUI application.
    """
    app = ChatTUI(instance=instance)

    def handle_signal(sig, frame):
        if sig == signal.SIGINT:
            app.action_handle_ctrl_c()

    signal.signal(signal.SIGINT, handle_signal)
    app.run()


if __name__ == "__main__":
    from morphcloud.api import MorphCloudClient

    inst = MorphCloudClient().instances.get("morphvm_8jlef1uw")
    run_chat_tui(inst)
