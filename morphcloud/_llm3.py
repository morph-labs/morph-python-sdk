import copy
import io
import json
import os
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

from anthropic import AsyncAnthropic
from dotenv import load_dotenv
from rich.markdown import Markdown
from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.widgets import Button, Input, Label, Static, Tree

# Load environment variables from .env file
load_dotenv()

# -----------------------------------------------------------------------------
# Configuration and helper functions (chat-loop logic)
# -----------------------------------------------------------------------------

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
MODEL_NAME = "claude-3-5-sonnet-20241022"
MAX_TOKENS = 4096


def add_cache_control_to_last_content(
    messages: List[dict],
    cache_control: dict = {"type": "ephemeral"},
    max_cache_controls: int = 4,
) -> List[dict]:
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


def call_model(
    client: AsyncAnthropic, system: str, messages: List[dict], tools: List[dict]
):
    """
    Call Anthropic’s streaming endpoint (using the AsyncAnthropic client)
    with our system prompt, messages (with cache_control applied), and tool info.
    """
    return client.messages.create(
        model=MODEL_NAME,
        system=system,
        messages=add_cache_control_to_last_content(messages),
        max_tokens=MAX_TOKENS,
        tools=tools,
        stream=True,
        extra_headers={"anthropic-beta": "prompt-caching-2024-07-31"},
    )


async def process_assistant_message(response_stream) -> dict:
    """
    Asynchronously process the streaming response from Anthropic and accumulate
    the assistant’s message.
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
                text_to_append = chunk.delta.text or ""
                content_acc.write(text_to_append)
            elif content_block_type == "tool_use":
                content_acc.write(chunk.delta.partial_json or "")
        elif chunk.type == "content_block_stop":
            flush_content()
            content_block_type = None
    if content_acc.getvalue().strip():
        flush_content()
    return {
        "message": response_msg,
        "tool_use_active": any(
            b["type"] == "tool_use" for b in response_msg["content"]
        ),
    }


# -----------------------------------------------------------------------------
# SSH Execution Helpers
# -----------------------------------------------------------------------------


# (This function uses the MorphVM instance’s ssh interface to run commands.)
def ssh_connect_and_run(instance: any, command: str) -> dict:
    with instance.ssh() as ssh:
        # (This example assumes a blocking SSH command execution with streaming output.
        # In a real implementation, you might stream output back to the UI.)
        last_stdout = ""
        last_stderr = ""
        with ssh.run(command, background=True, get_pty=True) as process:
            while not process.completed:
                # In a TUI you might want to capture partial output;
                # here we simply wait for completion.
                pass
            final_stdout = process.stdout
            final_stderr = process.stderr
            return {
                "exit_code": process.channel.recv_exit_status(),
                "stdout": final_stdout,
                "stderr": final_stderr,
            }


# A pydantic model for tool calls.
from pydantic import BaseModel


class ToolCall(BaseModel):
    name: str
    input: dict


def run_tool(tool_call: ToolCall, instance: any) -> dict:
    if tool_call.name == "run_command":
        cmd = tool_call.input.get("command", "")
        # Run the command via SSH
        result = ssh_connect_and_run(instance, cmd)
        return result
    else:
        return {"error": f"Unknown tool '{tool_call.name}'"}


# -----------------------------------------------------------------------------
# Data classes representing messages and sessions
# -----------------------------------------------------------------------------


@dataclass
class Message:
    content: str
    is_user: bool
    timestamp: datetime = None
    message_type: str = "user"  # "user", "assistant", or "system"

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


@dataclass
class ChatSession:
    id: str
    messages: List[Message]
    created_at: datetime = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()


# -----------------------------------------------------------------------------
# TUI Widgets
# -----------------------------------------------------------------------------


class LoadingIndicator(Static):
    """Widget to show a simple loading animation."""

    DEFAULT_CSS = """
    LoadingIndicator {
        content-align: center middle;
        padding: 1;
        width: 100%;
        color: #dcdccc;
    }
    """

    def __init__(self):
        super().__init__("Loading...")
        self._running = True
        self._dots = 0
        self._timer = None

    def on_mount(self):
        self._timer = self.set_interval(0.5, self._update_dots)

    def stop(self):
        self._running = False
        if self._timer:
            self._timer.stop()

    def _update_dots(self):
        if self._running:
            self._dots = (self._dots + 1) % 4
            self.update(f"Claude is thinking{'.' * self._dots}")


class MessageWidget(Static):
    """Widget to display a single message (rendered as Markdown)."""

    def __init__(self, message: Message):
        super().__init__()
        self.message = message

    def compose(self) -> ComposeResult:
        role_label = "You" if self.message.is_user else "Claude"
        timestamp = self.message.timestamp.strftime("%H:%M")
        yield Label(f"{role_label} - {timestamp}")
        yield Static(Markdown(self.message.content))


class ChatWindow(ScrollableContainer):
    """The main chat display area."""

    def __init__(self, session: Optional[ChatSession] = None, id: Optional[str] = None):
        super().__init__(id=id)
        self.session = session

    def compose(self) -> ComposeResult:
        if self.session:
            for message in self.session.messages:
                yield MessageWidget(message)

    def add_message(self, message: Message):
        if self.session:
            self.session.messages.append(message)
            self.mount(MessageWidget(message))
            self.scroll_end(animate=False)

    def remove_children(self):
        for child in list(self.children):
            child.remove()


# -----------------------------------------------------------------------------
# Main TUI App
# -----------------------------------------------------------------------------


class ChatTUI(App):
    """A TUI chat application that maintains multiple sessions and runs the chat loop in each session."""

    CSS = """
    Horizontal {
        height: 100%;
        background: #3f3f3f;
    }
    #sessions_container {
        width: 30%;
        height: 100%;
        dock: left;
    }
    #sessions_tree {
        width: 100%;
        height: 100%;
        border: solid #6f6f6f;
        background: #2f2f2f;
    }
    #new_chat_button {
        dock: top;
        width: 100%;
        height: 3;
        background: #4f4f4f;
        color: #dcdccc;
        border: solid #6f6f6f;
        margin: 0 0 1 0;
        content-align: center middle;
    }
    #chat_container {
        width: 70%;
        height: 100%;
        dock: right;
        background: #3f3f3f;
    }
    #chat_window {
        height: 90%;
        border: solid #6f6f6f;
        background: #3f3f3f;
    }
    #input_container {
        height: auto;
        dock: bottom;
        border: solid #6f6f6f;
        padding: 1;
        background: #2f2f2f;
    }
    Input {
        width: 100%;
        height: 3;
        border: solid #6f6f6f;
        background: #2f2f2f;
        color: #dcdccc;
        padding: 0 1;
    }
    MessageWidget {
        margin: 1;
        padding: 1;
        background: #2f2f2f;
        color: #dcdccc;
    }
    MessageWidget Static {
        margin: 1 1;
        color: #dcdccc;
    }
    Tree {
        background: #2f2f2f;
        color: #dcdccc;
    }
    """
    BINDINGS = [
        Binding("ctrl+n", "new_chat", "New Chat"),
        Binding("ctrl+q", "quit", "Quit"),
    ]

    def __init__(self, instance=None):
        super().__init__()
        self.sessions: List[ChatSession] = []
        self.current_session: Optional[ChatSession] = None
        # Initialize the AsyncAnthropic client
        self.anthropic = AsyncAnthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
        # Initialize the MorphVM instance.
        # Replace FakeInstance with your actual MorphVM instance (which must implement an ssh() method).
        self.instance = instance or FakeInstance()

    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(id="sessions_container"):
                yield Button("+ New Chat", id="new_chat_button")
                yield Tree("Chat Sessions", id="sessions_tree")
            with Vertical(id="chat_container"):
                yield ChatWindow(id="chat_window")
                with Vertical(id="input_container"):
                    yield Input(
                        placeholder="Type your message here...", id="message_input"
                    )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "new_chat_button":
            self.action_new_chat()

    def on_mount(self) -> None:
        self.action_new_chat()

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        if not event.node.data:
            return
        session = event.node.data.get("session")
        if not session:
            return
        self.current_session = session
        chat_window = self.query_one("#chat_window", ChatWindow)
        chat_window.remove_children()
        chat_window.session = session
        for message in session.messages:
            chat_window.mount(MessageWidget(message))
        chat_window.scroll_end(animate=False)

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if not event.value or not self.current_session:
            return
        input_widget = self.query_one("#message_input", Input)
        message_text = event.value
        input_widget.value = ""
        chat_window = self.query_one("#chat_window", ChatWindow)
        user_message = Message(content=message_text, is_user=True)
        chat_window.add_message(user_message)
        # Run the chat loop for this session and show a loading indicator
        loading = LoadingIndicator()
        chat_window.mount(loading)
        chat_window.scroll_end(animate=False)
        try:
            await self.run_chat_loop(message_text)
        except Exception as e:
            loading.stop()
            await loading.remove()
            error_message = Message(content=f"Error: {str(e)}", is_user=False)
            chat_window.add_message(error_message)
        else:
            loading.stop()
            await loading.remove()

    async def run_chat_loop(self, user_text: str) -> None:
        """
        Build the conversation payload from the current session’s messages,
        call the Anthropic API (streaming mode), process the assistant’s reply,
        and update the session. If tool_use blocks are present, run them via SSH
        against the MorphVM instance and then chain the tool result back into the conversation.
        """
        chat_window = self.query_one("#chat_window", ChatWindow)
        # Build the messages payload from the session's Message objects.
        messages_payload = []
        for msg in self.current_session.messages:
            role = "user" if msg.is_user else "assistant"
            messages_payload.append({"role": role, "content": msg.content})
        # Ensure the latest user message is included.
        if not messages_payload or messages_payload[-1]["role"] != "user":
            messages_payload.append({"role": "user", "content": user_text})
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
        # Loop until no tool_use blocks remain.
        while True:
            response_stream = await call_model(
                self.anthropic, SYSTEM_MESSAGE, messages_payload, tools
            )
            assistant_result = await process_assistant_message(response_stream)
            # Process any tool_use blocks first.
            tool_blocks = [
                block
                for block in assistant_result["message"]["content"]
                if block["type"] == "tool_use"
            ]
            if tool_blocks:
                for block in tool_blocks:
                    # Run the tool using SSH on the MorphVM instance.
                    tool_result = run_tool(ToolCall(**block), self.instance)
                    # Append the tool result as a new user message.
                    tool_result_text = f"Tool result: {json.dumps(tool_result)}"
                    tool_result_message = Message(
                        content=tool_result_text,
                        is_user=True,
                        message_type="tool_result",
                    )
                    self.current_session.messages.append(tool_result_message)
                    chat_window.add_message(tool_result_message)
                # Update the payload with the new tool result messages.
                messages_payload = []
                for msg in self.current_session.messages:
                    role = "user" if msg.is_user else "assistant"
                    messages_payload.append({"role": role, "content": msg.content})
                # Continue the loop to allow the assistant to process the tool results.
                continue
            else:
                # No tool_use blocks—combine text blocks into the assistant reply.
                assistant_text_parts = [
                    block["text"]
                    for block in assistant_result["message"]["content"]
                    if block["type"] == "text"
                ]
                assistant_text = "\n".join(assistant_text_parts)
                assistant_message = Message(content=assistant_text, is_user=False)
                self.current_session.messages.append(assistant_message)
                chat_window.add_message(assistant_message)
                break

    def action_new_chat(self) -> None:
        session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        new_session = ChatSession(id=session_id, messages=[])
        self.sessions.append(new_session)
        sidebar = self.query_one("#sessions_tree", Tree)
        session_node = sidebar.root.add(
            new_session.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            data={"session": new_session},
        )
        self.current_session = new_session
        chat_window = self.query_one("#chat_window", ChatWindow)
        chat_window.remove_children()
        chat_window.session = new_session
        sidebar.select_node(session_node)


# -----------------------------------------------------------------------------
# MorphVM Instance Implementation (replace with your real instance)
# -----------------------------------------------------------------------------


class FakeInstance:
    """
    A fake SSH-enabled instance.
    Replace this class with your actual MorphVM instance implementation,
    which must implement an ssh() method returning a context manager whose
    run() method can execute a command.
    """

    def ssh(self):
        class FakeSSH:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def run(self, cmd, background=True, get_pty=True):
                class FakeProcess:
                    stdout = f"Simulated output for: {cmd}"
                    stderr = ""
                    completed = True

                    def __init__(self):
                        self.channel = self

                    def recv_exit_status(self):
                        return 0

                return FakeProcess()

        return FakeSSH()


# -----------------------------------------------------------------------------
# Main entry point
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    from morphcloud.api import MorphCloudClient

    instance = MorphCloudClient().instances.get("morphvm_8jlef1uw")
    app = ChatTUI(instance=instance)
    app.run()
