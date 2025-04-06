import os
import json
import time
import base64
import asyncio
import argparse
import traceback

from io import BytesIO

import anthropic

from PIL import Image

from morphcloud.api import MorphCloudClient


# Terminal colors for better UX
COLORS = {
    "PRIMARY": "\033[32m",  # Green
    "HIGHLIGHT": "\033[31m",  # Red
    "TEXT": "\033[39m",  # Default text
    "SECONDARY": "\033[90m",  # Gray
    "OUTPUT_HEADER": "\033[34m",  # Blue
    "SUCCESS": "\033[32m",  # Green
    "ERROR": "\033[31m",  # Red
    "RESET": "\033[0m",  # Reset
}


# Tool definitions
class Tool:
    """Base class for tools that can be called by the agent."""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    def run(self, input_text: str) -> str:
        """Execute the tool with the given input."""
        raise NotImplementedError("Subclasses must implement run()")


class BrowserTool(Tool):
    """Tool for browser automation."""

    def __init__(self):
        super().__init__(
            name="browser_tool",
            description="Automates browser interactions using MorphCloud.",
        )
        self.browser = None
        self.is_connected = False

    def set_computer(self, computer):
        """Set the shared computer instance."""
        self.computer = computer

    async def ensure_connected(self):
        """Ensure the browser is connected and ready."""
        if not self.is_connected:
            print(f"[BrowserTool] Not connected, establishing connection...")
            if not self.computer:
                print(f"[BrowserTool] Error: No computer instance set")
                raise ValueError("No computer instance set")

            print(
                f"[BrowserTool] Getting browser interface from computer {self.computer.id}"
            )
            self.browser = self.computer.browser

            # If CDP URL is None, try to expose a web service
            if self.computer.cdp_url is None:
                try:
                    url = self.computer.expose_http_service("web", 8080)
                except Exception as e:
                    pass

            print(f"[BrowserTool] Connecting to browser...")
            try:
                await self.browser.connect(timeout_seconds=60)
                print(f"[BrowserTool] Browser connected successfully")
                self.is_connected = True
            except Exception as e:
                print(f"[BrowserTool] Error connecting to browser: {str(e)}")
                # Connection failed
                raise
        return self.browser

    def run(self, command_json: str) -> str:
        """Execute browser commands."""
        try:
            command_data = json.loads(command_json)
            action = command_data.get("action")
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(
                self._execute_browser_action(action, command_data)
            )
            return result
        except Exception as e:
            return f"Error executing browser command: {str(e)}"

    async def _execute_browser_action(self, action, command_data):
        """Execute browser actions based on command."""
        browser = await self.ensure_connected()

        if action == "goto":
            url = command_data.get("url")
            await browser.goto(url)
            title = await browser.get_title()
            return f"Navigated to {url}. Page title: {title}"

        elif action == "get_title":
            title = await browser.get_title()
            return f"Page title: {title}"

        elif action == "get_url":
            url = await browser.get_url()
            return f"Current URL: {url}"

        elif action == "screenshot":
            # Get screenshot as binary data
            screenshot_bytes = await browser.screenshot()
            # Get image dimensions
            image = Image.open(BytesIO(screenshot_bytes))
            dimensions = f"{image.width}x{image.height}"

            # Show image locally if enabled
            if hasattr(self, "show_images") and self.show_images:
                show_image(base64.b64encode(screenshot_bytes).decode("utf-8"))

            # For direct viewing, create a smaller preview to prevent prompt overflow
            max_size = (400, 300)  # Adjust size as needed
            image_thumb = image.copy()
            image_thumb.thumbnail(max_size, Image.LANCZOS)

            # Save the thumbnail to a buffer and convert to base64
            buffer = BytesIO()
            image_thumb.save(buffer, format="PNG")
            preview_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

            return f"Browser screenshot captured (dimensions: {dimensions})\nResized preview ({image_thumb.width}x{image_thumb.height}): {preview_base64}"

        elif action == "back":
            await browser.back()
            return "Navigated back"

        elif action == "forward":
            await browser.forward()
            return "Navigated forward"

        elif action == "reload":
            await browser.reload()
            return "Page reloaded"

        elif action == "close":
            await browser.close()
            self.is_connected = False
            return "Browser session closed"

        else:
            return f"Unknown browser action: {action}"

    async def cleanup(self):
        """Clean up resources."""
        print(f"[BrowserTool] Cleaning up browser resources...")
        if self.browser and self.is_connected:
            try:
                await self.browser.close()
                print(f"[BrowserTool] Browser connection closed successfully")
            except Exception as e:
                print(f"[BrowserTool] Error closing browser connection: {str(e)}")
            self.is_connected = False


class SandboxTool(Tool):
    """Tool for code execution in a sandbox environment."""

    def __init__(self):
        super().__init__(
            name="sandbox_tool",
            description="Executes code in a secure Jupyter sandbox using MorphCloud.",
        )
        self.sandbox = None
        self.is_connected = False

    def set_computer(self, computer):
        """Set the shared computer instance."""
        self.computer = computer

    async def ensure_connected(self):
        """Ensure the sandbox is connected and ready."""
        if not self.is_connected:
            print(f"[SandboxTool] Not connected, establishing connection...")
            if not self.computer:
                print(f"[SandboxTool] Error: No computer instance set")
                raise ValueError("No computer instance set")

            print(
                f"[SandboxTool] Getting sandbox interface from computer {self.computer.id}"
            )
            self.sandbox = self.computer.sandbox
            print(f"[SandboxTool] Connecting to sandbox...")
            try:
                await self.sandbox.connect(timeout_seconds=60)
                print(f"[SandboxTool] Sandbox connected successfully")
                self.is_connected = True
            except Exception as e:
                print(f"[SandboxTool] Error connecting to sandbox: {str(e)}")
                raise
        return self.sandbox

    def run(self, command_json: str) -> str:
        """Execute sandbox commands."""
        try:
            command_data = json.loads(command_json)
            action = command_data.get("action")
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(
                self._execute_sandbox_action(action, command_data)
            )
            return result
        except Exception as e:
            return f"Error executing sandbox command: {str(e)}"

    async def _execute_sandbox_action(self, action, command_data):
        """Execute sandbox actions based on command."""
        sandbox = await self.ensure_connected()

        if action == "execute_code":
            code = command_data.get("code")
            result = await sandbox.execute_code(code)

            # Format the response
            response = (
                f"Status: {result.get('status')}\nOutput:\n{result.get('output', '')}"
            )

            # Handle images if present
            if "images" in result and result["images"]:
                img_count = len(result["images"])
                response += f"\n\nGenerated {img_count} image(s)"

                # Save images
                os.makedirs("sandbox_output", exist_ok=True)
                for i, img in enumerate(result["images"]):
                    image_data = img.get("data")
                    image_type = img.get("mime_type")

                    if image_data and image_type == "image/png":
                        filename = f"sandbox_output/image_{int(time.time())}_{i}.png"
                        with open(filename, "wb") as f:
                            f.write(base64.b64decode(image_data))
                        response += f"\nSaved image to {filename}"

            return response

        elif action == "create_notebook":
            notebook_name = command_data.get("name")
            notebook = await sandbox.create_notebook(notebook_name)
            return f"Notebook created: {notebook['path']}"

        elif action == "add_cell":
            notebook_path = command_data.get("notebook_path")
            content = command_data.get("content")
            cell_type = command_data.get("cell_type", "code")

            cell = await sandbox.add_cell(
                notebook_path=notebook_path, content=content, cell_type=cell_type
            )

            return f"Cell added to {notebook_path} at index {cell['index']}"

        elif action == "execute_cell":
            notebook_path = command_data.get("notebook_path")
            cell_index = command_data.get("cell_index")

            result = await sandbox.execute_cell(notebook_path, cell_index)
            return f"Cell execution result:\nStatus: {result['status']}\nOutput: {result['output']}"

        elif action == "list_kernels":
            kernels = await sandbox.list_kernels()
            kernel_info = [f"- {k.get('id')} ({k.get('name')})" for k in kernels]
            return f"Available kernels:\n" + "\n".join(kernel_info)

        elif action == "close":
            await sandbox.close()
            self.is_connected = False
            return "Sandbox connection closed"

        else:
            return f"Unknown sandbox action: {action}"

    async def cleanup(self):
        """Clean up resources."""
        print(f"[SandboxTool] Cleaning up sandbox resources...")
        if self.sandbox and self.is_connected:
            try:
                await self.sandbox.close()
                print(f"[SandboxTool] Sandbox closed successfully")
            except Exception as e:
                print(f"[SandboxTool] Error closing sandbox: {str(e)}")
            self.is_connected = False


def show_image(base64_image):
    """
    Display an image from base64 encoded data.

    Args:
        base64_image: Base64 encoded image data
    """
    try:
        image_data = base64.b64decode(base64_image)
        image = Image.open(BytesIO(image_data))
        image.show()
    except Exception as e:
        print(f"Error displaying image: {e}")


class DesktopTool(Tool):
    """Tool for desktop interaction."""

    def __init__(self, show_images=False):
        super().__init__(
            name="desktop_tool",
            description="Interacts with a virtual desktop using MorphCloud.",
        )
        self.is_connected = False
        self.show_images = show_images  # Control whether to display images locally

    def set_computer(self, computer):
        """Set the shared computer instance."""
        self.computer = computer
        self.is_connected = True

    def run(self, command_json: str) -> str:
        """Execute desktop interaction commands."""
        try:
            command_data = json.loads(command_json)
            action = command_data.get("action")
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(
                self._execute_desktop_action(action, command_data)
            )
            return result
        except Exception as e:
            return f"Error executing desktop command: {str(e)}"

    async def _execute_desktop_action(self, action, command_data):
        """Execute desktop interaction actions based on command."""
        if not self.is_connected or not self.computer:
            print(f"[DesktopTool] Error: No computer instance set or not connected")
            raise ValueError("No computer instance set")

        if action == "move_mouse":
            x = command_data.get("x")
            y = command_data.get("y")
            if x is None or y is None:
                raise ValueError("move_mouse action requires both x and y parameters")
            await self.computer.amove_mouse(x, y)
            return f"Moved mouse to position ({x}, {y})"

        elif action == "click":
            x = command_data.get("x")
            y = command_data.get("y")
            if x is None or y is None:
                raise ValueError("click action requires both x and y parameters")
            button = command_data.get("button", "left")
            await self.computer.aclick(x, y, button=button)
            return f"Clicked {button} mouse button at position ({x}, {y})"

        elif action == "type_text":
            text = command_data.get("text")
            await self.computer.atype_text(text)
            return f"Typed text: '{text}'"

        elif action == "key_press":
            keys = command_data.get("keys", [])
            await self.computer.akey_press_special(keys)
            return f"Pressed special keys: {', '.join(keys)}"

        elif action == "scroll":
            x = command_data.get("x")
            y = command_data.get("y")
            if x is None or y is None:
                raise ValueError("scroll action requires both x and y parameters")
            scroll_x = command_data.get("scroll_x", 0)
            scroll_y = command_data.get("scroll_y", 0)
            await self.computer.ascroll(x, y, scroll_x, scroll_y)
            return f"Scrolled at position ({x}, {y}), amounts: horizontal={scroll_x}, vertical={scroll_y}"

        elif action == "wait":
            ms = command_data.get("ms", 1000)
            await self.computer.a_wait(ms)
            return f"Waited for {ms} milliseconds"

        elif action == "screenshot":
            # Get screenshot directly as base64 from the computer
            # Get screenshot directly as binary data
            image_data = await self.computer.ascreenshot()

            # Show image locally if enabled
            if self.show_images:
                show_image(base64.b64encode(image_data).decode("utf-8"))

            # Get image dimensions
            image = Image.open(BytesIO(image_data))
            dimensions = f"{image.width}x{image.height}"

            # Check if we need to save to a file
            filename = command_data.get("filename")
            if filename:
                # If it has a directory component, ensure it exists
                dirname = os.path.dirname(filename)
                if dirname:
                    os.makedirs(dirname, exist_ok=True)

                # Save the screenshot to file
                with open(filename, "wb") as f:
                    f.write(image_data)
                return f"Screenshot captured (dimensions: {dimensions})\nSaved to: {filename}"
            else:
                # For direct viewing without saving, create a smaller preview to prevent prompt overflow
                max_size = (400, 300)  # Adjust size as needed
                image_thumb = image.copy()
                image_thumb.thumbnail(max_size, Image.LANCZOS)

                # Save the thumbnail to a buffer and convert to base64
                buffer = BytesIO()
                image_thumb.save(buffer, format="PNG")
                preview_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

                return f"Screenshot captured (dimensions: {dimensions})\nResized preview ({image_thumb.width}x{image_thumb.height}): {preview_base64}"

        else:
            return f"Unknown desktop action: {action}"

    async def get_desktop_url(self):
        """Get the URL to view the desktop."""
        if not self.computer:
            print(f"[DesktopTool] Error: No computer instance set")
            raise ValueError("No computer instance set")

        print(f"[DesktopTool.get_desktop_url] Checking for existing web service...")
        for service in self.computer.networking.http_services:
            if service.name == "desktop":
                print(
                    f"[DesktopTool.get_desktop_url] Found existing web service: {service.url}"
                )
                return service.url

        return None


class MorphCloudAgent:
    """An agent that can use tools to accomplish tasks."""

    def __init__(self, snapshot_id, show_images=False):
        # Get API key from environment variable
        anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable not set")

        # Verify MorphCloud API key is available
        morph_api_key = os.environ.get("MORPH_API_KEY")
        if not morph_api_key:
            raise ValueError("MORPH_API_KEY environment variable not set")

        # Set up Claude client
        self.client = anthropic.Anthropic(api_key=anthropic_api_key)
        self.model = "claude-3-7-sonnet-latest"  # Can be configured as needed

        # Set up MorphCloud client
        self.morph_client = MorphCloudClient()
        self.snapshot_id = snapshot_id
        self.show_images = show_images

        # Initialize computer instance to None - will be created when needed
        self.computer = None

        # Set up tools
        self.browser_tool = BrowserTool()
        self.sandbox_tool = SandboxTool()
        self.desktop_tool = DesktopTool(show_images=show_images)

        # Store tools in a dictionary
        self.tools = {
            self.browser_tool.name: self.browser_tool,
            self.sandbox_tool.name: self.sandbox_tool,
            self.desktop_tool.name: self.desktop_tool,
        }

        # Initialize empty tool specs - we'll populate from the computer later
        self.tool_specs = []

        # Initialize conversation history
        self.messages = []

        # System prompt with tool descriptions
        self.system_prompt = """You are a helpful AI assistant with access to the following tools:

- browser_tool: Automates browser interactions through MorphCloud with actions like goto, screenshot.
- sandbox_tool: Executes code in a secure Jupyter sandbox through MorphCloud with plotting capabilities.
- desktop_tool: Interacts with a virtual desktop through MorphCloud with mouse/keyboard control.

In addition, you have direct access to individual computer tools:

Browser tools:
- browser_goto: Navigate to a URL directly
- browser_back: Go back in browser history
- browser_forward: Go forward in browser history
- browser_get_title: Get the current page title
- browser_get_url: Get the current page URL
- browser_screenshot: Take a screenshot of the current page and return the image data

Desktop interaction tools:
- click: Click at specified coordinates on the screen
- double_click: Double-click at specified coordinates
- move_mouse: Move the mouse without clicking
- type_text: Type the specified text
- key_press: Press the specified key or key combination
- screenshot: Take a screenshot of the desktop and return the image data
- scroll: Scroll at specified coordinates
- wait: Wait for specified milliseconds

Sandbox code execution tools:
- execute_code: Execute Python code in a sandbox environment
- create_notebook: Create a new Jupyter notebook
- add_cell: Add a cell to a Jupyter notebook
- execute_cell: Execute a specific cell in a Jupyter notebook

When you need to use a tool, use the proper tool call format. Each tool call will be processed before you continue.
If you need to use multiple tools to solve a problem, make one tool call at a time.
Only use tools when necessary. Respond directly to questions that don't require tools.

For browser_tool, use actions like:
- goto: Navigate to a URL
- get_title: Get the page title
- back/forward: Navigate back or forward

For sandbox_tool, use actions like:
- execute_code: Run Python code with full plotting support
- create_notebook: Create a new Jupyter notebook
- add_cell: Add a cell to a notebook
- execute_cell: Execute a cell in a notebook

For desktop_tool, use actions like:
- move_mouse: Move the mouse to x,y coordinates (REQUIRES both x and y parameters)
- click: Click at x,y coordinates (REQUIRES both x and y parameters, don't use move_mouse then click separately)
- type_text: Type text into the desktop (REQUIRES text parameter)
- key_press: Press special keys like ENTER, TAB, etc. (REQUIRES keys parameter)
- scroll: Scroll at x,y coordinates (REQUIRES both x and y parameters, plus scroll_x and/or scroll_y values)
- wait: Wait for specified milliseconds (parameter ms, default 1000)
- screenshot: Take a screenshot of the desktop

IMPORTANT: When taking screenshots with desktop_tool or the screenshot tool:
1. Screenshots always return a Base64 encoded version of the image that you can directly see and analyze
2. Saving to a file is optional - only happens if you provide a filename parameter
3. If you specify a filename with a directory (e.g., "screenshots/google_page.png"), the directory will be created if needed
4. If you don't provide a filename, the screenshot is only available as base64 and not saved to disk

IMPORTANT: Take screenshots frequently using the desktop_tool's screenshot action or the direct screenshot tool to understand the current state of the desktop. 
You should take a screenshot:
1. At the beginning of a task to understand the initial state
2. Before performing key actions like clicks or typing to confirm the correct position
3. After performing actions to verify the result
4. Whenever you're unsure about the current state of the desktop

Screenshots are essential for you to accurately navigate the desktop environment, understand what you're seeing, 
and make precise mouse movements and clicks.

Note: You can use either the combined tools (browser_tool, sandbox_tool, desktop_tool) or the individual tools.
The individual tools come directly from the computer instance and provide more direct access to functionality.

Always use the appropriate tool for the task at hand.
"""

    async def initialize_computer(self):
        """Initialize a single computer instance and connect all tools to it."""
        print(
            f"[MorphCloudAgent] Initializing computer instance with snapshot_id: {self.snapshot_id}"
        )

        # Start the computer
        try:
            computer_api = self.morph_client.computers
            print(f"[MorphCloudAgent] Starting computer...")
            self.computer = await computer_api.astart(self.snapshot_id)
            print(
                f"[MorphCloudAgent] Started computer with id: {self.computer.id}, status: {self.computer.status}"
            )

            # Wait for the computer to be ready
            print(f"[MorphCloudAgent] Waiting for computer to be ready...")
            await self.computer.await_until_ready()
            print(
                f"[MorphCloudAgent] Computer is ready, status: {self.computer.status}"
            )

            # Connect all the tools to this computer
            print(f"[MorphCloudAgent] Connecting tools to computer...")
            self.browser_tool.set_computer(self.computer)
            self.sandbox_tool.set_computer(self.computer)
            self.desktop_tool.set_computer(self.computer)
            print(
                f"[MorphCloudAgent] All tools connected to computer: {self.computer.id}"
            )

            # Update tool specs with computer's available tools
            print(f"[MorphCloudAgent] Getting wrapped tools from computer...")
            # Get the computer's tools in Anthropic format
            self.tool_specs = self.computer.as_anthropic_tools()

            print(
                f"[MorphCloudAgent] Computer tools ready. Total available tools: {len(self.tool_specs)}"
            )

            return self.computer
        except Exception as e:
            print(f"[MorphCloudAgent] Error initializing computer: {str(e)}")
            raise

    def format_tool_call(self, tool_name, tool_input):
        """Format tool call for display."""
        print(
            f"\n{COLORS['OUTPUT_HEADER']}┌──────────────────────────────────────────┐{COLORS['RESET']}"
        )
        print(
            f"{COLORS['OUTPUT_HEADER']}│ EXECUTING TOOL: {tool_name:<24} │{COLORS['RESET']}"
        )
        print(
            f"{COLORS['OUTPUT_HEADER']}└──────────────────────────────────────────┘{COLORS['RESET']}"
        )
        print(f"{COLORS['SECONDARY']}Input:{COLORS['RESET']}")
        print(f"{COLORS['TEXT']}{tool_input}{COLORS['RESET']}")
        print(f"{COLORS['SECONDARY']}{'─' * 50}{COLORS['RESET']}")

    def format_tool_result(self, result, execution_time):
        """Format tool result for display."""
        print(
            f"\n{COLORS['OUTPUT_HEADER']}┌──────────────────────────────────────────┐{COLORS['RESET']}"
        )
        print(
            f"{COLORS['OUTPUT_HEADER']}│ TOOL RESULT ({execution_time:.2f}s)                  │{COLORS['RESET']}"
        )
        print(
            f"{COLORS['OUTPUT_HEADER']}└──────────────────────────────────────────┘{COLORS['RESET']}"
        )
        print(f"{COLORS['TEXT']}{result}{COLORS['RESET']}")
        print(f"{COLORS['SECONDARY']}{'─' * 50}{COLORS['RESET']}")

    def process_message(self, user_input):
        """Process a user message and handle any tool calls from Claude."""
        # Add user message to conversation
        self.messages.append({"role": "user", "content": user_input})

        # Main loop for handling tool calls
        while True:
            # Get Claude's response
            print(f"{COLORS['SECONDARY']}Thinking...{COLORS['RESET']}")

            response = self.client.messages.create(
                model=self.model,
                system=self.system_prompt,
                messages=self.messages,
                tools=self.tool_specs,
                max_tokens=4096,
            )

            # Print Claude's response
            print()

            # Extract and add the assistant's message to conversation
            assistant_msg = {"role": "assistant", "content": response.content}
            self.messages.append(assistant_msg)

            # Print content and check for tool calls
            tool_calls = []

            # Process each content block
            for content in response.content:
                if content.type == "text":
                    print(f"{COLORS['TEXT']}{content.text}{COLORS['RESET']}")
                elif content.type == "tool_use":
                    tool_calls.append(content)

            # If no tool calls, we're done
            if not tool_calls:
                break

            # Handle each tool call
            for tool_call in tool_calls:
                tool_name = tool_call.name

                # Extract the appropriate input parameter based on tool type
                if tool_name in ["browser_tool", "sandbox_tool", "desktop_tool"]:
                    # For complex tools, convert the input to JSON
                    tool_input = json.dumps(dict(tool_call.input), indent=2)
                else:
                    tool_input = str(tool_call.input)

                # Display tool call
                self.format_tool_call(tool_name, tool_input)

                # Make sure we have a computer instance for the tools that need it
                if (
                    tool_name in ["browser_tool", "sandbox_tool", "desktop_tool"]
                    and not self.computer
                ):
                    print(
                        f"{COLORS['SECONDARY']}Initializing computer for {tool_name}...{COLORS['RESET']}"
                    )
                    loop = asyncio.get_event_loop()
                    loop.run_until_complete(self.initialize_computer())

                # Execute the tool
                start_time = time.time()

                # Check if this is one of our wrapped tools or a direct computer tool
                if tool_name in self.tools:
                    # Use our wrapper tools
                    result = self.tools[tool_name].run(tool_input)
                else:
                    # This might be a direct computer tool from as_anthropic_tools
                    # We need to check if it's one of the computer tools
                    print(
                        f"{COLORS['SECONDARY']}Using direct computer tool: {tool_name}{COLORS['RESET']}"
                    )
                    # Most computer tool names follow patterns that we can map
                    # Browser tools: browser_goto, browser_click, etc.
                    if tool_name.startswith("browser_"):
                        browser_method = tool_name.replace("browser_", "")
                        try:
                            # Get the method from the browser object
                            method = getattr(self.computer.browser, browser_method)
                            # Create a coroutine to run it
                            coro = method(**dict(tool_call.input))
                            # Run it in the event loop
                            result = asyncio.get_event_loop().run_until_complete(coro)
                            # Convert to string if needed
                            result = (
                                str(result)
                                if result is not None
                                else "Action completed successfully"
                            )
                        except Exception as e:
                            result = f"Error executing browser method {browser_method}: {str(e)}"
                    # Sandbox tools: execute_code, create_notebook, etc.
                    elif tool_name in [
                        "execute_code",
                        "create_notebook",
                        "add_cell",
                        "execute_cell",
                    ]:
                        sandbox_method = tool_name
                        try:
                            # Get the method from the sandbox object
                            method = getattr(self.computer.sandbox, sandbox_method)
                            # Create a coroutine to run it
                            coro = method(**dict(tool_call.input))
                            # Run it in the event loop
                            result = asyncio.get_event_loop().run_until_complete(coro)
                            # Convert to string for result display
                            result = (
                                json.dumps(result, indent=2)
                                if result is not None
                                else "Action completed successfully"
                            )
                        except Exception as e:
                            result = f"Error executing sandbox method {sandbox_method}: {str(e)}"
                    # Desktop tools: click, move_mouse, type_text, etc.
                    elif tool_name in [
                        "click",
                        "move_mouse",
                        "type_text",
                        "key_press",
                        "double_click",
                        "screenshot",
                        "scroll",
                        "wait",
                    ]:
                        # Most can be called directly on the computer instance
                        try:
                            # Convert to async version of method
                            desktop_method = (
                                "a" + tool_name
                                if hasattr(self.computer, "a" + tool_name)
                                else tool_name
                            )
                            # Get the method
                            method = getattr(self.computer, desktop_method)
                            # Create a coroutine to run it
                            coro = method(**dict(tool_call.input))
                            # Run it in the event loop
                            result = asyncio.get_event_loop().run_until_complete(coro)
                            # For screenshot, we need to handle base64 or file saving
                            if tool_name == "screenshot" and isinstance(result, bytes):
                                # Convert to base64
                                import base64

                                b64data = base64.b64encode(result).decode("utf-8")
                                result = (
                                    f"Screenshot captured (size: {len(result)} bytes)"
                                )
                                # Include the data for viewing
                                if self.show_images:
                                    result += f"\nBase64 data: {b64data[:100]}..."
                            else:
                                result = (
                                    "Action completed successfully"
                                    if result is None
                                    else str(result)
                                )
                        except Exception as e:
                            result = (
                                f"Error executing desktop method {tool_name}: {str(e)}"
                            )
                    else:
                        # For unknown tools, provide an error
                        result = (
                            f"Unknown tool: {tool_name}. This tool is not implemented."
                        )

                execution_time = time.time() - start_time

                # Display tool result
                self.format_tool_result(result, execution_time)

                # Add tool result to conversation
                self.messages.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": tool_call.id,
                                "content": result,
                            }
                        ],
                    }
                )

            print(f"{COLORS['SECONDARY']}Processing results...{COLORS['RESET']}")

    async def cleanup(self):
        """Clean up all resources."""
        print(f"[MorphCloudAgent] Cleaning up resources...")

        # First have each tool clean up its resources
        cleanup_tasks = []
        if self.browser_tool:
            cleanup_tasks.append(self.browser_tool.cleanup())
        if self.sandbox_tool:
            cleanup_tasks.append(self.sandbox_tool.cleanup())

        if cleanup_tasks:
            await asyncio.gather(*cleanup_tasks)

        # Finally stop the computer
        if self.computer:
            print(f"[MorphCloudAgent] Stopping computer with id: {self.computer.id}")
            try:
                await self.computer.astop()
                print(f"[MorphCloudAgent] Computer stopped successfully")
                self.computer = None
            except Exception as e:
                print(f"[MorphCloudAgent] Error stopping computer: {str(e)}")

        print(f"[MorphCloudAgent] All resources cleaned up.")


async def get_desktop_url(agent):
    """Get URL for viewing the desktop using the agent's desktop tool."""
    print(f"[get_desktop_url] Starting with agent's desktop tool")

    if not agent.computer:
        print(f"[get_desktop_url] Initializing computer...")
        await agent.initialize_computer()

    print(f"[get_desktop_url] Getting desktop URL...")
    try:
        url = await agent.desktop_tool.get_desktop_url()
        print(f"[get_desktop_url] Got desktop URL: {url}")
        return url
    except Exception as e:
        print(f"[get_desktop_url] Error getting desktop URL: {str(e)}")
        raise


def main():
    """Run the agent in a conversation loop."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="MorphCloud AI Assistant with Tools")
    parser.add_argument(
        "--snapshot-id",
        default="snapshot_jx0rpqqt",
        help="MorphCloud snapshot ID to use (default: snapshot_jx0rpqqt)",
    )
    parser.add_argument(
        "--show-images",
        action="store_true",
        help="Show screenshots locally using PIL Image.show()",
    )
    parser.add_argument(
        "--initial-instruction",
        type=str,
        help="Initial instruction to give the agent upon startup",
    )
    args = parser.parse_args()

    print(
        f"{COLORS['PRIMARY']}┌───────────────────────────────────────────────┐{COLORS['RESET']}"
    )
    print(
        f"{COLORS['PRIMARY']}│       MorphCloud AI Assistant with Tools      │{COLORS['RESET']}"
    )
    print(
        f"{COLORS['PRIMARY']}└───────────────────────────────────────────────┘{COLORS['RESET']}"
    )
    print(
        f"{COLORS['SECONDARY']}Using snapshot ID: {args.snapshot_id}{COLORS['RESET']}"
    )
    if args.initial_instruction:
        print(
            f"{COLORS['SECONDARY']}Using initial instruction: {args.initial_instruction}{COLORS['RESET']}"
        )

    # Create necessary directories
    os.makedirs("sandbox_output", exist_ok=True)

    try:
        print(f"{COLORS['SECONDARY']}Initializing agent...{COLORS['RESET']}")
        if args.show_images:
            print(
                f"{COLORS['SECONDARY']}Image display is enabled - screenshots will open locally{COLORS['RESET']}"
            )
        agent = MorphCloudAgent(args.snapshot_id, show_images=args.show_images)
        print(f"{COLORS['SECONDARY']}Agent initialized.{COLORS['RESET']}")

        # Set up the event loop
        loop = asyncio.get_event_loop()

        # Initialize the computer instance up front
        print(f"{COLORS['SECONDARY']}Initializing computer...{COLORS['RESET']}")
        loop.run_until_complete(agent.initialize_computer())
        print(f"{COLORS['SECONDARY']}Computer initialized.{COLORS['RESET']}")

        # Get and display desktop URL
        try:
            print(f"{COLORS['SECONDARY']}Getting desktop URL...{COLORS['RESET']}")
            desktop_url = loop.run_until_complete(get_desktop_url(agent))
            print(f"{COLORS['SUCCESS']}Desktop URL: {desktop_url}{COLORS['RESET']}")
            print(
                f"{COLORS['SECONDARY']}You can view the agent's actions in a browser at this URL{COLORS['RESET']}"
            )
        except Exception as e:
            print(
                f"{COLORS['ERROR']}Error getting desktop URL: {str(e)}{COLORS['RESET']}"
            )
            traceback.print_exc()

        print(
            f"{COLORS['SECONDARY']}Type 'exit' or 'quit' to end the conversation{COLORS['RESET']}"
        )
        print(f"{COLORS['SECONDARY']}{'─' * 50}{COLORS['RESET']}")

        # Process initial instruction if provided
        if args.initial_instruction:
            print(
                f"\n{COLORS['HIGHLIGHT']}Initial instruction:{COLORS['RESET']} {args.initial_instruction}"
            )
            try:
                agent.process_message(args.initial_instruction)
                print(f"{COLORS['SECONDARY']}{'─' * 50}{COLORS['RESET']}")
            except Exception as e:
                print(
                    f"{COLORS['ERROR']}Error processing initial instruction: {str(e)}{COLORS['RESET']}"
                )
                traceback.print_exc()
                print(f"{COLORS['SECONDARY']}{'─' * 50}{COLORS['RESET']}")

        # Main conversation loop
        try:
            while True:
                user_input = input(f"\n{COLORS['HIGHLIGHT']}You:{COLORS['RESET']} ")

                if user_input.lower() in ["exit", "quit"]:
                    print(
                        f"\n{COLORS['PRIMARY']}Cleaning up and exiting...{COLORS['RESET']}"
                    )
                    loop.run_until_complete(agent.cleanup())
                    print(f"\n{COLORS['PRIMARY']}Goodbye!{COLORS['RESET']}")
                    break

                try:
                    agent.process_message(user_input)
                    print(f"{COLORS['SECONDARY']}{'─' * 50}{COLORS['RESET']}")
                except Exception as e:
                    print(f"{COLORS['ERROR']}Error: {str(e)}{COLORS['RESET']}")
                    traceback.print_exc()
                    print(f"{COLORS['SECONDARY']}{'─' * 50}{COLORS['RESET']}")
        except KeyboardInterrupt:
            print(f"\n{COLORS['PRIMARY']}Interrupted. Cleaning up...{COLORS['RESET']}")
            loop.run_until_complete(agent.cleanup())
            print(f"\n{COLORS['PRIMARY']}Goodbye!{COLORS['RESET']}")

    except ValueError as e:
        print(f"{COLORS['ERROR']}Initialization error: {e}{COLORS['RESET']}")
        return


if __name__ == "__main__":
    main()
