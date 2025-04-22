from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
import subprocess
import time
import typing
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

import requests
import websocket
from playwright.sync_api import sync_playwright

from morphcloud.api import Instance, InstanceAPI, MorphCloudClient, Snapshot

_websockets_available = importlib.util.find_spec("websockets") is not None
_jupyter_client_available = importlib.util.find_spec("jupyter_client") is not None

_playwright_available = importlib.util.find_spec("playwright") is not None

# Optional: key mapping if your model uses "CUA" style keys
CUA_KEY_TO_PLAYWRIGHT_KEY = {
    "/": "Divide",
    "\\": "Backslash",
    "alt": "Alt",
    "arrowdown": "ArrowDown",
    "arrowleft": "ArrowLeft",
    "arrowright": "ArrowRight",
    "arrowup": "ArrowUp",
    "backspace": "Backspace",
    "capslock": "CapsLock",
    "cmd": "Meta",
    "ctrl": "Control",
    "delete": "Delete",
    "end": "End",
    "enter": "Enter",
    "esc": "Escape",
    "home": "Home",
    "insert": "Insert",
    "option": "Alt",
    "pagedown": "PageDown",
    "pageup": "PageUp",
    "shift": "Shift",
    "space": " ",
    "super": "Meta",
    "tab": "Tab",
    "win": "Meta",
}


class Browser:
    """
    A 'safe' Browser class that:
     - Uses the sync Playwright API
     - Offloads calls to a dedicated ThreadPoolExecutor so it never blocks
       or interferes with any asyncio loop your environment might have.
     - All public methods remain synchronous – the call blocks until the
       background thread finishes the Playwright operation.
    """

    def __init__(self, computer):
        self._computer = computer
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None
        self._connected = False

        self._timeout = 30
        self.wait_until = None

        # A dedicated, single-thread executor for all browser actions
        self._executor = ThreadPoolExecutor(max_workers=1)

    # ----------------------------------------------------------------
    # Internals: actual sync Playwright calls to run in the background
    # ----------------------------------------------------------------

    def _sync_connect(self, cdp_url: str):
        if self._connected:
            return
        with sync_playwright() as p:
            # We do want to keep the playwright instance around, so store it
            # IMPORTANT: you can't do 'with sync_playwright()' once and store it
            # if you plan on calling _sync_connect more than once. But typically
            # you only connect once. So either:
            #
            # 1) Keep the 'with' block at the class level (you'll close on .close())
            #    Or:
            # 2) Re-init playwright each time.
            #
            # For a single connect, let's do the approach below:
            self._playwright = p
            ws_url = self._get_browser_ws_endpoint(cdp_url)
            self._browser = p.chromium.connect_over_cdp(ws_url)
            self._context = self._browser.new_context()
            self._page = self._context.new_page()
            self._connected = True
            # Do not exit the 'with' block here or p.stop() is called automatically
            # We want to keep it alive for subsequent calls.
            # So we must manually remove the 'with' and do p.stop() in ._sync_close

    def _sync_close(self):
        # If we got here, we need to be sure to do .stop() on the original `Playwright` object
        # But the code above used `with sync_playwright() as p:`.
        # That means p.stop() is called automatically on exit of that 'with' block –
        # so we either need to restructure the code or re-init sync_playwright.
        #
        # Easiest fix: DO NOT use 'with sync_playwright() as p:' for connect.
        # Instead, call sync_playwright().start() once, store in self._playwright,
        # call .stop() here. Let's do that:
        if not self._connected:
            return
        if self._context:
            self._context.close()
        if self._browser:
            self._browser.close()
        if self._playwright:
            self._playwright.stop()

        self._connected = False
        self._browser = None
        self._context = None
        self._page = None
        self._playwright = None

    def _sync_goto(self, url: str):
        if not self._connected or not self._page:
            raise RuntimeError("Browser not connected.")
        self._page.goto(url)
        time.sleep(1)  # small wait for stability

    def _sync_back(self):
        if not self._connected or not self._page:
            raise RuntimeError("Browser not connected.")
        self._page.go_back()

    def _sync_forward(self):
        if not self._connected or not self._page:
            raise RuntimeError("Browser not connected.")
        self._page.go_forward()

    def _sync_screenshot(self) -> str:
        if not self._connected or not self._page:
            raise RuntimeError("Browser not connected.")
        png_bytes = self._page.screenshot(full_page=False)
        return base64.b64encode(png_bytes).decode("utf-8")

    def _sync_click(self, x: int, y: int, button: str):
        if not self._connected or not self._page:
            raise RuntimeError("Browser not connected.")
        # handle "back"/"forward" as you do
        if button == "back":
            self._sync_back()
        elif button == "forward":
            self._sync_forward()
        elif button == "wheel":
            self._page.mouse.wheel(x, y)
        else:
            btn_type = "left" if button == "left" else "right"
            self._page.mouse.click(x, y, button=btn_type)

    def _sync_double_click(self, x: int, y: int):
        if not self._connected or not self._page:
            raise RuntimeError("Browser not connected.")
        self._page.mouse.dblclick(x, y)

    def _sync_scroll(self, x: int, y: int, scroll_x: int, scroll_y: int):
        if not self._connected or not self._page:
            raise RuntimeError("Browser not connected.")
        self._page.mouse.move(x, y)
        self._page.evaluate(f"window.scrollBy({scroll_x}, {scroll_y})")

    def _sync_type_text(self, text: str):
        if not self._connected or not self._page:
            raise RuntimeError("Browser not connected.")
        self._page.keyboard.type(text)

    def _sync_wait(self, ms: int):
        time.sleep(ms / 1000.0)

    def _sync_move(self, x: int, y: int):
        if not self._connected or not self._page:
            raise RuntimeError("Browser not connected.")
        self._page.mouse.move(x, y)

    def _sync_keypress(self, keys: List[str]):
        if not self._connected or not self._page:
            raise RuntimeError("Browser not connected.")
        mapped = [CUA_KEY_TO_PLAYWRIGHT_KEY.get(k.lower(), k) for k in keys]
        for key in mapped:
            self._page.keyboard.down(key)
        for key in reversed(mapped):
            self._page.keyboard.up(key)

    def _sync_drag(self, path: List[Dict[str, int]]):
        if not self._connected or not self._page:
            raise RuntimeError("Browser not connected.")
        if not path:
            return
        self._page.mouse.move(path[0]["x"], path[0]["y"])
        self._page.mouse.down()
        for point in path[1:]:
            self._page.mouse.move(point["x"], point["y"])
        self._page.mouse.up()

    def _sync_get_title(self) -> str:
        if not self._connected or not self._page:
            raise RuntimeError("Browser not connected.")
        return self._page.title()

    def _sync_get_current_url(self) -> str:
        if not self._connected or not self._page:
            raise RuntimeError("Browser not connected.")
        return self._page.url

    def _sync_get_html(self) -> str:
        """
        Get the HTML DOM content of the current page.

        Returns:
            The HTML content of the current page as a string.

        Raises:
            RuntimeError: If the browser is not connected.
        """
        if not self._connected or not self._page:
            raise RuntimeError("Browser not connected.")

        # Get the full HTML content of the page
        html_content = self._page.content()
        return html_content

    @property
    def cdp_url(self):
        return self._computer.cdp_url

    # ----------------------------------------------------------------
    # Public methods: synchronous, but run in the thread pool
    # ----------------------------------------------------------------

    def connect(self) -> "Browser":
        """
        Connect to the remote CDP browser. Blocks until connected.
        """
        if self._connected:
            return self
        cdp_url = self._computer.cdp_url
        if not cdp_url:
            raise RuntimeError("No CDP URL found. Is the browser service running?")

        # The .submit(...) call schedules self._sync_connect in the background
        future = self._executor.submit(self._sync_connect_no_with, cdp_url)
        future.result()  # block until it completes or raises
        return self

    def _sync_connect_no_with(self, cdp_url: str):
        """
        Variation that doesn't use 'with sync_playwright()' block,
        so we can close it properly later in _sync_close.
        """
        if self._connected:
            return
        self._playwright = sync_playwright().start()
        # No need to convert to WebSocket URL anymore
        ws_url = cdp_url  # Already the WebSocket URL
        self._browser = self._playwright.chromium.connect_over_cdp(ws_url)
        self._context = self._browser.new_context()
        self._page = self._context.new_page()
        self._connected = True

    def close(self) -> None:
        # Just schedule the sync close in the same thread pool
        future = self._executor.submit(self._sync_close)
        future.result()

    def goto(self, url: str):
        if not self._connected:
            self.connect()
        future = self._executor.submit(self._sync_goto, url)
        return future.result()

    def back(self):
        future = self._executor.submit(self._sync_back)
        return future.result()

    def forward(self):
        future = self._executor.submit(self._sync_forward)
        return future.result()

    def screenshot(self) -> str:
        future = self._executor.submit(self._sync_screenshot)
        return future.result()

    def click(self, x: int, y: int, button: str = "left") -> None:
        future = self._executor.submit(self._sync_click, x, y, button)
        return future.result()

    def double_click(self, x: int, y: int) -> None:
        future = self._executor.submit(self._sync_double_click, x, y)
        return future.result()

    def scroll(self, x: int, y: int, scroll_x: int, scroll_y: int) -> None:
        future = self._executor.submit(self._sync_scroll, x, y, scroll_x, scroll_y)
        return future.result()

    def type(self, text: str) -> None:
        future = self._executor.submit(self._sync_type_text, text)
        return future.result()

    def wait(self, ms: int = 1000) -> None:
        future = self._executor.submit(self._sync_wait, ms)
        return future.result()

    def move(self, x: int, y: int) -> None:
        future = self._executor.submit(self._sync_move, x, y)
        return future.result()

    def keypress(self, keys: List[str]) -> None:
        future = self._executor.submit(self._sync_keypress, keys)
        return future.result()

    def drag(self, path: List[Dict[str, int]]) -> None:
        future = self._executor.submit(self._sync_drag, path)
        return future.result()

    def get_title(self) -> str:
        future = self._executor.submit(self._sync_get_title)
        return future.result()

    def get_current_url(self) -> str:
        future = self._executor.submit(self._sync_get_current_url)
        return future.result()

    def get_html(self) -> str:
        """
        Get the HTML DOM content of the current page.

        This method returns the complete HTML content of the currently loaded page.
        You can use this content for parsing, analysis, or extracting specific elements.

        Returns:
            The HTML content of the current page as a string.

        Raises:
            RuntimeError: If the browser is not connected.
        """
        future = self._executor.submit(self._sync_get_html)
        return future.result()


class Sandbox:
    """
    Code execution sandbox interface for Computer using Jupyter kernels.

    This class provides methods to execute Python code in a secure sandbox environment,
    manage Jupyter notebooks, create and execute notebook cells, and handle kernel
    lifecycle. It uses Jupyter kernels to run code securely and capture outputs including
    text and images.
    """

    def __init__(self, computer: Computer):
        self._computer = computer
        self._jupyter_url = None
        self._ws = None
        self._kernel_id = None
        self._ws_connected = False
        self._session_id = str(uuid.uuid4())

    def _check_dependencies(self) -> None:
        """
        Check if required dependencies are installed.

        Raises:
            ImportError: If any required package is missing
        """
        missing = []
        if not _jupyter_client_available:
            missing.append("jupyter_client")

        if missing:
            raise ImportError(
                f"The following packages are required for sandbox code execution: {', '.join(missing)}. "
                f"Install them with: pip install {' '.join(missing)}"
            )

    def _ensure_kernel_connection(self) -> None:
        """
        Ensure we have an active kernel connection.

        Connects to a kernel if not already connected.

        Raises:
            Various exceptions from connect() method
        """
        if not self._ws_connected:
            self.connect()

    def connect(
        self, timeout_seconds: int = 30, kernel_id: Optional[str] = None
    ) -> "Sandbox":
        """
        Connect to a Jupyter kernel.

        Args:
            timeout_seconds: Maximum time to wait for service in seconds
            kernel_id: Optional ID of existing kernel to connect to. If not provided, a new kernel will be started

        Returns:
            The Sandbox instance for method chaining

        Raises:
            ImportError: If required dependencies are not installed
            TimeoutError: If Jupyter service doesn't start within timeout
            websocket.WebSocketException: If WebSocket connection fails
        """
        self._check_dependencies()

        # Wait for Jupyter service to be ready
        self.wait_for_service(timeout_seconds)

        # Use existing kernel_id if provided, otherwise start a new kernel
        if kernel_id:
            self._kernel_id = kernel_id
        elif not self._kernel_id:
            self.start_kernel()

        # Connect to the WebSocket
        ws_url = self.jupyter_url.replace("https://", "wss://").replace(
            "http://", "ws://"
        )
        ws_endpoint = f"{ws_url}/api/kernels/{self._kernel_id}/channels"

        # Close existing connection if any
        if self._ws:
            try:
                self._ws.close()
            except Exception as e:
                print(f"Error closing WebSocket connection: {str(e)}")
            finally:
                self._ws = None
                self._ws_connected = False

        # Connect to kernel WebSocket
        self._ws = websocket.create_connection(ws_endpoint)
        self._ws_connected = True

        return self

    def close(self) -> None:
        """
        Close the kernel WebSocket connection.

        This method should be called when done using the sandbox to free resources.
        Any errors during closing are logged but don't prevent cleanup.
        """
        if self._ws:
            try:
                self._ws.close()
            except Exception as e:
                # Log the error but continue with cleanup
                print(f"Error closing WebSocket connection: {str(e)}")
            finally:
                self._ws = None
                self._ws_connected = False

    def __enter__(self) -> "Sandbox":
        """
        Enter context manager.

        Returns:
            The Sandbox instance
        """
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """
        Exit context manager and close connections.
        """
        _ = exc_type, exc_val, exc_tb  # Unused
        self.close()

    @property
    def jupyter_url(self) -> str:
        """
        Get the Jupyter server URL.

        This property looks for a JupyterLab service in the computer's HTTP services,
        either by name ("jupyterlab") or by port (8888). If none is found, it will
        expose the service automatically.

        Returns:
            URL string to the Jupyter server

        Note:
            The port 8888 is the default Jupyter server port
        """
        if not self._jupyter_url:
            # Find JupyterLab in exposed services or expose it
            for service in self._computer._instance.networking.http_services:
                if service.port == 8888 or service.name == "jupyterlab":
                    self._jupyter_url = service.url
                    break

            # If not found, expose it
            if not self._jupyter_url:
                self._jupyter_url = self._computer._instance.expose_http_service(
                    "jupyterlab", 8888
                )

        return self._jupyter_url

    def wait_for_service(self, timeout: int = 30) -> bool:
        """
        Wait for Jupyter service to be ready.

        Args:
            timeout: Maximum time to wait in seconds

        Returns:
            True if service is ready

        Raises:
            TimeoutError: If service does not become ready within timeout
            ImportError: If required dependencies are not installed
        """
        self._check_dependencies()
        import requests

        start_time = time.time()
        errors = []

        while time.time() - start_time < timeout:
            try:
                response = requests.get(f"{self.jupyter_url}/api/status", timeout=5.0)
                if response.status_code == 200:
                    return True
            except Exception as e:
                # Store error but continue trying
                errors.append(f"Error connecting to Jupyter service: {str(e)}")
            time.sleep(2)

        error_detail = (
            "; ".join(errors[-3:]) if errors else "No specific errors recorded"
        )
        raise TimeoutError(
            f"Jupyter service failed to start within {timeout} seconds. Errors: {error_detail}"
        )

    def list_kernels(self) -> List[Dict[str, Any]]:
        """
        List available kernels.

        Returns:
            List of kernel dictionaries with metadata

        Raises:
            ImportError: If required dependencies are not installed
            requests.RequestException: If API request fails
        """
        self._check_dependencies()
        import requests

        response = requests.get(f"{self.jupyter_url}/api/kernels")
        response.raise_for_status()
        return response.json()

    def start_kernel(self, kernel_name: str = "python3") -> Dict[str, Any]:
        """
        Start a new kernel with the given name.

        Args:
            kernel_name: The name of the kernel to start (default: python3)

        Returns:
            Dictionary with kernel information including ID

        Raises:
            ImportError: If required dependencies are not installed
            requests.RequestException: If API request fails
        """
        self._check_dependencies()
        import requests

        response = requests.post(
            f"{self.jupyter_url}/api/kernels", json={"name": kernel_name}
        )
        response.raise_for_status()
        kernel_info = response.json()
        self._kernel_id = kernel_info["id"]
        return kernel_info

    def execute_code(self, code: str, timeout: int = 30) -> Dict[str, Any]:
        """
        Execute Python code in a Jupyter kernel and return the result.

        Args:
            code: Python code to execute
            timeout: Maximum time to wait for execution in seconds

        Returns:
            Dictionary containing execution results with keys:
            - status: 'ok' or 'error'
            - output: Text output
            - images: List of images (if any)
            - execution_count: Cell execution number
            - kernel_id: ID of the kernel used for execution
        """
        self._ensure_kernel_connection()
        assert self._ws, "WebSocket connection is not established"

        # Prepare message
        msg_id = str(uuid.uuid4())
        msg = {
            "header": {
                "msg_id": msg_id,
                "username": "kernel",
                "session": self._session_id,
                "msg_type": "execute_request",
                "version": "5.0",
                "date": datetime.now().isoformat(),
            },
            "parent_header": {},
            "metadata": {},
            "content": {
                "code": code,
                "silent": False,
                "store_history": True,
                "user_expressions": {},
                "allow_stdin": False,
                "stop_on_error": True,
            },
            "channel": "shell",
        }

        # Convert datetime to string for JSON serialization
        class DateTimeEncoder(json.JSONEncoder):
            def default(self, o):
                if isinstance(o, datetime):
                    return o.isoformat()
                return json.JSONEncoder.default(self, o)

        self._ws.send(json.dumps(msg, cls=DateTimeEncoder))

        # Process messages
        outputs = []
        images = []
        status = "ok"
        execution_count = None

        # Track message types we've received
        got_execute_input = False
        got_output = False
        got_status_idle = False

        start_time = time.time()

        # Setting timeout for WebSocket operations
        original_timeout = self._ws.gettimeout()
        self._ws.settimeout(5.0)  # 5 second timeout for recv operations

        try:
            while time.time() - start_time < timeout:
                try:
                    response = self._ws.recv()

                    try:
                        response_data = json.loads(response)
                    except json.JSONDecodeError as json_err:
                        print(f"Failed to parse WebSocket message: {str(json_err)}")
                        continue

                    parent_msg_id = response_data.get("parent_header", {}).get("msg_id")
                    msg_type = response_data.get("header", {}).get("msg_type")

                    # Only process messages related to our request
                    if parent_msg_id != msg_id:
                        continue

                    if msg_type == "execute_input":
                        got_execute_input = True
                        execution_count = response_data.get("content", {}).get(
                            "execution_count"
                        )

                    elif msg_type == "stream":
                        got_output = True
                        text = response_data.get("content", {}).get("text", "")
                        outputs.append(text)

                    elif msg_type == "execute_result":
                        got_output = True
                        data = response_data.get("content", {}).get("data", {})
                        text = data.get("text/plain", "")
                        outputs.append(text)

                        # Check for image data
                        for mime_type in ["image/png", "image/jpeg", "image/svg+xml"]:
                            if mime_type in data:
                                images.append(
                                    {"mime_type": mime_type, "data": data[mime_type]}
                                )

                    elif msg_type == "display_data":
                        got_output = True
                        data = response_data.get("content", {}).get("data", {})
                        text = data.get("text/plain", "")
                        outputs.append(text)

                        # Check for image data
                        for mime_type in ["image/png", "image/jpeg", "image/svg+xml"]:
                            if mime_type in data:
                                images.append(
                                    {"mime_type": mime_type, "data": data[mime_type]}
                                )

                    elif msg_type == "error":
                        got_output = True
                        status = "error"
                        traceback = response_data.get("content", {}).get(
                            "traceback", []
                        )
                        outputs.extend(traceback)

                    elif msg_type == "status":
                        if (
                            response_data.get("content", {}).get("execution_state")
                            == "idle"
                        ):
                            got_status_idle = True

                    # Break if we have both the idle status and either input or output
                    if got_status_idle and (got_output or got_execute_input):
                        # Add a small delay to ensure we've gotten all messages
                        time.sleep(0.1)
                        break

                except websocket.WebSocketTimeoutException:
                    # If we've seen idle but no output, we might be done (empty execution)
                    if got_status_idle and got_execute_input:
                        break
                    continue
                except Exception as e:
                    outputs.append(f"Error processing message: {str(e)}")
                    status = "error"
                    break
        finally:
            # Restore original timeout
            if original_timeout is not None:
                self._ws.settimeout(original_timeout)

        # Create result
        result = {
            "status": status,
            "execution_count": execution_count,
            "output": "\n".join(outputs).strip(),
            "kernel_id": self._kernel_id,
        }

        if images:
            result["images"] = images

        return result

    def create_notebook(self, name: str) -> Dict[str, Any]:
        """
        Create a new notebook.

        Args:
            name: Name of the notebook (with or without .ipynb extension)

        Returns:
            Notebook metadata dictionary

        Raises:
            ImportError: If required dependencies are not installed
            requests.RequestException: If API request fails
        """
        self._check_dependencies()
        import requests

        # Ensure notebook name has .ipynb extension
        if not name.endswith(".ipynb"):
            name = f"{name}.ipynb"

        # Minimal notebook format
        notebook = {
            "metadata": {
                "kernelspec": {
                    "name": "python3",
                    "display_name": "Python 3",
                    "language": "python",
                }
            },
            "nbformat": 4,
            "nbformat_minor": 5,
            "cells": [],
        }

        response = requests.put(
            f"{self.jupyter_url}/api/contents/{name}",
            json={"type": "notebook", "content": notebook},
        )
        response.raise_for_status()
        return response.json()

    def add_cell(
        self, notebook_path: str, content: str, cell_type: str = "code"
    ) -> Dict[str, Any]:
        """
        Add a cell to a notebook.

        Args:
            notebook_path: Path to the notebook
            content: Cell content
            cell_type: Cell type ("code", "markdown", or "raw")

        Returns:
            Dictionary with cell index and cell data

        Raises:
            ImportError: If required dependencies are not installed
            requests.RequestException: If API request fails
            ValueError: If cell_type is invalid
        """
        self._check_dependencies()
        import requests

        # Ensure notebook path has .ipynb extension
        if not notebook_path.endswith(".ipynb"):
            notebook_path = f"{notebook_path}.ipynb"

        # Get current notebook
        response = requests.get(
            f"{self.jupyter_url}/api/contents/{notebook_path}",
        )
        response.raise_for_status()
        notebook_data = response.json()
        notebook = notebook_data["content"]

        # Create new cell
        new_cell = {"cell_type": cell_type, "metadata": {}, "source": content}

        if cell_type == "code":
            new_cell["execution_count"] = None
            new_cell["outputs"] = []

        # Append cell
        notebook["cells"].append(new_cell)
        cell_index = len(notebook["cells"]) - 1

        # Save notebook
        response = requests.put(
            f"{self.jupyter_url}/api/contents/{notebook_path}",
            json={"type": "notebook", "content": notebook},
        )
        response.raise_for_status()

        return {"index": cell_index, "cell": new_cell}

    def execute_cell(self, notebook_path: str, cell_index: int) -> Dict[str, Any]:
        """
        Execute a specific cell in a notebook.

        Args:
            notebook_path: Path to the notebook
            cell_index: Index of the cell to execute

        Returns:
            Dictionary containing execution results (same format as execute_code)

        Raises:
            ImportError: If required dependencies are not installed
            requests.RequestException: If API request fails
            ValueError: If cell_index is out of range or cell is not a code cell
        """
        self._check_dependencies()
        import requests

        # Get the notebook
        response = requests.get(
            f"{self.jupyter_url}/api/contents/{notebook_path}",
        )
        response.raise_for_status()
        notebook_data = response.json()
        cells = notebook_data["content"]["cells"]

        if cell_index >= len(cells):
            raise ValueError(f"Cell index {cell_index} out of range")

        cell = cells[cell_index]
        if cell["cell_type"] != "code":
            raise ValueError(f"Cell {cell_index} is not a code cell")

        # Execute the cell's code
        code = cell["source"]
        return self.execute_code(code)


class Computer:
    """
    A Computer is an enhanced Instance with additional capabilities
    like VNC interaction, browser automation, and code execution.
    """

    def __init__(self, instance: Instance):
        self._instance = instance

    def _set_api(self, api: InstanceAPI) -> Computer:
        """Override _set_api to return a Computer instead of an Instance."""
        self._instance._set_api(api)  # Set the API for the instance

        # Initialize computer-specific components
        self._browser = Browser(self)
        self._sandbox = Sandbox(self)
        # Set default display - the _display attribute is managed through the display property
        self._display = ":1"
        return self

    def _refresh(self) -> None:
        # Store computer-specific attributes to restore after refresh
        browser = getattr(self, "_browser", None)
        sandbox = getattr(self, "_sandbox", None)
        display = getattr(self, "_display", ":1")

        # Refresh using parent method
        self._instance._refresh()

        # Restore computer-specific attributes
        if browser:
            self._browser = browser
        if sandbox:
            self._sandbox = sandbox
        # Restore the display value
        self._display = display

    @property
    def environment(self) -> str:
        """Get the environment type (linux, mac, windows, browser)."""
        # This implementation assumes Linux environment
        # Could be expanded to detect other environments
        return "linux"

    @property
    def dimensions(self) -> tuple[int, int]:
        """Get the screen dimensions (width, height)."""
        # Get screen dimensions using xdpyinfo
        result = self._instance.exec(
            "sudo -u morph bash -c 'DISPLAY={0} xdpyinfo | grep dimensions'".format(
                self.display
            )
        )
        # Parse the dimensions from output like "dimensions:    1920x1080 pixels (508x285 millimeters)"
        dimensions_str = result.stdout.strip()
        if "dimensions:" in dimensions_str:
            # Extract the resolution part like "1920x1080"
            resolution = dimensions_str.split("dimensions:")[1].strip().split()[0]
            width, height = map(int, resolution.split("x"))
            return (width, height)
        # Return a default if unable to detect
        return (1024, 768)

    @property
    def browser(self) -> Browser:
        """
        Access the browser automation interface.

        This property provides access to the Browser object, creating it if
        necessary. The Browser object manages connections to the Chrome browser
        instance and provides methods for browser automation.

        Returns:
            The Browser instance associated with this Computer
        """
        if not hasattr(self, "_browser"):
            self._browser = Browser(self)
        return self._browser

    @property
    def sandbox(self) -> Sandbox:
        """
        Access the code execution sandbox.

        This property provides access to the Sandbox object, creating it if
        necessary. The Sandbox object allows for executing Python code in a
        secure environment using Jupyter kernels.

        Returns:
            The Sandbox instance associated with this Computer
        """
        if not hasattr(self, "_sandbox"):
            self._sandbox = Sandbox(self)
        return self._sandbox

    @property
    def cdp_url(self) -> Optional[str]:
        """
        Get the Chrome DevTools Protocol WebSocket URL for this computer.

        Returns:
            WebSocket URL string to connect to CDP, or None if not found
        """
        self._instance.wait_until_ready()
        for service in self._instance.networking.http_services:
            if service.name == "web":
                http_url = service.url
                # Get the WebSocket URL directly
                try:
                    return self._get_browser_ws_endpoint(http_url)
                except Exception as e:
                    print(f"Failed to get WebSocket URL: {str(e)}")
                    return None
        # No CDP service found
        return None

    def _get_browser_ws_endpoint(self, cdp_url: str, timeout_seconds: int = 15) -> str:
        """
        Get the WebSocket debugger URL from the CDP HTTP endpoint.
        """
        cdp_url = cdp_url.rstrip("/")
        json_version_url = f"{cdp_url}/json/version"
        start_time = time.time()
        base_delay = 0.5
        errors = []
        retry_count = 0

        while time.time() - start_time < timeout_seconds:
            retry_count += 1
            delay = min(base_delay * retry_count, 2.0)
            try:
                resp = requests.get(json_version_url, timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    ws_url = data.get("webSocketDebuggerUrl")
                    if ws_url:
                        return ws_url
            except Exception as e:
                errors.append(str(e))
            time.sleep(delay)

        err_msg = "; ".join(errors[-3:]) if errors else "No specific errors"
        raise TimeoutError(f"Failed to get WebSocketDebuggerUrl: {err_msg}")

    @property
    def display(self) -> str:
        """
        Get the X display identifier being used by this Computer.

        This property returns the X11 display identifier (e.g., ":1") that is used
        for X11-based GUI operations like taking screenshots and simulating user input.

        In Linux systems, the X display is where graphical applications render their output.
        The default display ":1" is typically used for the primary screen in virtual environments.

        This display value is used in all VNC interaction methods such as:
        - screenshot()
        - click()
        - type_text()
        - key_press()

        Returns:
            String identifier of the X display (e.g., ":1")

        See Also:
            set_display: Method to change the display identifier
        """
        return getattr(self, "_display", ":1")

    def set_display(self, display_id: str) -> None:
        """
        Set the X display identifier to use for this Computer.

        Use this method if you need to change which X display is targeted for GUI operations.
        In most cases, the default display ":1" is appropriate.

        Example:
            computer.set_display(":2")  # Set to use the secondary display

        Args:
            display_id: The X11 display identifier to use (e.g., ":1", ":2")
        """
        self._display = display_id

    # VNC interaction methods
    def click(self, x: int, y: int, button: str = "left") -> None:
        """
        Click at the specified coordinates on the screen.

        Args:
            x: X coordinate
            y: Y coordinate
            button: Mouse button ("left", "middle", or "right")

        Returns:
            None

        Raises:
            Exception: If the click operation fails
        """
        try:
            button_map = {"left": 1, "middle": 2, "right": 3}
            b = button_map.get(button, 1)
            self._instance.exec(
                f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool mousemove {x} {y} click {b}'"
            )
        except Exception as e:
            raise Exception(
                f"Failed to click at coordinates ({x}, {y}): {str(e)}"
            ) from e

    def double_click(self, x: int, y: int) -> None:
        """
        Double-click at the specified coordinates on the screen.

        Args:
            x: X coordinate
            y: Y coordinate

        Returns:
            None

        Raises:
            Exception: If the double-click operation fails
        """
        try:
            self._instance.exec(
                f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool mousemove {x} {y} click --repeat 2 1'"
            )
        except Exception as e:
            raise Exception(
                f"Failed to double-click at coordinates ({x}, {y}): {str(e)}"
            ) from e

    def move_mouse(self, x: int, y: int) -> None:
        """
        Move the mouse to the specified coordinates without clicking.

        Args:
            x: X coordinate
            y: Y coordinate

        Returns:
            None

        Raises:
            Exception: If the mouse movement operation fails
        """
        try:
            self._instance.exec(
                f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool mousemove {x} {y}'"
            )
        except Exception as e:
            raise Exception(
                f"Failed to move mouse to coordinates ({x}, {y}): {str(e)}"
            ) from e

    def scroll(self, x: int, y: int, scroll_x: int, scroll_y: int) -> None:
        """
        Scroll at the specified coordinates.

        Args:
            x: X coordinate of the mouse
            y: Y coordinate of the mouse
            scroll_x: Horizontal scroll amount (negative = left, positive = right)
            scroll_y: Vertical scroll amount (negative = up, positive = down)
        """
        # First move mouse to position
        self.move_mouse(x, y)

        # Then perform scrolling
        if scroll_y != 0:
            # Positive scroll_y scrolls down, negative scrolls up
            # Xdotool takes click 4 for scroll up, 5 for scroll down
            button = 5 if scroll_y > 0 else 4  # 5 = down, 4 = up
            count = abs(scroll_y)
            self._instance.exec(
                f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool click --repeat {count} {button}'"
            )

        if scroll_x != 0:
            # Horizontal scrolling (button 6 = left, 7 = right)
            button = 7 if scroll_x > 0 else 6  # 7 = right, 6 = left
            count = abs(scroll_x)
            self._instance.exec(
                f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool click --repeat {count} {button}'"
            )

    def wait(self, ms: int = 1000) -> None:
        """
        Wait for the specified number of milliseconds.

        Args:
            ms: Number of milliseconds to wait
        """
        seconds = ms / 1000.0
        time.sleep(seconds)

    def type_text(self, text: str) -> None:
        """
        Type the specified text.

        This simulates keyboard input as if the user typed the text.
        """
        # Escape single quotes for bash
        safe_text = text.replace("'", "'\\''")
        # Use consistent quoting structure
        self._instance.exec(
            f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool type -- \"{safe_text}\"'"
        )

    def key_press(self, key_combo: str) -> None:
        """
        Press the specified key or key combination.

        Examples:
            computer.key_press("Return")  # Press Enter
            computer.key_press("ctrl+a")  # Press Ctrl+A
            computer.key_press("alt+F4")  # Press Alt+F4
        """
        self._instance.exec(
            f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool key {key_combo}'"
        )

    def key_press_special(self, keys: List[str]) -> None:
        """
        Press special keys using a more user-friendly interface.

        Args:
            keys: List of keys to press together (e.g., ["CTRL", "A"])

        Supports special keys like ARROWLEFT, ENTER, ESC, etc.
        """
        mapping = {
            "ARROWLEFT": "Left",
            "ARROWRIGHT": "Right",
            "ARROWUP": "Up",
            "ARROWDOWN": "Down",
            "ENTER": "Return",
            "LEFT": "Left",
            "RIGHT": "Right",
            "UP": "Up",
            "DOWN": "Down",
            "ESC": "Escape",
            "SPACE": "space",
            "BACKSPACE": "BackSpace",
            "TAB": "Tab",
            "CTRL": "ctrl",
            "ALT": "alt",
            "SHIFT": "shift",
        }
        mapped_keys = [mapping.get(key.upper(), key) for key in keys]
        combo = "+".join(mapped_keys)
        self._instance.exec(
            f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool key {combo}'"
        )

    def drag(self, path: List[Dict[str, int]]) -> None:
        """
        Drag from point to point along a path.

        Args:
            path: List of points like [{"x": 100, "y": 200}, {"x": 300, "y": 400}]
        """
        if not path:
            return

        start_x = path[0]["x"]
        start_y = path[0]["y"]

        self._instance.exec(
            f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool mousemove {start_x} {start_y} mousedown 1'"
        )

        for point in path[1:]:
            # Use separate variables for x and y to avoid escaping issues
            x = point["x"]
            y = point["y"]
            self._instance.exec(
                f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool mousemove {x} {y}'"
            )

        self._instance.exec(
            f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool mouseup 1'"
        )

    def screenshot(self) -> str:
        """
        Take a screenshot of the desktop and return the raw image data.

        Returns:
            Raw image data as bytes
        """
        # Ensure temp dir exists
        self._instance.exec("mkdir -p /tmp/screenshots && chmod 777 /tmp/screenshots")

        # Take screenshot as the morph user
        temp_path = "/tmp/screenshots/screenshot.png"
        self._instance.exec(
            f"sudo -u morph bash -c 'DISPLAY={self.display} import -window root {temp_path}'"
        )

        # Return the raw image data
        result = self._instance.exec(f"cat {temp_path} | base64 -w 0")
        return result.stdout

    def shutdown(self) -> None:
        """
        Shut down the computer.

        This method will shut down the computer instance.
        """
        self._instance.stop()

    def mcp(self) -> "mcp.server.fastmcp.FastMCP":
        """
        Get a FastMCP server for this Computer instance.

        This method creates and returns a FastMCP server object that exposes the Computer's
        capabilities through the Model Context Protocol (MCP). The server includes tools for:

        1. Desktop/VNC operations - screenshot, mouse actions, keyboard input, etc.
        2. Browser automation - web navigation, interaction, scraping, etc.
        3. Code execution sandbox - running Python code, notebook management, etc.

        Note: The returned FastMCP server is not started automatically. You need to
        call its .run() method with the desired transport protocol to start it, or use
        the Computer's helper methods like start_mcp_server().

        Returns:
            A FastMCP server instance with Computer-specific tools configured

        Example:
            # Get the MCP server
            mcp_server = computer.mcp()

            # Run it with SSE transport
            mcp_server.run(transport="sse")
        """
        from mcp.server.fastmcp import FastMCP

        mcp_server = FastMCP("computer")

        # Desktop/VNC unified tool
        mcp_server.add_tool(
            lambda command_name, **kwargs: self._execute_desktop_command(
                command_name, **kwargs
            ),
            name="desktop",
            description="Execute desktop/VNC commands. Available commands: screenshot, click, double_click, move_mouse, scroll, wait, type_text, key_press, key_press_special, drag, get_dimensions, set_display",
        )

        # Browser unified tool
        mcp_server.add_tool(
            lambda command_name, **kwargs: self._execute_browser_command(
                command_name, **kwargs
            ),
            name="browser",
            description="Execute browser commands. Available commands: goto, back, forward, get_title, get_url, screenshot, click, double_click, scroll, type, keypress, move, drag, wait, get_html",
        )

        # Sandbox unified tool
        mcp_server.add_tool(
            lambda command_name, **kwargs: self._execute_sandbox_command(
                command_name, **kwargs
            ),
            name="sandbox",
            description="Execute sandbox commands. Available commands: execute_code, create_notebook, add_cell, execute_cell, list_kernels, get_jupyter_url, wait_for_jupyter, start_kernel",
        )

        return mcp_server

    def get_mcp_stdio_command(self, file_path=None, object_name=None) -> "list[str]":
        """
        Get the command to invoke an MCP server in stdio transport mode.

        This method returns the command array that can be used with subprocess.run()
        to start the MCP server with stdio transport, allowing clients to
        communicate with it through stdin/stdout streams.

        Args:
            file_path: Optional path to the server file
                      If None, a temporary file will be created with the MCP server
            object_name: Optional name of the server object in the file
                        Defaults to None

        Returns:
            List of strings representing the command to execute

        Raises:
            NotImplementedError: This method is not yet implemented
        """
        raise NotImplementedError("The stdio command generation is not yet implemented")

    def get_mcp_sse_url(self, host=None, port=None) -> "str":
        """
        Get the SSE URL for connecting to the MCP server.

        This method returns the URL that clients can use to connect to
        the MCP server over SSE transport.

        Args:
            host: Optional host address (defaults to the computer's IP or 0.0.0.0)
            port: Optional port number (defaults to 8000)

        Returns:
            String URL for SSE connection
        """
        # Get the MCP server
        mcp_server = self.mcp()

        # Use specified values or defaults from server settings
        host = host or mcp_server.settings.host or "0.0.0.0"
        port = port or mcp_server.settings.port or 8000

        # Return the SSE URL
        return f"http://{host}:{port}/sse"

    def start_mcp_server(
        self, transport="sse", host=None, port=None, file_path=None
    ) -> "Union[str, 'subprocess.Popen']":
        """
        Start the MCP server with the specified transport.

        This method starts the MCP server either using stdio or SSE transport.
        For stdio, it returns a subprocess.Popen object.
        For SSE, it starts the server in a background thread and returns the URL.

        Args:
            transport: Transport protocol to use ("stdio" or "sse")
            host: Optional host address for SSE transport
            port: Optional port number for SSE transport
            file_path: Optional path to server file for stdio transport

        Returns:
            For "stdio": a subprocess.Popen object (not implemented yet)
            For "sse": the URL to connect to the server

        Raises:
            NotImplementedError: When stdio transport is requested (not yet implemented)
            ValueError: When an unknown transport is specified
        """
        if transport == "stdio":
            raise NotImplementedError("The stdio server startup is not yet implemented")

        elif transport == "sse":
            import threading

            # Get the MCP server
            mcp_server = self.mcp()

            # Set host and port if provided
            if host:
                mcp_server.settings.host = host
            if port:
                mcp_server.settings.port = port

            # Start the server in a background thread
            def run_server():
                import asyncio

                asyncio.run(mcp_server.run_sse_async())

            server_thread = threading.Thread(target=run_server, daemon=True)
            server_thread.start()

            # Return the URL for clients to connect
            url = self.get_mcp_sse_url(
                host=mcp_server.settings.host, port=mcp_server.settings.port
            )

            return url

        else:
            raise ValueError(f"Unknown transport: {transport}. Use 'stdio' or 'sse'.")

    def _execute_desktop_command(self, command_name, **kwargs):
        """Execute a desktop/VNC command based on the command_name parameter."""

        if command_name == "screenshot":
            return self.screenshot()

        elif command_name == "click":
            x = kwargs.get("x")
            y = kwargs.get("y")
            button = kwargs.get("button", "left")
            self.click(x, y, button)
            return f"{button} click performed at coordinates ({x}, {y})"

        elif command_name == "double_click":
            x = kwargs.get("x")
            y = kwargs.get("y")
            self.double_click(x, y)
            return f"Double-click performed at coordinates ({x}, {y})"

        elif command_name == "move_mouse":
            x = kwargs.get("x")
            y = kwargs.get("y")
            self.move_mouse(x, y)
            return f"Mouse moved to coordinates ({x}, {y})"

        elif command_name == "scroll":
            x = kwargs.get("x")
            y = kwargs.get("y")
            scroll_x = kwargs.get("scroll_x")
            scroll_y = kwargs.get("scroll_y")
            self.scroll(x, y, scroll_x, scroll_y)
            return f"Scroll performed at ({x}, {y}) with horizontal movement of {scroll_x} and vertical movement of {scroll_y}"

        elif command_name == "wait":
            ms = kwargs.get("ms", 1000)
            self.wait(ms)
            return f"Waited for {ms} milliseconds"

        elif command_name == "type_text":
            text = kwargs.get("text")
            self.type_text(text)
            return f"Typed text: '{text}'"

        elif command_name == "key_press":
            key_combo = kwargs.get("key_combo")
            self.key_press(key_combo)
            return f"Pressed key combination: {key_combo}"

        elif command_name == "key_press_special":
            keys = kwargs.get("keys")
            self.key_press_special(keys)
            return f"Pressed special keys: {', '.join(keys)}"

        elif command_name == "drag":
            path = kwargs.get("path")
            self.drag(path)
            return f"Performed drag operation from ({path[0]['x']}, {path[0]['y']}) to ({path[-1]['x']}, {path[-1]['y']})"

        elif command_name == "get_dimensions":
            return self.dimensions

        elif command_name == "set_display":
            display_id = kwargs.get("display_id")
            self.set_display(display_id)
            return f"Display set to {display_id}"

        else:
            raise ValueError(f"Unknown desktop command: {command_name}")

    def _execute_browser_command(self, command_name, **kwargs):
        """Execute a browser command based on the command_name parameter."""

        if command_name == "goto":
            url = kwargs.get("url")
            self.browser.goto(url)
            return f"Navigated to URL: {url}"

        elif command_name == "back":
            self.browser.back()
            return "Navigated back in browser history"

        elif command_name == "forward":
            self.browser.forward()
            return "Navigated forward in browser history"

        elif command_name == "get_title":
            return self.browser.get_title()

        elif command_name == "get_url":
            return self.browser.get_current_url()

        elif command_name == "screenshot":
            return self.browser.screenshot()

        elif command_name == "click":
            x = kwargs.get("x")
            y = kwargs.get("y")
            button = kwargs.get("button", "left")
            self.browser.click(x, y, button)
            return f"{button} click performed in browser at coordinates ({x}, {y})"

        elif command_name == "double_click":
            x = kwargs.get("x")
            y = kwargs.get("y")
            self.browser.double_click(x, y)
            return f"Double-click performed in browser at coordinates ({x}, {y})"

        elif command_name == "scroll":
            x = kwargs.get("x")
            y = kwargs.get("y")
            scroll_x = kwargs.get("scroll_x")
            scroll_y = kwargs.get("scroll_y")
            self.browser.scroll(x, y, scroll_x, scroll_y)
            return f"Scroll performed in browser at ({x}, {y}) with horizontal movement of {scroll_x} and vertical movement of {scroll_y}"

        elif command_name == "type":
            text = kwargs.get("text")
            self.browser.type(text)
            return f"Typed text in browser: '{text}'"

        elif command_name == "keypress":
            key = kwargs.get("key")
            self.browser.keypress([key])
            return f"Pressed key in browser: {key}"

        elif command_name == "move":
            x = kwargs.get("x")
            y = kwargs.get("y")
            self.browser.move(x, y)
            return f"Moved mouse in browser to coordinates ({x}, {y})"

        elif command_name == "drag":
            path = kwargs.get("path")
            self.browser.drag(path)
            return f"Performed drag operation in browser from ({path[0]['x']}, {path[0]['y']}) to ({path[-1]['x']}, {path[-1]['y']})"

        elif command_name == "wait":
            ms = kwargs.get("ms", 1000)
            self.browser.wait(ms)
            return f"Waited for {ms} milliseconds in browser"

        elif command_name == "get_html":
            return self.browser.get_html()

        else:
            raise ValueError(f"Unknown browser command: {command_name}")

    def _execute_sandbox_command(self, command_name, **kwargs):
        """Execute a sandbox command based on the command_name parameter."""

        if command_name == "execute_code":
            code = kwargs.get("code")
            timeout = kwargs.get("timeout", 30)
            return self.sandbox.execute_code(code, timeout)

        elif command_name == "create_notebook":
            name = kwargs.get("name")
            return self.sandbox.create_notebook(name)

        elif command_name == "add_cell":
            notebook_path = kwargs.get("notebook_path")
            content = kwargs.get("content")
            cell_type = kwargs.get("cell_type", "code")
            return self.sandbox.add_cell(notebook_path, content, cell_type)

        elif command_name == "execute_cell":
            notebook_path = kwargs.get("notebook_path")
            cell_index = kwargs.get("cell_index")
            return self.sandbox.execute_cell(notebook_path, cell_index)

        elif command_name == "list_kernels":
            return self.sandbox.list_kernels()

        elif command_name == "get_jupyter_url":
            return self.sandbox.jupyter_url

        elif command_name == "wait_for_jupyter":
            timeout = kwargs.get("timeout", 30)
            self.sandbox.wait_for_service(timeout)
            return f"Jupyter service ready after waiting up to {timeout} seconds"

        elif command_name == "start_kernel":
            kernel_name = kwargs.get("kernel_name", "python3")
            return self.sandbox.start_kernel(kernel_name)

        else:
            raise ValueError(f"Unknown sandbox command: {command_name}")

    def as_anthropic_tools(self) -> List[Dict[str, Any]]:
        """
        Convert Computer's MCP tools into Anthropic's function calling format.

        Fetches the available tools from the MCP server and formats them
        according to Anthropic's function calling API requirements.

        Returns:
            List of dictionaries representing Computer's tools in Anthropic's format
        """
        # Initialize MCP server and get tools
        mcp_server = self.mcp()
        tools = asyncio.run(mcp_server.list_tools())

        anthropic_tools = []

        for tool in tools:
            # Create the basic tool structure
            anthropic_tool = {
                "name": tool.name,
                "description": tool.description,
                "input_schema": {"type": "object", "properties": {}, "required": []},
            }

            # Extract properties from inputSchema if available
            if hasattr(tool, "inputSchema") and isinstance(tool.inputSchema, dict):
                anthropic_tool["input_schema"]["properties"] = tool.inputSchema.get(
                    "properties", {}
                )
                # Only include required field if it exists
                if "required" in tool.inputSchema:
                    anthropic_tool["input_schema"]["required"] = tool.inputSchema.get(
                        "required", []
                    )

            anthropic_tools.append(anthropic_tool)

        return anthropic_tools

    def as_openai_tools(self) -> List[Dict[str, Any]]:
        """
        Convert Computer's MCP tools into OpenAI's function calling format.

        Fetches the available tools from the MCP server and formats them
        according to OpenAI's function calling API requirements.

        Returns:
            List of dictionaries representing Computer's tools in OpenAI's format
        """
        # Initialize MCP server and get tools
        mcp_server = self.mcp()
        tools = asyncio.run(mcp_server.list_tools())

        openai_tools = []

        for tool in tools:
            # Create the OpenAI tool structure
            openai_tool = {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": {"type": "object", "properties": {}, "required": []},
                },
            }

            # Extract properties from inputSchema if available
            if hasattr(tool, "inputSchema") and isinstance(tool.inputSchema, dict):
                openai_tool["function"]["parameters"]["properties"] = (
                    tool.inputSchema.get("properties", {})
                )
                # Only include required field if it exists
                if "required" in tool.inputSchema:
                    openai_tool["function"]["parameters"]["required"] = (
                        tool.inputSchema.get("required", [])
                    )

            openai_tools.append(openai_tool)

        return openai_tools

    def desktop_url(self) -> Optional[str]:
        """
        Get the URL for the VNC desktop.

        This URL can be used to access the VNC desktop of the computer instance.
        """
        self._instance.wait_until_ready()
        for service in self._instance.networking.http_services:
            if service.name == "desktop":
                return service.url

        # No VNC service found
        return None

    def upload(
        self, local_path: str, remote_path: str, recursive: bool = False
    ) -> None:
        return self._instance.upload(local_path, remote_path, recursive)

    def branch(self, count: int = 1):
        _, instances = self._instance.branch(count=count)
        return [
            Computer(Instance.model_validate(instance)._set_api(self._instance._api))
            for instance in instances
        ]

    @classmethod
    def new(
        cls,
        client: Optional[MorphCloudClient] = None,
        ttl_seconds: Optional[int] = None,
    ) -> Computer:
        client = client or MorphCloudClient()

        snapshot = client.snapshots.list(metadata={"type": "computer-dev-04072025"})

        if not snapshot:
            raise ValueError("No snapshots available for Computer.")

        # Start a new computer instance
        computer = ComputerAPI(client).start(
            snapshot_id=snapshot[0].id,
            metadata={"type": "computer-dev-04072025"},
            ttl_seconds=ttl_seconds,
        )

        return computer

    def __enter__(self) -> "Computer":
        """
        Enter the context manager, allowing the Computer to be used with 'with' statements.

        This enables using the Computer in a context manager pattern, which will automatically
        shut down the Computer when exiting the context:

        Example:
            with Computer.new() as computer:
                # Do operations with the computer
                computer.browser.goto("https://example.com")
                # Computer will be automatically shut down when exiting this block

        Returns:
            The Computer instance itself for method chaining
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """
        Exit the context manager, shutting down the Computer instance.

        This method is called automatically when exiting a 'with' block.
        It ensures the Computer is properly shut down, even if an exception occurs.

        Args:
            exc_type: The exception type, if an exception was raised in the context
            exc_val: The exception value, if an exception was raised in the context
            exc_tb: The traceback, if an exception was raised in the context

        Returns:
            None
        """
        self.shutdown()


class ComputerAPI:
    """API for managing Computers, which are enhanced Instances with additional capabilities."""

    def __init__(self, client: MorphCloudClient) -> None:
        """
        Initialize the ComputerAPI.

        Args:
            client: The MorphClient instance
        """
        self._client = client

    def _verify_snapshot_is_computer(self, snapshot_id: str) -> Snapshot:
        """
        Verify that a snapshot is meant to be used as a Computer.

        Args:
            snapshot_id: ID of the snapshot to verify

        Returns:
            The verified Snapshot object

        Raises:
            ValueError: If the snapshot is not a valid Computer snapshot
        """
        # Fetch the snapshot details
        snapshot = self._client.snapshots.get(snapshot_id)

        # Check if the snapshot has the required metadata tag
        if snapshot.metadata.get("type") != "computer-dev-04072025":
            raise ValueError(
                f"Snapshot {snapshot_id} is not a valid Computer snapshot. "
                f"Only snapshots with metadata 'type=computer-dev-04072025' can be used with Computer API."
            )

        return snapshot

    def start(
        self,
        snapshot_id: str,
        metadata: Optional[Dict[str, str]] = None,
        ttl_seconds: Optional[int] = None,
        ttl_action: Union[None, typing.Literal["stop", "pause"]] = None,
    ) -> Computer:
        """
        Start a new Computer from a snapshot.

        Args:
            snapshot_id: ID of the snapshot to start
            metadata: Optional metadata to attach to the computer
            ttl_seconds: Optional time-to-live in seconds
            ttl_action: Optional action to take when TTL expires ("stop" or "pause")

        Returns:
            A new Computer instance

        Raises:
            ValueError: If the snapshot is not a valid Computer snapshot
        """
        # Verify the snapshot is meant for Computer use
        self._verify_snapshot_is_computer(snapshot_id)

        # Start the instance
        response = self._client._http_client.post(
            "/instance",
            params={"snapshot_id": snapshot_id},
            json={
                "metadata": metadata,
                "ttl_seconds": ttl_seconds,
                "ttl_action": ttl_action,
            },
        )
        return Computer(
            Instance.model_validate(response.json())._set_api(self._client.instances)
        )

    def get(self, computer_id: str) -> Computer:
        """Get a Computer by ID."""
        response = self._client._http_client.get(f"/instance/{computer_id}")
        return Computer(
            Instance.model_validate(response.json())._set_api(self._client.instances)
        )

    def list(self, metadata: Optional[Dict[str, str]] = None) -> List[Computer]:
        """List all computers available to the user."""
        response = self._client._http_client.get(
            "/instance",
            params={f"metadata[{k}]": v for k, v in (metadata or {}).items()},
        )
        return [
            Computer(Instance.model_validate(instance)._set_api(self._client.instances))
            for instance in response.json()["data"]
        ]
