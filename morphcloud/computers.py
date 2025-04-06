from __future__ import annotations

import typing
from typing import Any, Dict, List, Optional, Union
import importlib
from morphcloud.api import Instance, InstanceAPI, Snapshot
import base64
import time
import asyncio
import json 
import uuid
from datetime import datetime

_websockets_available = importlib.util.find_spec("websockets") is not None
_httpx_available = importlib.util.find_spec("httpx") is not None
_jupyter_client_available = importlib.util.find_spec("jupyter_client") is not None

_playwright_available = importlib.util.find_spec("playwright") is not None
_aiohttp_available = importlib.util.find_spec("aiohttp") is not None

class Browser:
    """
    Browser automation interface for Computer using Chrome DevTools Protocol.
    
    This class provides methods to automate browser interactions through Playwright
    and Chrome DevTools Protocol. It handles connection management, navigation,
    and browser control operations.
    """
    
    def __init__(self, computer: 'Computer'):
        """
        Initialize a Browser instance.
        
        Args:
            computer: The parent Computer instance
        """
        self._computer = computer
        self._browser = None
        self._context = None
        self._page = None
        self._playwright = None
        self._connected = False
    
    def _check_dependencies(self) -> None:
        """
        Check if required dependencies are installed.
        
        Raises:
            ImportError: If any required package is missing
        """
        if not _playwright_available:
            raise ImportError(
                "The playwright package is required for browser automation. "
                "Install it with: pip install playwright"
            )
        if not _aiohttp_available:
            raise ImportError(
                "The aiohttp package is required for browser automation. "
                "Install it with: pip install aiohttp"
            )
    
    async def connect(self, timeout_seconds: int = 30) -> 'Browser':
        """
        Connect to a CDP endpoint and create a browser client.
        
        Args:
            timeout_seconds: Maximum time to wait for connection in seconds
            
        Returns:
            The Browser instance for method chaining
            
        Raises:
            ImportError: If required dependencies are not installed
            TimeoutError: If connection times out
            Exception: Other connection errors
        """
        if self._connected:
            return self
        
        self._check_dependencies()
        from playwright.async_api import async_playwright
        import aiohttp
        
        # Get CDP URL
        cdp_url = self._computer.cdp_url
        
        try:
            # Get the WebSocket URL directly from the /json/version endpoint
            browser_ws_endpoint = await self._get_browser_ws_endpoint(cdp_url, timeout_seconds)
            
            # Launch playwright
            self._playwright = await async_playwright().start()
            
            # Connect to the browser using CDP
            self._browser = await self._playwright.chromium.connect_over_cdp(browser_ws_endpoint)
            
            # Create a new context and page
            self._context = await self._browser.new_context()
            self._page = await self._context.new_page()
            self._connected = True
            
            return self
        except Exception as e:
            raise Exception(f"Failed to connect to browser: {str(e)}") from e
    
    async def _get_browser_ws_endpoint(self, cdp_url: str, timeout_seconds: int = 15) -> str:
        """
        Get the WebSocket endpoint URL from the CDP server with retries.
        
        Args:
            cdp_url: Chrome DevTools Protocol URL
            timeout_seconds: Maximum time to wait for connection in seconds
            
        Returns:
            WebSocket URL as a string
            
        Raises:
            TimeoutError: If unable to get WebSocket URL within timeout period
        """
        import aiohttp
        
        # Remove any trailing slashes
        cdp_url = cdp_url.rstrip('/')
        json_version_url = f"{cdp_url}/json/version"
        
        # Set up retry parameters
        start_time = time.time()
        retry_count = 0
        base_delay = 0.5  # Start with a short delay
        errors = []
        
        while time.time() - start_time < timeout_seconds:
            retry_count += 1
            current_delay = min(base_delay * retry_count, 2.0)  # Cap at 2 seconds per retry
            
            try:
                async with aiohttp.ClientSession() as session:
                    # Get the /json/version endpoint
                    async with session.get(json_version_url, timeout=5) as response:
                        if response.status != 200:
                            await asyncio.sleep(current_delay)
                            continue
                        
                        try:
                            data = await response.json()
                            
                            # Use the exact WebSocketDebuggerUrl from the response
                            websocket_url = data.get("webSocketDebuggerUrl")
                            if not websocket_url:
                                await asyncio.sleep(current_delay)
                                continue
                            
                            # Success!
                            return websocket_url
                        except json.JSONDecodeError:
                            errors.append(f"Invalid JSON response on attempt {retry_count}")
                            await asyncio.sleep(current_delay)
                            continue
                        
            except aiohttp.ClientError as e:
                errors.append(f"HTTP client error on attempt {retry_count}: {str(e)}")
            except asyncio.TimeoutError:
                errors.append(f"Timeout error on attempt {retry_count}")
            except Exception as e:
                errors.append(f"Unexpected error on attempt {retry_count}: {str(e)}")
            
            # Sleep before retry
            await asyncio.sleep(current_delay)
            
            # Check if we're about to exceed the timeout
            time_remaining = timeout_seconds - (time.time() - start_time)
            if time_remaining < 1:
                break
        
        # If we got here, we've timed out
        error_summary = "; ".join(errors[-3:]) if errors else "No specific errors recorded"
        raise TimeoutError(f"Failed to get WebSocket URL after {retry_count} attempts. Errors: {error_summary}")
    
    async def _ensure_connected(self) -> None:
        """
        Ensure browser is connected before performing operations.
        
        Connects to the browser if not already connected.
        
        Raises:
            Exception: If connection fails
        """
        if not self._connected:
            await self.connect()
    
    async def goto(self, url: str, timeout: int = 15000, wait_until: str = "domcontentloaded") -> None:
        """
        Navigate to a URL.
        
        Args:
            url: The URL to navigate to
            timeout: Maximum time to wait for navigation in milliseconds
            wait_until: Navigation event to wait for ('domcontentloaded', 'load', 'networkidle')
            
        Raises:
            TimeoutError: If navigation takes longer than timeout
            Exception: If an error occurs during navigation
        """
        try:
            await self._ensure_connected()
            # Use a shorter timeout and wait until 'domcontentloaded' instead of 'load'
            await self._page.goto(url, timeout=timeout, wait_until=wait_until)
            
            # Add a small delay to ensure the page is stable
            await asyncio.sleep(1)
        except Exception as e:
            raise Exception(f"Failed to navigate to {url}: {str(e)}") from e
    
    async def back(self, timeout: int = 10000, wait_until: str = "domcontentloaded") -> None:
        """
        Go back in the browser history with fallback behavior.
        
        Args:
            timeout: Maximum time to wait for navigation in milliseconds
            wait_until: Navigation event to wait for ('domcontentloaded', 'load', 'networkidle')
            
        Raises:
            Exception: If an error occurs during navigation
        """
        try:
            await self._ensure_connected()
            
            try:
                # Try with a shorter timeout and 'domcontentloaded' event
                await self._page.go_back(timeout=timeout, wait_until=wait_until)
            except Exception as nav_error:
                # If timeout occurs, the page might still be navigating
                print(f"Navigation error when going back: {str(nav_error)}")
                # Wait a bit to give the page a chance to settle
                await asyncio.sleep(3)
            
            # Get the current URL to verify navigation happened
            current_url = self._page.url
        except Exception as e:
            raise Exception(f"Failed to go back in browser history: {str(e)}") from e
    
    async def forward(self, timeout: int = 10000, wait_until: str = "domcontentloaded") -> None:
        """
        Go forward in the browser history with fallback behavior.
        
        Args:
            timeout: Maximum time to wait for navigation in milliseconds
            wait_until: Navigation event to wait for ('domcontentloaded', 'load', 'networkidle')
            
        Raises:
            Exception: If an error occurs during navigation
        """
        try:
            await self._ensure_connected()
            
            try:
                # Try with a shorter timeout and 'domcontentloaded' event
                await self._page.go_forward(timeout=timeout, wait_until=wait_until)
            except Exception as nav_error:
                # If timeout occurs, the page might still be navigating
                print(f"Navigation error when going forward: {str(nav_error)}")
                # Wait a bit to give the page a chance to settle
                await asyncio.sleep(3)
            
            # Get the current URL to verify navigation happened
            current_url = self._page.url
        except Exception as e:
            raise Exception(f"Failed to go forward in browser history: {str(e)}") from e
    
    async def get_title(self) -> str:
        """
        Get the current page title.
        
        Returns:
            The title of the current page
            
        Raises:
            Exception: If not connected or fails to get title
        """
        await self._ensure_connected()
        return await self._page.title()
    
    async def get_url(self) -> str:
        """
        Get the current page URL.
        
        Returns:
            The URL of the current page
            
        Raises:
            Exception: If not connected
        """
        await self._ensure_connected()
        return self._page.url
    
    async def screenshot(self) -> bytes:
        """
        Take a screenshot of the current page and return the raw image data.
        
        Returns:
            Raw image data as bytes
            
        Raises:
            Exception: If screenshot fails
        """
        await self._ensure_connected()
        screenshot_bytes = await self._page.screenshot()
        return screenshot_bytes
    
    
    async def close(self) -> None:
        """
        Close the browser and clean up resources.
        
        This method should be called when done using the browser to free resources.
        """
        if not self._connected:
            return
            
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
            
        self._connected = False
        self._browser = None
        self._context = None
        self._page = None
        self._playwright = None


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
        if not _websockets_available:
            missing.append("websockets")
        if not _httpx_available:
            missing.append("httpx")
            
        if missing:
            raise ImportError(
                f"The following packages are required for sandbox code execution: {', '.join(missing)}. "
                f"Install them with: pip install {' '.join(missing)}"
            )
    
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
            for service in self._computer.networking.http_services:
                if service.port == 8888 or service.name == "jupyterlab":
                    self._jupyter_url = service.url
                    break
            
            # If not found, expose it
            if not self._jupyter_url:
                self._jupyter_url = self._computer.expose_http_service("jupyterlab", 8888)
        
        return self._jupyter_url
    
    async def _ensure_kernel_connection(self) -> None:
        """
        Ensure we have an active kernel connection.
        
        Connects to a kernel if not already connected.
        
        Raises:
            Various exceptions from connect() method
        """
        if not self._ws_connected:
            await self.connect()
    
    async def wait_for_service(self, timeout: int = 30) -> bool:
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
        import httpx
        
        start_time = time.time()
        errors = []
        
        async with httpx.AsyncClient() as client:
            while time.time() - start_time < timeout:
                try:
                    response = await client.get(
                        f"{self.jupyter_url}/api/status",
                        timeout=5.0
                    )
                    if response.status_code == 200:
                        return True
                except Exception as e:
                    # Store error but continue trying
                    errors.append(f"Error connecting to Jupyter service: {str(e)}")
                await asyncio.sleep(2)
            
            error_detail = "; ".join(errors[-3:]) if errors else "No specific errors recorded"
            raise TimeoutError(f"Jupyter service failed to start within {timeout} seconds. Errors: {error_detail}")
    
    async def list_kernels(self) -> List[Dict[str, Any]]:
        """
        List available kernels.
        
        Returns:
            List of kernel dictionaries with metadata
            
        Raises:
            ImportError: If required dependencies are not installed
            httpx.HTTPError: If API request fails
        """
        self._check_dependencies()
        import httpx
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.jupyter_url}/api/kernels"
            )
            response.raise_for_status()
            return response.json()
    
    async def start_kernel(self, kernel_name: str = "python3") -> Dict[str, Any]:
        """
        Start a new kernel with the given name.
        
        Args:
            kernel_name: The name of the kernel to start (default: python3)
            
        Returns:
            Dictionary with kernel information including ID
            
        Raises:
            ImportError: If required dependencies are not installed
            httpx.HTTPError: If API request fails
        """
        self._check_dependencies()
        import httpx
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.jupyter_url}/api/kernels",
                json={"name": kernel_name}
            )
            response.raise_for_status()
            kernel_info = response.json()
            self._kernel_id = kernel_info['id']
            return kernel_info
    
    async def connect(self, timeout_seconds: int = 30, kernel_id: Optional[str] = None) -> 'Sandbox':
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
            websockets.WebSocketException: If WebSocket connection fails
        """
        self._check_dependencies()
        import httpx
        import websockets
        
        # Wait for Jupyter service to be ready
        await self.wait_for_service(timeout_seconds)
        
        # Use existing kernel_id if provided, otherwise start a new kernel
        if kernel_id:
            self._kernel_id = kernel_id
        elif not self._kernel_id:
            await self.start_kernel()
        
        # Connect to the WebSocket
        ws_url = self.jupyter_url.replace('https://', 'wss://').replace('http://', 'ws://')
        ws_endpoint = f"{ws_url}/api/kernels/{self._kernel_id}/channels"
        
        # Close existing connection if any
        if self._ws:
            try:
                await self._ws.close()
            except Exception as e:
                print(f"Error closing WebSocket connection: {str(e)}")
            finally:
                self._ws = None
                self._ws_connected = False
        
        # Connect to kernel WebSocket
        self._ws = await websockets.connect(ws_endpoint)
        self._ws_connected = True
        
        return self
    
    async def execute_code(self, code: str, timeout: int = 30) -> Dict[str, Any]:
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
        await self._ensure_kernel_connection()
        
        # Prepare message
        msg_id = str(uuid.uuid4())
        msg = {
            'header': {
                'msg_id': msg_id,
                'username': 'kernel',
                'session': self._session_id,
                'msg_type': 'execute_request',
                'version': '5.0',
                'date': datetime.now().isoformat(),
            },
            'parent_header': {},
            'metadata': {},
            'content': {
                'code': code,
                'silent': False,
                'store_history': True,
                'user_expressions': {},
                'allow_stdin': False,
                'stop_on_error': True
            },
            'channel': 'shell'
        }
        
        # Convert datetime to string for JSON serialization
        class DateTimeEncoder(json.JSONEncoder):
            def default(self, obj):
                if isinstance(obj, datetime):
                    return obj.isoformat()
                return json.JSONEncoder.default(self, obj)
        
        await self._ws.send(json.dumps(msg, cls=DateTimeEncoder))
        
        # Process messages
        outputs = []
        images = []
        status = 'ok'
        execution_count = None
        
        # Track message types we've received
        got_execute_input = False
        got_output = False
        got_status_idle = False
        
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                response = await asyncio.wait_for(self._ws.recv(), timeout=5.0)
                
                try:
                    response_data = json.loads(response)
                except json.JSONDecodeError as json_err:
                    print(f"Failed to parse WebSocket message: {str(json_err)}")
                    continue
                
                parent_msg_id = response_data.get('parent_header', {}).get('msg_id')
                msg_type = response_data.get('header', {}).get('msg_type')
                
                # Only process messages related to our request
                if parent_msg_id != msg_id:
                    continue
                
                if msg_type == 'execute_input':
                    got_execute_input = True
                    execution_count = response_data.get('content', {}).get('execution_count')
                
                elif msg_type == 'stream':
                    got_output = True
                    text = response_data.get('content', {}).get('text', '')
                    outputs.append(text)
                
                elif msg_type == 'execute_result':
                    got_output = True
                    data = response_data.get('content', {}).get('data', {})
                    text = data.get('text/plain', '')
                    outputs.append(text)
                    
                    # Check for image data
                    for mime_type in ['image/png', 'image/jpeg', 'image/svg+xml']:
                        if mime_type in data:
                            images.append({
                                'mime_type': mime_type,
                                'data': data[mime_type]
                            })
                
                elif msg_type == 'display_data':
                    got_output = True
                    data = response_data.get('content', {}).get('data', {})
                    text = data.get('text/plain', '')
                    outputs.append(text)
                    
                    # Check for image data
                    for mime_type in ['image/png', 'image/jpeg', 'image/svg+xml']:
                        if mime_type in data:
                            images.append({
                                'mime_type': mime_type,
                                'data': data[mime_type]
                            })
                
                elif msg_type == 'error':
                    got_output = True
                    status = 'error'
                    traceback = response_data.get('content', {}).get('traceback', [])
                    outputs.extend(traceback)
                
                elif msg_type == 'status':
                    if response_data.get('content', {}).get('execution_state') == 'idle':
                        got_status_idle = True
                
                # Break if we have both the idle status and either input or output
                if got_status_idle and (got_output or got_execute_input):
                    # Add a small delay to ensure we've gotten all messages
                    await asyncio.sleep(0.1)
                    break
            
            except asyncio.TimeoutError:
                # If we've seen idle but no output, we might be done (empty execution)
                if got_status_idle and got_execute_input:
                    break
                continue
            except Exception as e:
                outputs.append(f"Error processing message: {str(e)}")
                status = 'error'
                break
        
        # Create result
        result = {
            'status': status,
            'execution_count': execution_count,
            'output': '\n'.join(outputs).strip(),
            'kernel_id': self._kernel_id
        }
        
        if images:
            result['images'] = images
        
        return result
    
    async def create_notebook(self, name: str) -> Dict[str, Any]:
        """
        Create a new notebook.
        
        Args:
            name: Name of the notebook (with or without .ipynb extension)
            
        Returns:
            Notebook metadata dictionary
            
        Raises:
            ImportError: If required dependencies are not installed
            httpx.HTTPError: If API request fails
        """
        self._check_dependencies()
        import httpx
        
        # Ensure notebook name has .ipynb extension
        if not name.endswith('.ipynb'):
            name = f"{name}.ipynb"
        
        # Minimal notebook format
        notebook = {
            "metadata": {
                "kernelspec": {
                    "name": "python3",
                    "display_name": "Python 3",
                    "language": "python"
                }
            },
            "nbformat": 4,
            "nbformat_minor": 5,
            "cells": []
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.put(
                f"{self.jupyter_url}/api/contents/{name}",
                json={
                    "type": "notebook",
                    "content": notebook
                }
            )
            response.raise_for_status()
            return response.json()
    
    async def add_cell(self, notebook_path: str, content: str, cell_type: str = "code") -> Dict[str, Any]:
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
            httpx.HTTPError: If API request fails
            ValueError: If cell_type is invalid
        """
        self._check_dependencies()
        import httpx
        
        # Ensure notebook path has .ipynb extension
        if not notebook_path.endswith('.ipynb'):
            notebook_path = f"{notebook_path}.ipynb"
            
        # Get current notebook
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.jupyter_url}/api/contents/{notebook_path}",
            )
            response.raise_for_status()
            notebook_data = response.json()
            notebook = notebook_data["content"]
            
            # Create new cell
            new_cell = {
                "cell_type": cell_type,
                "metadata": {},
                "source": content
            }
            
            if cell_type == "code":
                new_cell["execution_count"] = None
                new_cell["outputs"] = []
            
            # Append cell
            notebook["cells"].append(new_cell)
            cell_index = len(notebook["cells"]) - 1
            
            # Save notebook
            response = await client.put(
                f"{self.jupyter_url}/api/contents/{notebook_path}",
                json={
                    "type": "notebook",
                    "content": notebook
                }
            )
            response.raise_for_status()
            
            return {"index": cell_index, "cell": new_cell}
    
    async def execute_cell(self, notebook_path: str, cell_index: int) -> Dict[str, Any]:
        """
        Execute a specific cell in a notebook.
        
        Args:
            notebook_path: Path to the notebook
            cell_index: Index of the cell to execute
            
        Returns:
            Dictionary containing execution results (same format as execute_code)
            
        Raises:
            ImportError: If required dependencies are not installed
            httpx.HTTPError: If API request fails
            ValueError: If cell_index is out of range or cell is not a code cell
        """
        self._check_dependencies()
        import httpx
        
        # Get the notebook
        async with httpx.AsyncClient() as client:
            response = await client.get(
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
            return await self.execute_code(code)
    
    async def close(self) -> None:
        """
        Close the kernel WebSocket connection.
        
        This method should be called when done using the sandbox to free resources.
        Any errors during closing are logged but don't prevent cleanup.
        """
        if self._ws:
            try:
                await self._ws.close()
            except Exception as e:
                # Log the error but continue with cleanup
                print(f"Error closing WebSocket connection: {str(e)}")
            finally:
                self._ws = None
                self._ws_connected = False
    
    # Synchronous interface
    
    def _run_async(self, coro: typing.Coroutine) -> Any:
        """
        Run an async coroutine in a new event loop.
        
        Args:
            coro: The coroutine to run
            
        Returns:
            The result of the coroutine
            
        Raises:
            Exception: Any exception raised by the coroutine
        """
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()
    
    def wait_for_service_sync(self, timeout: int = 30) -> bool:
        """
        Synchronous version of wait_for_service.
        
        Args:
            timeout: Maximum time to wait in seconds
            
        Returns:
            True if service is ready
            
        Raises:
            Same exceptions as the async version
        """
        return self._run_async(self.wait_for_service(timeout))
    
    def connect_sync(self, timeout_seconds: int = 30, kernel_id: Optional[str] = None) -> 'Sandbox':
        """
        Synchronous version of connect.
        
        Args:
            timeout_seconds: Maximum time to wait for service in seconds
            kernel_id: Optional ID of existing kernel to connect to
            
        Returns:
            The Sandbox instance for method chaining
            
        Raises:
            Same exceptions as the async version
        """
        return self._run_async(self.connect(timeout_seconds, kernel_id))
    
    def list_kernels_sync(self) -> List[Dict[str, Any]]:
        """
        Synchronous version of list_kernels.
        
        Returns:
            List of kernel dictionaries with metadata
            
        Raises:
            Same exceptions as the async version
        """
        return self._run_async(self.list_kernels())
    
    def start_kernel_sync(self, kernel_name: str = "python3") -> Dict[str, Any]:
        """
        Synchronous version of start_kernel.
        
        Args:
            kernel_name: The name of the kernel to start (default: python3)
            
        Returns:
            Dictionary with kernel information including ID
            
        Raises:
            Same exceptions as the async version
        """
        return self._run_async(self.start_kernel(kernel_name))
    
    def execute_code_sync(self, code: str, timeout: int = 30) -> Dict[str, Any]:
        """
        Synchronous version of execute_code.
        
        Args:
            code: Python code to execute
            timeout: Maximum time to wait for execution in seconds
            
        Returns:
            Dictionary containing execution results
            
        Raises:
            Same exceptions as the async version
        """
        return self._run_async(self.execute_code(code, timeout))
    
    def create_notebook_sync(self, name: str) -> Dict[str, Any]:
        """
        Synchronous version of create_notebook.
        
        Args:
            name: Name of the notebook (with or without .ipynb extension)
            
        Returns:
            Notebook metadata dictionary
            
        Raises:
            Same exceptions as the async version
        """
        return self._run_async(self.create_notebook(name))
    
    def add_cell_sync(self, notebook_path: str, content: str, cell_type: str = "code") -> Dict[str, Any]:
        """
        Synchronous version of add_cell.
        
        Args:
            notebook_path: Path to the notebook
            content: Cell content
            cell_type: Cell type ("code", "markdown", or "raw")
            
        Returns:
            Dictionary with cell index and cell data
            
        Raises:
            Same exceptions as the async version
        """
        return self._run_async(self.add_cell(notebook_path, content, cell_type))
    
    def execute_cell_sync(self, notebook_path: str, cell_index: int) -> Dict[str, Any]:
        """
        Synchronous version of execute_cell.
        
        Args:
            notebook_path: Path to the notebook
            cell_index: Index of the cell to execute
            
        Returns:
            Dictionary containing execution results
            
        Raises:
            Same exceptions as the async version
        """
        return self._run_async(self.execute_cell(notebook_path, cell_index))
    
    def close_sync(self) -> None:
        """
        Synchronous version of close.
        
        Closes the kernel WebSocket connection.
        """
        return self._run_async(self.close())


class Computer(Instance):
    """
    A Computer is an enhanced Instance with additional capabilities
    like VNC interaction, browser automation, and code execution.
    """
    
    def _set_api(self, api: InstanceAPI) -> Computer:
        """Override _set_api to return a Computer instead of an Instance."""
        super()._set_api(api)  # Call the parent method to set the _api attribute
        
        # Initialize computer-specific components
        self._browser = Browser(self)
        self._sandbox = Sandbox(self)
        self._display = ":1"  # Default display
        return self
        
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
        result = self.exec("sudo -u morph bash -c 'DISPLAY={0} xdpyinfo | grep dimensions'".format(self.display))
        # Parse the dimensions from output like "dimensions:    1920x1080 pixels (508x285 millimeters)"
        dimensions_str = result.stdout.strip()
        if "dimensions:" in dimensions_str:
            # Extract the resolution part like "1920x1080"
            resolution = dimensions_str.split("dimensions:")[1].strip().split()[0]
            width, height = map(int, resolution.split("x"))
            return (width, height)
        # Return a default if unable to detect
        return (1024, 768)
        
    def as_anthropic_tools(self) -> List[Dict[str, Any]]:
        """
        Convert Computer's tools into Anthropic's function calling format.
        
        This method generates tool definitions for use with Anthropic's function calling API.
        It includes both high-level wrapper tools for browser, sandbox, and desktop interaction,
        as well as granular direct tools for specific operations.
        
        The tools are formatted according to Anthropic's schema requirements:
        - name: The tool name (e.g., "browser_tool", "browser_goto")
        - description: Human-readable description of what the tool does
        - input_schema: JSON schema describing the required and optional parameters
        
        Returns:
            List of dictionaries representing Computer's tools in Anthropic's format
            with high-level wrapper tools and granular direct tools.
        """
        tools = []
        
        # Add high-level browser tool wrapper
        tools.append({
            "name": "browser_tool",
            "description": "Automates browser interactions through MorphCloud.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string", 
                        "description": "The browser action to perform",
                        "enum": ["goto", "get_title", "get_url", 
                                "back", "forward", "reload", "close"]
                    },
                    "url": {"type": "string", "description": "The URL to navigate to"},
                    "timeout": {"type": "integer", "description": "Timeout in milliseconds (for navigation actions)"},
                    "wait_until": {"type": "string", "description": "Wait until event (for navigation actions)"}
                },
                "required": ["action"]
            }
        })
        
        # Add high-level sandbox tool wrapper
        tools.append({
            "name": "sandbox_tool",
            "description": "Executes code in a Jupyter sandbox through MorphCloud.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string", 
                        "description": "The sandbox action to perform",
                        "enum": ["execute_code", "create_notebook", "add_cell", "execute_cell", 
                                "list_kernels", "close"]
                    },
                    "code": {"type": "string", "description": "Python code to execute"},
                    "name": {"type": "string", "description": "Name for a new notebook"},
                    "notebook_path": {"type": "string", "description": "Path to a notebook"},
                    "content": {"type": "string", "description": "Content for a notebook cell"},
                    "cell_type": {"type": "string", "description": "Type of cell (code or markdown)"},
                    "cell_index": {"type": "integer", "description": "Index of a cell to execute"}
                },
                "required": ["action"]
            }
        })
        
        # Add high-level desktop tool wrapper
        tools.append({
            "name": "desktop_tool",
            "description": "Interacts with a virtual desktop through MorphCloud.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string", 
                        "description": "The desktop action to perform",
                        "enum": ["move_mouse", "click", "type_text", "key_press", "screenshot", "scroll", "wait"]
                    },
                    "x": {"type": "integer", "description": "X coordinate for mouse action (required for move_mouse, click, and scroll)"},
                    "y": {"type": "integer", "description": "Y coordinate for mouse action (required for move_mouse, click, and scroll)"},
                    "scroll_x": {"type": "integer", "description": "Horizontal scroll amount (for scroll action)"},
                    "scroll_y": {"type": "integer", "description": "Vertical scroll amount (for scroll action)"},
                    "ms": {"type": "integer", "description": "Milliseconds to wait (for wait action)"},
                    "button": {"type": "string", "description": "Mouse button (left, right, middle)"},
                    "text": {"type": "string", "description": "Text to type (required for type_text)"},
                    "keys": {"type": "array", "description": "Special keys to press (required for key_press)", "items": {"type": "string"}},
                    "filename": {"type": "string", "description": "Optional filename to save the screenshot (if omitted, screenshot is only returned as base64)"}
                },
                "required": ["action"]
            }
        })
        
        # Add individual browser tools
        tools.extend([
            # Browser tools
            {
                "name": "browser_goto",
                "description": "Navigate to a URL in the browser",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "The URL to navigate to"
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Timeout in milliseconds",
                            "default": 15000
                        },
                        "wait_until": {
                            "type": "string",
                            "description": "Wait until event (domcontentloaded, load, networkidle)",
                            "default": "domcontentloaded"
                        }
                    },
                    "required": ["url"]
                }
            },
            {
                "name": "browser_back",
                "description": "Go back in browser history",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "timeout": {
                            "type": "integer",
                            "description": "Timeout in milliseconds",
                            "default": 10000
                        },
                        "wait_until": {
                            "type": "string",
                            "description": "Wait until event (domcontentloaded, load, networkidle)",
                            "default": "domcontentloaded"
                        }
                    }
                }
            },
            {
                "name": "browser_forward",
                "description": "Go forward in browser history",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "timeout": {
                            "type": "integer",
                            "description": "Timeout in milliseconds",
                            "default": 10000
                        },
                        "wait_until": {
                            "type": "string",
                            "description": "Wait until event (domcontentloaded, load, networkidle)",
                            "default": "domcontentloaded"
                        }
                    }
                }
            },
            {
                "name": "browser_get_title",
                "description": "Get the current page title",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "browser_get_url",
                "description": "Get the current page URL",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "browser_screenshot",
                "description": "Take a screenshot of the current page and return as raw bytes",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                }
            }
        ])
        
        # Add VNC interaction tools
        tools.extend([
            {
                "name": "scroll",
                "description": "Scroll at specified coordinates on the screen",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "x": {
                            "type": "integer",
                            "description": "X coordinate for mouse position"
                        },
                        "y": {
                            "type": "integer",
                            "description": "Y coordinate for mouse position"
                        },
                        "scroll_x": {
                            "type": "integer",
                            "description": "Horizontal scroll amount (negative = left, positive = right)",
                            "default": 0
                        },
                        "scroll_y": {
                            "type": "integer",
                            "description": "Vertical scroll amount (negative = up, positive = down)",
                            "default": 0
                        }
                    },
                    "required": ["x", "y"]
                }
            },
            {
                "name": "wait",
                "description": "Wait for specified milliseconds",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ms": {
                            "type": "integer",
                            "description": "Milliseconds to wait",
                            "default": 1000
                        }
                    }
                }
            },
            {
                "name": "click",
                "description": "Click at specified coordinates on the screen",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "x": {
                            "type": "integer",
                            "description": "X coordinate"
                        },
                        "y": {
                            "type": "integer",
                            "description": "Y coordinate"
                        },
                        "button": {
                            "type": "string",
                            "description": "Mouse button (left, middle, right)",
                            "default": "left"
                        }
                    },
                    "required": ["x", "y"]
                }
            },
            {
                "name": "double_click",
                "description": "Double-click at specified coordinates on the screen",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "x": {
                            "type": "integer",
                            "description": "X coordinate"
                        },
                        "y": {
                            "type": "integer",
                            "description": "Y coordinate"
                        }
                    },
                    "required": ["x", "y"]
                }
            },
            {
                "name": "move_mouse",
                "description": "Move the mouse to specified coordinates without clicking",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "x": {
                            "type": "integer",
                            "description": "X coordinate"
                        },
                        "y": {
                            "type": "integer",
                            "description": "Y coordinate"
                        }
                    },
                    "required": ["x", "y"]
                }
            },
            {
                "name": "type_text",
                "description": "Type the specified text",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "Text to type"
                        }
                    },
                    "required": ["text"]
                }
            },
            {
                "name": "key_press",
                "description": "Press the specified key or key combination",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "key_combo": {
                            "type": "string",
                            "description": "Key or key combination to press (e.g., 'Return', 'ctrl+a')"
                        }
                    },
                    "required": ["key_combo"]
                }
            },
            {
                "name": "screenshot",
                "description": "Take a screenshot of the desktop and return as raw bytes",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                }
            }
        ])
        
        # Add sandbox tools
        tools.extend([
            {
                "name": "execute_code",
                "description": "Execute Python code in a sandbox environment",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "Python code to execute"
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Timeout in seconds",
                            "default": 30
                        }
                    },
                    "required": ["code"]
                }
            },
            {
                "name": "create_notebook",
                "description": "Create a new Jupyter notebook",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Name of the notebook (with or without .ipynb extension)"
                        }
                    },
                    "required": ["name"]
                }
            },
            {
                "name": "add_cell",
                "description": "Add a cell to a Jupyter notebook",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "notebook_path": {
                            "type": "string",
                            "description": "Path to the notebook"
                        },
                        "content": {
                            "type": "string",
                            "description": "Cell content"
                        },
                        "cell_type": {
                            "type": "string",
                            "description": "Cell type (code, markdown, or raw)",
                            "default": "code"
                        }
                    },
                    "required": ["notebook_path", "content"]
                }
            },
            {
                "name": "execute_cell",
                "description": "Execute a specific cell in a Jupyter notebook",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "notebook_path": {
                            "type": "string",
                            "description": "Path to the notebook"
                        },
                        "cell_index": {
                            "type": "integer",
                            "description": "Index of the cell to execute"
                        }
                    },
                    "required": ["notebook_path", "cell_index"]
                }
            }
        ])
        
        return tools
    
    def as_openai_tools(self) -> List[Dict[str, Any]]:
        """
        Convert Computer's tools into OpenAI's function calling format.
        
        This method transforms the Computer's capabilities into OpenAI's function calling format
        by converting the Anthropic tool definitions. The conversion process:
        
        1. Gets the Anthropic tool definitions from as_anthropic_tools()
        2. Restructures each tool to match OpenAI's schema:
           - "type": "function"
           - "function": Contains name, description, and parameters
        
        OpenAI tools follow a different structure from Anthropic tools but maintain
        the same functionality and parameter requirements.
        
        Returns:
            List of dictionaries representing Computer's tools in OpenAI's format.
        """
        tools = []
        
        # Convert Anthropic tools to OpenAI format
        for tool in self.as_anthropic_tools():
            openai_tool = {
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool["description"],
                    "parameters": tool["input_schema"]
                }
            }
            tools.append(openai_tool)
            
        return tools
    
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
        if not hasattr(self, '_browser'):
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
        if not hasattr(self, '_sandbox'):
            self._sandbox = Sandbox(self)
        return self._sandbox
    
    @property
    def cdp_url(self) -> Optional[str]:
        """
        Get the Chrome DevTools Protocol URL for this computer.
        
        This property looks for a service named "web" in the computer's 
        HTTP services which should provide the Chrome DevTools Protocol endpoint.
        
        Returns:
            URL string to the CDP endpoint, or None if not found
        """
        self.wait_until_ready()
        for service in self.networking.http_services:
            if service.name == "web":
                return service.url
                
        # No CDP service found
        return None
    
    @property
    def display(self) -> str:
        """
        Get the X display identifier being used.
        
        This property returns the X11 display identifier (e.g., ":1") that is used
        for X11-based GUI operations like taking screenshots and simulating user input.
        
        Returns:
            String identifier of the X display
        """
        return getattr(self, '_display', ":1")
    
    @display.setter
    def display(self, value: str) -> None:
        """
        Set the X display to use.
        
        Args:
            value: The X11 display identifier to use (e.g., ":1")
        """
        self._display = value
    
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
            self.exec(f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool mousemove {x} {y} click {b}'")
        except Exception as e:
            raise Exception(f"Failed to click at coordinates ({x}, {y}): {str(e)}") from e
    
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
            self.exec(f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool mousemove {x} {y} click --repeat 2 1'")
        except Exception as e:
            raise Exception(f"Failed to double-click at coordinates ({x}, {y}): {str(e)}") from e
    
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
            self.exec(f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool mousemove {x} {y}'")
        except Exception as e:
            raise Exception(f"Failed to move mouse to coordinates ({x}, {y}): {str(e)}") from e
    
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
            self.exec(f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool click --repeat {count} {button}'")
            
        if scroll_x != 0:
            # Horizontal scrolling (button 6 = left, 7 = right)
            button = 7 if scroll_x > 0 else 6  # 7 = right, 6 = left
            count = abs(scroll_x)
            self.exec(f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool click --repeat {count} {button}'")
    
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
        self.exec(f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool type -- \"{safe_text}\"'")
    
    def key_press(self, key_combo: str) -> None:
        """
        Press the specified key or key combination.
        
        Examples:
            computer.key_press("Return")  # Press Enter
            computer.key_press("ctrl+a")  # Press Ctrl+A
            computer.key_press("alt+F4")  # Press Alt+F4
        """
        self.exec(f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool key {key_combo}'")
    
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
        self.exec(f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool key {combo}'")
    
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
        
        self.exec(f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool mousemove {start_x} {start_y} mousedown 1'")
        
        for point in path[1:]:
            # Use separate variables for x and y to avoid escaping issues
            x = point['x']
            y = point['y']
            self.exec(f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool mousemove {x} {y}'")
        
        self.exec(f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool mouseup 1'")
    
    def screenshot(self) -> bytes:
        """
        Take a screenshot of the desktop and return the raw image data.
        
        Returns:
            Raw image data as bytes
        """
        # Ensure temp dir exists
        self.exec("mkdir -p /tmp/screenshots && chmod 777 /tmp/screenshots")
        
        # Take screenshot as the morph user
        temp_path = "/tmp/screenshots/screenshot.png"
        self.exec(f"sudo -u morph bash -c 'DISPLAY={self.display} import -window root {temp_path}'")
        
        # Return the raw image data
        result = self.exec(f"cat {temp_path} | base64 -w 0")
        return base64.b64decode(result.stdout)
    
    # Async versions of the VNC interaction methods
    async def aclick(self, x: int, y: int, button: str = "left") -> None:
        """Async version of click."""
        button_map = {"left": 1, "middle": 2, "right": 3}
        b = button_map.get(button, 1)
        await self.aexec(f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool mousemove {x} {y} click {b}'")
    
    async def adouble_click(self, x: int, y: int) -> None:
        """Async version of double_click."""
        await self.aexec(f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool mousemove {x} {y} click --repeat 2 1'")
    
    async def amove_mouse(self, x: int, y: int) -> None:
        """Async version of move_mouse."""
        await self.aexec(f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool mousemove {x} {y}'")
    
    async def ascroll(self, x: int, y: int, scroll_x: int, scroll_y: int) -> None:
        """Async version of scroll."""
        # First move mouse to position
        await self.amove_mouse(x, y)
        
        # Then perform scrolling
        if scroll_y != 0:
            # Positive scroll_y scrolls down, negative scrolls up
            button = 5 if scroll_y > 0 else 4  # 5 = down, 4 = up
            count = abs(scroll_y)
            await self.aexec(f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool click --repeat {count} {button}'")
            
        if scroll_x != 0:
            # Horizontal scrolling (button 6 = left, 7 = right)
            button = 7 if scroll_x > 0 else 6  # 7 = right, 6 = left
            count = abs(scroll_x)
            await self.aexec(f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool click --repeat {count} {button}'")
    
    async def a_wait(self, ms: int = 1000) -> None:
        """
        Async version of wait.
        
        Args:
            ms: Number of milliseconds to wait
        """
        seconds = ms / 1000.0
        await asyncio.sleep(seconds)
    
    async def atype_text(self, text: str) -> None:
        """
        Async version of type_text.
        
        Args:
            text: Text to type
            
        Raises:
            Exception: If typing fails
        """
        # Escape single quotes for bash
        safe_text = text.replace("'", "'\\''")
        # Use consistent quoting structure
        await self.aexec(f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool type -- \"{safe_text}\"'")
    
    async def akey_press(self, key_combo: str) -> None:
        """
        Async version of key_press.
        
        Args:
            key_combo: Key or key combination to press (e.g., 'Return', 'ctrl+a')
            
        Raises:
            Exception: If key press fails
        """
        await self.aexec(f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool key {key_combo}'")
    
    async def akey_press_special(self, keys: List[str]) -> None:
        """
        Async version of key_press_special.
        
        Args:
            keys: List of keys to press together (e.g., ["CTRL", "A"])
            
        Raises:
            Exception: If key press fails
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
        await self.aexec(f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool key {combo}'")
    
    async def adrag(self, path: List[Dict[str, int]]) -> None:
        """Async version of drag."""
        if not path:
            return
            
        start_x = path[0]["x"]
        start_y = path[0]["y"]
        
        await self.aexec(f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool mousemove {start_x} {start_y} mousedown 1'")
        
        for point in path[1:]:
            # Use separate variables for x and y to avoid escaping issues
            x = point['x']
            y = point['y']
            await self.aexec(f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool mousemove {x} {y}'")
        
        await self.aexec(f"sudo -u morph bash -c 'DISPLAY={self.display} xdotool mouseup 1'")
    
    async def screenshot_base64(self) -> str:
        """
        Take a screenshot and return base64-encoded PNG data.
        
        Returns:
            Base64-encoded PNG data as a string
        """
        cmd = f"sudo -u morph bash -c 'DISPLAY={self.display} import -window root png:- | base64 -w 0'"
        result = await self.aexec(cmd)
        return result.stdout.strip()
    
    def screenshot_base64_sync(self) -> str:
        """
        Synchronous version of screenshot_base64.
        
        Returns:
            Base64-encoded PNG data as a string
        """
        cmd = f"sudo -u morph bash -c 'DISPLAY={self.display} import -window root png:- | base64 -w 0'"
        result = self.exec(cmd)
        return result.stdout.strip()
    
    async def ascreenshot(self) -> bytes:
        """
        Async version of screenshot.
        
        Returns:
            Raw image data as bytes
        """
        # Get base64 screenshot data
        base64_data = await self.screenshot_base64()
        
        # Convert to binary data and return
        return base64.b64decode(base64_data)
    
    # Override _refresh to properly handle Computer-specific attributes
    def _refresh(self) -> None:
        # Store computer-specific attributes to restore after refresh
        browser = getattr(self, '_browser', None)
        sandbox = getattr(self, '_sandbox', None)
        display = getattr(self, '_display', ":1")
        
        # Refresh using parent method
        super()._refresh()
        
        # Restore computer-specific attributes
        if browser:
            self._browser = browser
        if sandbox:
            self._sandbox = sandbox
        self._display = display
    
    async def _refresh_async(self) -> None:
        # Store computer-specific attributes to restore after refresh
        browser = getattr(self, '_browser', None)
        sandbox = getattr(self, '_sandbox', None)
        display = getattr(self, '_display', ":1")
        
        # Refresh using parent method
        await super()._refresh_async()
        
        # Restore computer-specific attributes
        if browser:
            self._browser = browser
        if sandbox:
            self._sandbox = sandbox
        self._display = display


class ComputerAPI(InstanceAPI):
    """API for managing Computers, which are enhanced Instances with additional capabilities."""
    
    def list(
        self, metadata: Optional[Dict[str, str]] = None
    ) -> List[Computer]:
        """List all computers available to the user."""
        response = self._client._http_client.get(
            "/instance",
            params={f"metadata[{k}]": v for k, v in (metadata or {}).items()},
        )
        return [
            Computer.model_validate(instance)._set_api(self)
            for instance in response.json()["data"]
        ]
    
    async def alist(
        self, metadata: Optional[Dict[str, str]] = None
    ) -> List[Computer]:
        """List all computers available to the user asynchronously."""
        response = await self._client._async_http_client.get(
            "/instance",
            params={f"metadata[{k}]": v for k, v in (metadata or {}).items()},
        )
        return [
            Computer.model_validate(instance)._set_api(self)
            for instance in response.json()["data"]
        ]
    
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
        if snapshot.metadata.get('type') != 'computer-dev':
            raise ValueError(
                f"Snapshot {snapshot_id} is not a valid Computer snapshot. "
                f"Only snapshots with metadata 'type=computer-dev' can be used with Computer API."
            )
        
        return snapshot

    async def _averify_snapshot_is_computer(self, snapshot_id: str) -> Snapshot:
        """Async version of _verify_snapshot_is_computer."""
        # Fetch the snapshot details asynchronously
        snapshot = await self._client.snapshots.aget(snapshot_id)
        
        # Check if the snapshot has the required metadata tag
        if snapshot.metadata.get('type') != 'computer-dev':
            raise ValueError(
                f"Snapshot {snapshot_id} is not a valid Computer snapshot. "
                f"Only snapshots with metadata 'type=computer-dev' can be used with Computer API."
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
        return Computer.model_validate(response.json())._set_api(self)

    async def astart(
        self,
        snapshot_id: str,
        metadata: Optional[Dict[str, str]] = None,
        ttl_seconds: Optional[int] = None,
        ttl_action: Union[None, typing.Literal["stop", "pause"]] = None,
    ) -> Computer:
        """
        Start a new Computer from a snapshot asynchronously.
        
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
        await self._averify_snapshot_is_computer(snapshot_id)
        
        # Start the instance
        response = await self._client._async_http_client.post(
            "/instance",
            params={"snapshot_id": snapshot_id},
            json={
                "metadata": metadata,
                "ttl_seconds": ttl_seconds,
                "ttl_action": ttl_action,
            },
        )
        return Computer.model_validate(response.json())._set_api(self)

    def get(self, computer_id: str) -> Computer:
        """Get a Computer by ID."""
        response = self._client._http_client.get(f"/instance/{computer_id}")
        return Computer.model_validate(response.json())._set_api(self)
    
    async def aget(self, computer_id: str) -> Computer:
        """Get a Computer by ID asynchronously."""
        response = await self._client._async_http_client.get(f"/instance/{computer_id}")
        return Computer.model_validate(response.json())._set_api(self)
