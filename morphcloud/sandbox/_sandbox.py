from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

import requests
import websocket

from morphcloud.api import Instance, MorphCloudClient, Snapshot


class OutputType(Enum):
    """Types of output that can be produced by code execution"""

    TEXT = "text"
    IMAGE = "image"
    ERROR = "error"


@dataclass
class OutputItem:
    """Represents a single output item from code execution"""

    type: OutputType
    data: Any
    metadata: Optional[Dict[str, Any]] = None


class ExecutionResult:
    """Result of code execution with rich output support."""

    def __init__(
        self,
        exit_code: int = 0,
        execution_time: float = 0.0,
        outputs: Optional[List[OutputItem]] = None,
        error: Optional[str] = None,
        stdout: Optional[str] = None,
        stderr: Optional[str] = None,
    ):
        self.exit_code = exit_code
        self.execution_time = execution_time
        self.outputs = outputs or []
        self.error = error
        self.stdout = stdout or ""
        self.stderr = stderr or ""

    @property
    def success(self) -> bool:
        """Check if execution was successful"""
        return self.exit_code == 0 and not self.error

    @property
    def text(self) -> str:
        """Get all text output concatenated"""
        text_outputs = [
            output.data for output in self.outputs if output.type == OutputType.TEXT
        ]
        result = "".join(text_outputs)

        if self.error:
            if result:
                result += f"\n\nError: {self.error}"
            else:
                result = f"Error: {self.error}"

        return result

    def add_output(
        self,
        output_type: OutputType,
        data: Any,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add an output item"""
        self.outputs.append(OutputItem(type=output_type, data=data, metadata=metadata))


class LanguageSupport:
    """Mapping between languages and Jupyter kernels"""

    @classmethod
    def get_supported_languages(cls) -> List[str]:
        """Return list of supported language identifiers"""
        return ["python", "javascript", "bash", "cpp", "rust"]

    @classmethod
    def get_kernel_name(cls, language: str) -> str:
        """Get the Jupyter kernel name for a language"""
        kernel_mapping = {
            "python": "python3",
            "javascript": "javascript",
            "bash": "bash",
            "cpp": "xcpp17",  # xeus-cling C++17 kernel
            "rust": "rust",  # evcxr kernel
        }
        return kernel_mapping.get(language, "python3")  # Default to python3


class SandboxAPI:
    """API for managing Sandboxes, which are Instances with code execution capabilities."""

    def __init__(self, client: MorphCloudClient) -> None:
        """
        Initialize the SandboxAPI.

        Args:
            client: The MorphClient instance
        """
        self._client = client

    def _verify_snapshot_is_sandbox(self, snapshot_id: str) -> Snapshot:
        """
        Verify that a snapshot is meant to be used as a Sandbox.

        Args:
            snapshot_id: ID of the snapshot to verify

        Returns:
            The verified Snapshot object

        Raises:
            ValueError: If the snapshot is not a valid Sandbox snapshot
        """
        # Fetch the snapshot details
        snapshot = self._client.snapshots.get(snapshot_id)

        # Check if the snapshot has the required metadata tag
        if snapshot.metadata.get("type") != "sandbox-dev":
            raise ValueError(
                f"Snapshot {snapshot_id} is not a valid Sandbox snapshot. "
                f"Only snapshots with metadata 'type=sandbox-dev' can be used with Sandbox API."
            )

        return snapshot

    def start(
        self,
        snapshot_id: str,
        metadata: Optional[Dict[str, str]] = None,
        ttl_seconds: Optional[int] = None,
    ) -> Sandbox:
        """
        Start a new Sandbox from a snapshot.

        Args:
            snapshot_id: ID of the snapshot to start
            metadata: Optional metadata to attach to the sandbox
            ttl_seconds: Optional time-to-live in seconds

        Returns:
            A new Sandbox instance

        Raises:
            ValueError: If the snapshot is not a valid Sandbox snapshot
        """
        # Verify the snapshot is meant for Sandbox use
        # self._verify_snapshot_is_sandbox(snapshot_id)

        # Start the instance
        response = self._client._http_client.post(
            "/instance",
            params={"snapshot_id": snapshot_id},
            json={"metadata": metadata, "ttl_seconds": ttl_seconds},
        )

        return Sandbox(
            Instance.model_validate(response.json())._set_api(self._client.instances)
        )

    def get(self, sandbox_id: str) -> Sandbox:
        """Get a Sandbox by ID."""
        response = self._client._http_client.get(f"/instance/{sandbox_id}")
        return Sandbox(
            Instance.model_validate(response.json())._set_api(self._client.instances)
        )

    def list(self, metadata: Optional[Dict[str, str]] = None) -> List[Sandbox]:
        """List all sandboxes available to the user."""
        response = self._client._http_client.get(
            "/instance",
            params={f"metadata[{k}]": v for k, v in (metadata or {}).items()},
        )
        return [
            Sandbox(Instance.model_validate(instance)._set_api(self._client.instances))
            for instance in response.json()["data"]
        ]

    def create_snapshot(
        self,
        sandbox_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> Snapshot:
        """
        Create a snapshot from an existing Sandbox.

        Args:
            sandbox_id: ID of the sandbox to snapshot
            name: Optional name for the snapshot
            description: Optional description
            metadata: Optional metadata dictionary

        Returns:
            The created Snapshot object
        """
        # Merge with sandbox-specific metadata
        full_metadata = {
            "type": "sandbox-dev",
            "description": description or "Jupyter Sandbox snapshot",
            "created_at": datetime.now().isoformat(),
        }

        if metadata:
            full_metadata.update(metadata)

        # Get the instance and create a snapshot
        response = self._client._http_client.post(
            f"/instance/{sandbox_id}/snapshot",
            json={"name": name, "metadata": full_metadata},
        )
        return Snapshot.model_validate(response.json())


class Sandbox:
    """
    A Sandbox is an enhanced Instance with code execution capabilities
    across multiple programming languages.
    """

    def __init__(self, instance: Instance):
        """Initialize sandbox with an instance"""
        self._instance = instance
        self._jupyter_url = None
        self._kernel_ids: Dict[str, str] = {}  # language -> kernel_id
        self._ws_connections: Dict[str, websocket.WebSocket] = (
            {}
        )  # kernel_id -> WebSocket
        self._session_id = str(uuid.uuid4())

    def _set_api(self, api: SandboxAPI) -> Sandbox:
        """Override _set_api to return a Sandbox instead of an Instance."""
        self._instance._set_api(api)  # Set the API for the instance
        return self

    def _refresh(self) -> None:
        """Refresh data from server while preserving Sandbox-specific attributes."""
        # Store Sandbox-specific attributes to restore after refresh
        jupyter_url = self._jupyter_url
        kernel_ids = self._kernel_ids.copy()
        ws_connections = self._ws_connections.copy()
        session_id = self._session_id

        # Refresh using parent method
        self._instance._refresh()

        # Restore Sandbox-specific attributes
        self._jupyter_url = jupyter_url
        self._kernel_ids = kernel_ids
        self._ws_connections = ws_connections
        self._session_id = session_id

    def _discover_existing_kernels(self) -> None:
        """
        Discover and reconnect to existing kernels on the Jupyter server.
        This preserves kernel state when getting an existing sandbox instance.
        """
        try:
            # Get list of existing kernels from Jupyter server
            response = requests.get(f"{self.jupyter_url}/api/kernels", timeout=10.0)
            response.raise_for_status()
            existing_kernels = response.json()
            
            # Map kernel specs to our supported languages
            kernel_to_language = {}
            for language in LanguageSupport.get_supported_languages():
                kernel_name = LanguageSupport.get_kernel_name(language)
                kernel_to_language[kernel_name] = language
            
            # Connect to existing kernels that match our supported languages
            for kernel_info in existing_kernels:
                kernel_id = kernel_info.get("id")
                kernel_spec = kernel_info.get("name")
                
                if kernel_spec in kernel_to_language:
                    language = kernel_to_language[kernel_spec]
                    # Only connect if we don't already have a kernel for this language
                    if language not in self._kernel_ids:
                        self._kernel_ids[language] = kernel_id
                        # Connect WebSocket to existing kernel
                        try:
                            self._connect_websocket(kernel_id)
                        except ConnectionError:
                            # If we can't connect, remove from our tracking
                            del self._kernel_ids[language]
                            
        except requests.RequestException:
            # If we can't discover existing kernels, that's okay
            # New kernels will be created as needed
            pass
        except Exception:
            # Any other error during discovery should not prevent connection
            pass

    def connect(self, timeout_seconds: int = 60) -> Sandbox:
        """Ensure Jupyter service is running and accessible"""
        self.wait_for_jupyter(timeout_seconds)
        self._discover_existing_kernels()
        return self

    def wait_for_jupyter(self, timeout: int = 60) -> bool:
        """
        Wait for Jupyter service to be ready

        Args:
            timeout: Maximum time to wait in seconds

        Returns:
            True if service is ready

        Raises:
            TimeoutError: If service doesn't start within timeout period
            ValueError: If timeout parameter is invalid
        """
        if timeout <= 0:
            raise ValueError("Timeout must be a positive integer")

        start_time = time.time()
        errors = []

        while time.time() - start_time < timeout:
            try:
                response = requests.get(f"{self.jupyter_url}/api/kernels", timeout=5.0)
                if response.status_code == 200:
                    return True
            except requests.RequestException as e:
                # Store specific error but continue trying
                errors.append(f"{type(e).__name__}: {str(e)}")
            except Exception as e:
                # Store unexpected error
                errors.append(f"Unexpected error: {type(e).__name__}: {str(e)}")

            time.sleep(2)

        # Provide error details for debugging
        error_msg = f"Jupyter service failed to start within {timeout} seconds"
        if errors:
            # Only include the last few errors to keep message concise
            error_detail = "; ".join(errors[-3:])
            error_msg += f". Last errors: {error_detail}"

        raise TimeoutError(error_msg)

    @property
    def jupyter_url(self) -> str:
        """Get the Jupyter server URL"""
        if not self._jupyter_url:
            # Find or expose Jupyter service
            for service in self._instance.networking.http_services:
                if service.port == 8888 or service.name == "jupyter":
                    self._jupyter_url = service.url
                    break

            # If not found, expose it
            if not self._jupyter_url:
                self._jupyter_url = self._instance.expose_http_service("jupyter", 8888)

        return self._jupyter_url

    def _ensure_kernel_for_language(self, language: str) -> str:
        """
        Ensure we have a kernel for the specified language and return kernel_id

        Args:
            language: Programming language to get a kernel for

        Returns:
            Kernel ID string

        Raises:
            ValueError: If language is not supported
            ConnectionError: If we can't connect to the kernel
            requests.RequestException: If API request fails
        """
        if language not in self._kernel_ids:
            # Get the appropriate kernel name
            kernel_name = LanguageSupport.get_kernel_name(language)
            if not kernel_name:
                raise ValueError(f"No kernel mapping found for language: {language}")

            try:
                # Start a new kernel via REST API
                response = requests.post(
                    f"{self.jupyter_url}/api/kernels",
                    json={"name": kernel_name},
                    timeout=10.0,  # Set a reasonable timeout
                )
                response.raise_for_status()

                # Parse the response
                try:
                    kernel_info = response.json()
                    if not isinstance(kernel_info, dict) or "id" not in kernel_info:
                        raise ValueError(f"Invalid kernel info returned: {kernel_info}")

                    kernel_id = kernel_info["id"]
                    self._kernel_ids[language] = kernel_id

                    # Connect WebSocket to kernel - use default timeout
                    self._connect_websocket(kernel_id)
                except (json.JSONDecodeError, KeyError) as e:
                    raise ValueError(f"Failed to parse kernel info: {str(e)}")

            except requests.RequestException as e:
                raise ConnectionError(
                    f"Failed to start kernel for {language}: {str(e)}"
                )

        return self._kernel_ids[language]

    def _connect_websocket(self, kernel_id: str, timeout: float = 30.0) -> None:
        """
        Connect to kernel WebSocket

        Args:
            kernel_id: ID of the kernel to connect to
            timeout: Timeout in seconds for the WebSocket connection

        Raises:
            websocket.WebSocketException: If connection fails
            ConnectionError: If the WebSocket can't be established
        """
        # Close existing connection if any
        if kernel_id in self._ws_connections:
            try:
                self._ws_connections[kernel_id].close()
            except websocket.WebSocketException as e:
                print(f"Warning: Error closing previous WebSocket: {str(e)}")
            except Exception as e:
                print(f"Warning: Unexpected error closing WebSocket: {str(e)}")

        # Create WebSocket URL
        ws_url = self.jupyter_url.replace("https://", "wss://").replace(
            "http://", "ws://"
        )
        ws_endpoint = f"{ws_url}/api/kernels/{kernel_id}/channels"

        try:
            # Connect WebSocket with user-specified timeout
            ws = websocket.create_connection(ws_endpoint, timeout=timeout)
            self._ws_connections[kernel_id] = ws
        except websocket.WebSocketTimeoutException:
            # Use a more user-friendly error message
            raise ConnectionError("Unable to connect to code execution environment")
        except websocket.WebSocketConnectionClosedException:
            raise ConnectionError("Connection to code execution environment was closed")
        except Exception:
            raise ConnectionError(
                "Failed to establish connection to code execution environment"
            )

    def run_code(
        self,
        code: str,
        language: str = "python",
        timeout: float = 60.0,
        show_code: bool = False,
    ) -> ExecutionResult:
        """
        Execute code in the specified language via Jupyter kernel

        Args:
            code: The code to execute
            language: Programming language to use (python, javascript, bash, cpp, rust)
            timeout: Maximum execution time in seconds for this specific code execution
            show_code: Whether to print the code being executed (useful for debugging)

        Returns:
            ExecutionResult with execution outputs and status

        Raises:
            ValueError: If code is empty or timeout is invalid
        """
        # Input validation
        if not code or not isinstance(code, str):
            raise ValueError("Code must be a non-empty string")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("Timeout must be a positive number")

        # Optionally show the code being executed (for testing and debugging)
        if show_code:
            print(f"\nExecuting {language} code:")
            print("```")
            print(code)
            print("```")

        start_time = time.time()

        if language not in LanguageSupport.get_supported_languages():
            return ExecutionResult(
                exit_code=1,
                execution_time=time.time() - start_time,
                error=f"Unsupported language: {language}",
            )

        try:
            # Get or create kernel for language
            kernel_id = self._ensure_kernel_for_language(language)

            # Execute code with user's timeout
            result = self._execute_via_websocket(kernel_id, code, timeout)
            result.execution_time = time.time() - start_time

            return result

        except Exception as e:
            # Handle any unexpected errors
            return ExecutionResult(
                exit_code=1,
                execution_time=time.time() - start_time,
                error=f"Execution error: {str(e)}",
            )

    def _execute_via_websocket(
        self, kernel_id: str, code: str, timeout: float
    ) -> ExecutionResult:
        """
        Execute code via WebSocket and collect results

        Args:
            kernel_id: ID of the kernel to execute code on
            code: The code to execute
            timeout: Maximum execution time in seconds

        Returns:
            ExecutionResult with execution outputs and status

        Raises:
            ConnectionError: If WebSocket connection cannot be established
        """
        # Verify we have a valid websocket connection
        ws = self._ws_connections.get(kernel_id)

        # If no connection exists or it's closed, reconnect with the user's timeout
        if not ws or not ws.connected:
            try:
                # Pass the user's timeout to the connection
                self._connect_websocket(kernel_id, timeout)
                ws = self._ws_connections[kernel_id]
                if not ws or not ws.connected:
                    raise ConnectionError("Failed to establish a connected WebSocket")
            except Exception as e:
                return ExecutionResult(
                    exit_code=1,
                    execution_time=0.0,
                    error="Unable to connect to code execution environment. Please try again.",
                )

        # Prepare execution message
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

        # Send message
        ws.send(json.dumps(msg))

        # Process responses
        result = ExecutionResult()
        outputs = []
        stdout_parts = []
        stderr_parts = []

        deadline = time.time() + timeout

        # Keep track of execution state
        got_execute_input = False
        got_output = False
        got_status_idle = False

        original_timeout = ws.gettimeout()
        ws.settimeout(1.0)  # 1 second timeout for recv operations

        try:
            while time.time() < deadline:
                try:
                    response = ws.recv()
                    try:
                        response_data = json.loads(response)
                    except json.JSONDecodeError as json_err:
                        result.error = (
                            f"Failed to parse WebSocket message: {str(json_err)}"
                        )
                        result.exit_code = 1
                        break

                    parent_msg_id = response_data.get("parent_header", {}).get("msg_id")
                    msg_type = response_data.get("header", {}).get("msg_type")

                    # Skip unrelated messages
                    if parent_msg_id != msg_id:
                        continue

                    if msg_type == "execute_input":
                        got_execute_input = True

                    elif msg_type == "stream":
                        got_output = True
                        content = response_data.get("content", {})
                        stream_name = content.get("name", "")
                        text = content.get("text", "")

                        if stream_name == "stdout":
                            stdout_parts.append(text)
                            result.add_output(OutputType.TEXT, text)
                        elif stream_name == "stderr":
                            stderr_parts.append(text)
                            result.add_output(OutputType.ERROR, text)

                    elif msg_type == "execute_result":
                        got_output = True
                        content = response_data.get("content", {})
                        data = content.get("data", {})

                        # Handle text
                        text = data.get("text/plain", "")
                        if text:
                            result.add_output(OutputType.TEXT, text)

                        # Handle images
                        for mime_type in ["image/png", "image/jpeg", "image/svg+xml"]:
                            if mime_type in data:
                                result.add_output(
                                    OutputType.IMAGE,
                                    data[mime_type],
                                    {"mime_type": mime_type},
                                )

                    elif msg_type == "display_data":
                        got_output = True
                        content = response_data.get("content", {})
                        data = content.get("data", {})

                        # Handle text
                        text = data.get("text/plain", "")
                        if text:
                            result.add_output(OutputType.TEXT, text)

                        # Handle images
                        for mime_type in ["image/png", "image/jpeg", "image/svg+xml"]:
                            if mime_type in data:
                                result.add_output(
                                    OutputType.IMAGE,
                                    data[mime_type],
                                    {"mime_type": mime_type},
                                )

                    elif msg_type == "error":
                        got_output = True
                        content = response_data.get("content", {})
                        ename = content.get("ename", "")
                        evalue = content.get("evalue", "")
                        traceback = content.get("traceback", [])

                        error_text = f"{ename}: {evalue}"
                        if traceback:
                            error_text += "\n" + "\n".join(traceback)

                        result.error = error_text
                        result.exit_code = 1
                        stderr_parts.append(error_text)

                    elif msg_type == "status":
                        if (
                            response_data.get("content", {}).get("execution_state")
                            == "idle"
                        ):
                            got_status_idle = True

                    # Check if we can finish processing
                    if got_status_idle and (got_output or got_execute_input):
                        # Small delay to catch any pending messages
                        time.sleep(0.1)
                        break

                except websocket.WebSocketTimeoutException:
                    # If we've seen idle but no output, we might be done (empty execution)
                    if got_status_idle and got_execute_input:
                        break
                    # Continue listening if we're still within timeout
                    continue
                except websocket.WebSocketConnectionClosedException as ws_err:
                    result.error = (
                        f"WebSocket connection closed unexpectedly: {str(ws_err)}"
                    )
                    result.exit_code = 1
                    break
                except Exception as e:
                    result.error = f"Error processing response: {str(e)}"
                    result.exit_code = 1
                    break

        except websocket.WebSocketException as ws_err:
            result.error = f"WebSocket error: {str(ws_err)}"
            result.exit_code = 1
        except Exception as e:
            result.error = f"Unexpected error during execution: {str(e)}"
            result.exit_code = 1

        finally:
            # Restore original timeout
            if original_timeout is not None:
                ws.settimeout(original_timeout)

        # Check for timeout
        if time.time() >= deadline and not got_status_idle:
            result.error = f"Execution timed out after {timeout} seconds"
            result.exit_code = 124  # Standard timeout exit code

        # Set stdout/stderr
        result.stdout = "".join(stdout_parts)
        result.stderr = "".join(stderr_parts)

        return result

    def reset_kernel(self, language: str) -> bool:
        """Reset the kernel for a specific language"""
        if language in self._kernel_ids:
            kernel_id = self._kernel_ids[language]

            # Close WebSocket if it exists
            if kernel_id in self._ws_connections:
                try:
                    self._ws_connections[kernel_id].close()
                except Exception:
                    pass
                del self._ws_connections[kernel_id]

            # Restart kernel via REST API
            response = requests.post(
                f"{self.jupyter_url}/api/kernels/{kernel_id}/restart"
            )
            response.raise_for_status()

            # Reconnect WebSocket
            self._connect_websocket(kernel_id)

            return True

        return False

    def close(self) -> None:
        """
        Close all connections and clean up resources

        This method ensures all WebSocket connections are closed properly
        and resources are released. It should be called when the Sandbox
        is no longer needed to avoid resource leaks.
        """
        # Track any errors during closing
        close_errors = []

        # Close all WebSockets
        for kernel_id, ws in list(self._ws_connections.items()):
            try:
                if ws and hasattr(ws, "connected") and ws.connected:
                    ws.close()
            except websocket.WebSocketException as e:
                close_errors.append(
                    f"Error closing WebSocket for kernel {kernel_id}: {str(e)}"
                )
            except Exception as e:
                close_errors.append(
                    f"Unexpected error closing WebSocket for kernel {kernel_id}: {str(e)}"
                )
            finally:
                # Ensure we remove from dict even if close fails
                self._ws_connections.pop(kernel_id, None)

        # Logging errors but not raising to ensure cleanup completes
        if close_errors:
            print("Warnings during sandbox cleanup:")
            for error in close_errors:
                print(f"- {error}")

        # Clear all references
        self._ws_connections.clear()
        self._jupyter_url = None  # Allow for reconnection if needed

    def branch(self, count: int = 1) -> List[Sandbox]:
        """Create multiple copies of this Sandbox."""
        _, instances = self._instance.branch(count=count)
        return [
            Sandbox(Instance.model_validate(instance)._set_api(self._instance._api))
            for instance in instances
        ]

    def shutdown(self) -> None:
        """Shut down the sandbox instance."""
        self._instance.stop()

    def snapshot(
        self,
        name: Optional[str] = None,
        description: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> Snapshot:
        """
        Create a snapshot of this sandbox's current state.

        Args:
            name: Optional name for the snapshot
            description: Optional description
            metadata: Optional metadata dictionary

        Returns:
            The created Snapshot object
        """
        # Get the API client from the instance
        client = self._instance._api._client
        sandbox_api = SandboxAPI(client)

        # Use the API to create the snapshot
        return sandbox_api.create_snapshot(
            sandbox_id=self._instance.id,
            name=name,
            description=description,
            metadata=metadata,
        )

    def __enter__(self) -> Sandbox:
        """Enter context manager."""
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """
        Exit context manager and clean up resources.

        This method is called when exiting a 'with' block and ensures
        proper cleanup of resources even if an exception occurred.

        Args:
            exc_type: Exception type if an exception was raised in the context
            exc_val: Exception value if an exception was raised
            exc_tb: Exception traceback if an exception was raised
        """
        try:
            # First try to close all connections
            self.close()
        finally:
            # Always attempt to shut down the instance, even if close() failed
            try:
                self.shutdown()
            except Exception as e:
                print(f"Warning: Error during sandbox shutdown: {str(e)}")
                # We don't re-raise as we want to ensure the context manager exits cleanly

    @classmethod
    def new(
        cls,
        client: Optional[MorphCloudClient] = None,
        ttl_seconds: Optional[int] = 600,
        snapshot_id: Optional[str] = None,
    ) -> Sandbox:
        """
        Create a new Sandbox with Jupyter and required kernels.

        Args:
            client: Optional MorphCloudClient instance
            ttl_seconds: Optional time-to-live in seconds
            snapshot_id: Optional snapshot ID to start from

        Returns:
            A new Sandbox instance
        """
        client = client or MorphCloudClient()
        sandbox_api = SandboxAPI(client)

        if snapshot_id:
            # Use the specified snapshot, verifying it's a valid sandbox snapshot
            try:
                sandbox_api._verify_snapshot_is_sandbox(snapshot_id)
                snapshot_to_use = snapshot_id
            except ValueError as e:
                raise ValueError(f"The specified snapshot is not a valid sandbox: {e}")
        else:
            # Look for existing sandbox snapshots
            snapshots = client.snapshots.list(metadata={"type": "sandbox-dev"})

            if not snapshots:
                # Alert the user
                print("No sandbox snapshot found with tag 'type=sandbox-dev'.")
                print("Performing one-time setup...")
                # Create a base snapshot with Jupyter environment
                base_snapshot = client.snapshots.create(
                    vcpus=1,
                    memory=2048,
                    disk_size=8192,
                    image_id="morphvm-sandbox",
                    digest="sandbox-dev",
                )

                # Start a temporary instance from the base snapshot
                print("Starting temporary instance to initialize kernels...")
                instance = client.instances.start(
                    snapshot_id=base_snapshot.id,
                    metadata={"purpose": "kernel-initialization"},
                    ttl_seconds=300,  # Short TTL for setup
                )

                # Expose Jupyter service
                jupyter_url = None
                for service in instance.networking.http_services:
                    if service.port == 8888 or service.name == "jupyter":
                        jupyter_url = service.url
                        break

                if not jupyter_url:
                    jupyter_url = instance.expose_http_service("jupyter", 8888)

                print("Initializing kernels for all supported languages...")

                # Wait for Jupyter to be ready (silently)
                start_time = time.time()
                jupyter_ready = False
                while time.time() - start_time < 90:  # 1.5 minute timeout
                    try:
                        response = requests.get(
                            f"{jupyter_url}/api/kernels", timeout=5.0
                        )
                        if response.status_code == 200:
                            jupyter_ready = True
                            break
                    except Exception:
                        pass
                    time.sleep(2)

                if not jupyter_ready:
                    raise TimeoutError("Jupyter service failed to start within timeout")

                # Initialize all kernels
                for language in LanguageSupport.get_supported_languages():
                    kernel_name = LanguageSupport.get_kernel_name(language)
                    print(
                        f"Starting {language} kernel ({kernel_name})...",
                        end="",
                        flush=True,
                    )

                    try:
                        # Start a new kernel via REST API
                        response = requests.post(
                            f"{jupyter_url}/api/kernels",
                            json={"name": kernel_name},
                            timeout=10.0,
                        )
                        response.raise_for_status()
                        kernel_info = response.json()
                        kernel_id = kernel_info["id"]
                        print(f" ✓ (kernel_id: {kernel_id[:8]}...)")
                    except Exception as e:
                        print(f" ✗ Error: {str(e)}")

                # Now that setup is complete, create a snapshot with the correct syntax
                print("Creating snapshot with initialized kernels...")
                response = client._http_client.post(
                    f"/instance/{instance.id}/snapshot",
                    json={
                        "name": "sandbox-initialized",
                        "metadata": {
                            "type": "sandbox-dev",
                            "kernels_initialized": "true",
                            "languages": ",".join(
                                LanguageSupport.get_supported_languages()
                            ),
                            "created_at": datetime.now().isoformat(),
                            "created_by": "sandbox",
                        },
                    },
                )
                initialized_snapshot = Snapshot.model_validate(response.json())

                # Shutdown temporary instance
                print("Shutting down temporary setup instance...")
                instance.stop()

                # Use the initialized snapshot
                snapshot_to_use = initialized_snapshot.id
            else:
                # Use the first available snapshot
                snapshot_to_use = snapshots[0].id

        # Start a new sandbox instance using the determined snapshot
        sandbox = sandbox_api.start(
            snapshot_id=snapshot_to_use,
            metadata={"type": "sandbox-dev"},
            ttl_seconds=ttl_seconds,
        )

        # Connect and return the sandbox
        # return sandbox.connect()
        return sandbox
