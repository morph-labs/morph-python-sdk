# morphcloud/api.py

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
import typing
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache

import httpx
from pydantic import BaseModel, Field, PrivateAttr
# Import Rich for fancy printing
from rich.console import Console
from rich.live import Live
from rich.panel import Panel

from morphcloud._utils import StrEnum

# Global console instance
console = Console()


@lru_cache
def _dummy_key():
    import io

    import paramiko

    key = paramiko.RSAKey.generate(1024)
    key_file = io.StringIO()
    key.write_private_key(key_file)
    key_file.seek(0)
    pkey = paramiko.RSAKey.from_private_key(key_file)

    return pkey


class ApiError(Exception):
    """Custom exception for Morph API errors that includes the response body"""

    def __init__(self, message: str, status_code: int, response_body: str):
        self.status_code = status_code
        self.response_body = response_body
        super().__init__(
            f"{message}\nStatus Code: {status_code}\nResponse Body: {response_body}"
        )


class ApiClient(httpx.Client):
    def raise_for_status(self, response: httpx.Response) -> None:
        """Custom error handling that includes the response body in the error message"""
        if response.is_error:
            try:
                error_body = json.dumps(response.json(), indent=2)
            except Exception:
                error_body = response.text

            message = f"HTTP Error {response.status_code} for url '{response.url}'"
            raise ApiError(message, response.status_code, error_body)

    def request(self, *args, **kwargs) -> httpx.Response:
        """Override request method to use our custom error handling"""
        response = super().request(*args, **kwargs)
        if response.is_error:
            self.raise_for_status(response)
        return response


class AsyncApiClient(httpx.AsyncClient):
    async def raise_for_status(self, response: httpx.Response) -> None:
        """Custom error handling that includes the response body in the error message"""
        if response.is_error:
            try:
                error_body = json.dumps(response.json(), indent=2)
            except Exception:
                error_body = response.text

            message = f"HTTP Error {response.status_code} for url '{response.url}'"
            raise ApiError(message, response.status_code, error_body)

    async def request(self, *args, **kwargs) -> httpx.Response:
        """Override request method to use our custom error handling"""
        response = await super().request(*args, **kwargs)
        if response.is_error:
            await self.raise_for_status(response)
        return response


class MorphCloudClient:
    def __init__(
        self,
        api_key: typing.Optional[str] = None,
        base_url: typing.Optional[str] = None,
    ):
        self.base_url = base_url or os.environ.get(
            "MORPH_BASE_URL", "https://cloud.morph.so/api"
        )
        self.api_key = api_key or os.environ.get("MORPH_API_KEY")
        if not self.api_key:
            raise ValueError(
                "API key must be provided or set in MORPH_API_KEY environment variable"
            )

        self._http_client = ApiClient(
            base_url=self.base_url,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            timeout=None,
        )
        self._async_http_client = AsyncApiClient(
            base_url=self.base_url,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            timeout=None,
        )

    @property
    def instances(self) -> InstanceAPI:
        return InstanceAPI(self)

    @property
    def snapshots(self) -> SnapshotAPI:
        return SnapshotAPI(self)

    @property
    def images(self) -> ImageAPI:
        return ImageAPI(self)

    # Add this property to the MorphCloudClient class
    @property
    def computers(self):
        """Access the API for enhanced instance capabilities."""
        from morphcloud.computer import ComputerAPI

        return ComputerAPI(self)


class BaseAPI:
    def __init__(self, client: MorphCloudClient):
        self._client = client


class ImageAPI(BaseAPI):
    def list(self) -> typing.List[Image]:
        """List all base images available to the user."""
        response = self._client._http_client.get("/image")
        return [
            Image.model_validate(image)._set_api(self)
            for image in response.json()["data"]
        ]

    async def alist(self) -> typing.List[Image]:
        """List all base images available to the user."""
        response = await self._client._async_http_client.get("/image")
        return [
            Image.model_validate(image)._set_api(self)
            for image in response.json()["data"]
        ]


class Image(BaseModel):
    id: str = Field(
        ..., description="Unique identifier for the base image, like img_xxxx"
    )
    object: typing.Literal["image"] = Field(
        "image", description="Object type, always 'image'"
    )
    name: str = Field(..., description="Name of the base image")
    description: typing.Optional[str] = Field(
        None, description="Description of the base image"
    )
    disk_size: int = Field(..., description="Size of the base image in bytes")
    created: int = Field(
        ..., description="Unix timestamp of when the base image was created"
    )

    _api: ImageAPI = PrivateAttr()

    def _set_api(self, api: ImageAPI) -> Image:
        self._api = api
        return self


class SnapshotStatus(StrEnum):
    PENDING = "pending"
    READY = "ready"
    FAILED = "failed"
    DELETING = "deleting"
    DELETED = "deleted"


class ResourceSpec(BaseModel):
    vcpus: int = Field(..., description="VCPU Count of the snapshot")
    memory: int = Field(..., description="Memory of the snapshot in megabytes")
    disk_size: int = Field(..., description="Size of the snapshot in megabytes")


class SnapshotRefs(BaseModel):
    image_id: str


class SnapshotAPI:
    def __init__(self, client: MorphCloudClient):
        self._client = client

    def list(
        self,
        digest: typing.Optional[str] = None,
        metadata: typing.Optional[typing.Dict[str, str]] = None,
    ) -> typing.List[Snapshot]:
        """List all snapshots available to the user.

        Parameters:
            digest: Optional digest to filter snapshots by.
            metadata: Optional metadata to filter snapshots by."""
        params = {}
        if digest is not None:
            params["digest"] = digest
        if metadata is not None:
            for k, v in metadata.items():
                params[f"metadata[{k}]"] = v
        response = self._client._http_client.get("/snapshot", params=params)
        return [
            Snapshot.model_validate(snapshot)._set_api(self)
            for snapshot in response.json()["data"]
        ]

    async def alist(
        self,
        digest: typing.Optional[str] = None,
        metadata: typing.Optional[typing.Dict[str, str]] = None,
    ) -> typing.List[Snapshot]:
        """List all snapshots available to the user.

        Parameters:
            digest: Optional digest to filter snapshots by.
            metadata: Optional metadata to filter snapshots by."""
        params = {}
        if digest is not None:
            params["digest"] = digest
        if metadata is not None:
            for k, v in metadata.items():
                params[f"metadata[{k}]"] = v
        response = await self._client._async_http_client.get("/snapshot", params=params)
        return [
            Snapshot.model_validate(snapshot)._set_api(self)
            for snapshot in response.json()["data"]
        ]

    def create(
        self,
        image_id: typing.Optional[str] = None,
        vcpus: typing.Optional[int] = None,
        memory: typing.Optional[int] = None,
        disk_size: typing.Optional[int] = None,
        digest: typing.Optional[str] = None,
        metadata: typing.Optional[typing.Dict[str, str]] = None,
    ) -> Snapshot:
        """Create a new snapshot from a base image and a machine configuration.

        Parameters:
            image_id: The ID of the base image to use.
            vcpus: The number of virtual CPUs for the snapshot.
            memory: The amount of memory (in MB) for the snapshot.
            disk_size: The size of the snapshot (in MB).
            digest: Optional digest for the snapshot. If provided, it will be used to identify the snapshot. If a snapshot with the same digest already exists, it will be returned instead of creating a new one.
            metadata: Optional metadata to attach to the snapshot."""
        body = {}
        if image_id is not None:
            body["image_id"] = image_id
        if vcpus is not None:
            body["vcpus"] = vcpus
        if memory is not None:
            body["memory"] = memory
        if disk_size is not None:
            body["disk_size"] = disk_size
        if digest is not None:
            body["digest"] = digest
        if metadata is not None:
            body["metadata"] = metadata
        response = self._client._http_client.post("/snapshot", json=body)
        return Snapshot.model_validate(response.json())._set_api(self)

    async def acreate(
        self,
        image_id: typing.Optional[str] = None,
        vcpus: typing.Optional[int] = None,
        memory: typing.Optional[int] = None,
        disk_size: typing.Optional[int] = None,
        digest: typing.Optional[str] = None,
        metadata: typing.Optional[typing.Dict[str, str]] = None,
    ) -> Snapshot:
        """Create a new snapshot from a base image and a machine configuration.

        Parameters:
            image_id: The ID of the base image to use.
            vcpus: The number of virtual CPUs for the snapshot.
            memory: The amount of memory (in MB) for the snapshot.
            disk_size: The size of the snapshot (in MB).
            digest: Optional digest for the snapshot. If provided, it will be used to identify the snapshot. If a snapshot with the same digest already exists, it will be returned instead of creating a new one.
            metadata: Optional metadata to attach to the snapshot."""
        body = {}
        if image_id is not None:
            body["image_id"] = image_id
        if vcpus is not None:
            body["vcpus"] = vcpus
        if memory is not None:
            body["memory"] = memory
        if disk_size is not None:
            body["disk_size"] = disk_size
        if digest is not None:
            body["digest"] = digest
        if metadata is not None:
            body["metadata"] = metadata
        response = await self._client._async_http_client.post("/snapshot", json=body)
        return Snapshot.model_validate(response.json())._set_api(self)

    def get(self, snapshot_id: str) -> Snapshot:
        response = self._client._http_client.get(f"/snapshot/{snapshot_id}")
        return Snapshot.model_validate(response.json())._set_api(self)

    async def aget(self, snapshot_id: str) -> Snapshot:
        response = await self._client._async_http_client.get(f"/snapshot/{snapshot_id}")
        return Snapshot.model_validate(response.json())._set_api(self)


class Snapshot(BaseModel):
    id: str = Field(
        ..., description="Unique identifier for the snapshot, e.g. snapshot_xxxx"
    )
    object: typing.Literal["snapshot"] = Field(
        "snapshot", description="Object type, always 'snapshot'"
    )
    created: int = Field(..., description="Unix timestamp of snapshot creation")
    status: SnapshotStatus = Field(..., description="Snapshot status")
    spec: ResourceSpec = Field(..., description="Resource specifications")
    refs: SnapshotRefs = Field(..., description="Referenced resources")
    digest: typing.Optional[str] = Field(
        default=None, description="User provided digest"
    )
    metadata: typing.Dict[str, str] = Field(
        default_factory=dict, description="User provided metadata"
    )

    _api: SnapshotAPI = PrivateAttr()

    def _set_api(self, api: SnapshotAPI) -> Snapshot:
        self._api = api
        return self

    def delete(self) -> None:
        response = self._api._client._http_client.delete(f"/snapshot/{self.id}")
        response.raise_for_status()

    async def adelete(self) -> None:
        response = await self._api._client._async_http_client.delete(
            f"/snapshot/{self.id}"
        )
        response.raise_for_status()

    def set_metadata(self, metadata: typing.Dict[str, str]) -> None:
        response = self._api._client._http_client.post(
            f"/snapshot/{self.id}/metadata", json=metadata
        )
        response.raise_for_status()
        self._refresh()

    async def aset_metadata(self, metadata: typing.Dict[str, str]) -> None:
        response = await self._api._client._async_http_client.post(
            f"/snapshot/{self.id}/metadata", json=metadata
        )
        response.raise_for_status()
        await self._refresh_async()

    def _refresh(self) -> None:
        refreshed = self._api.get(self.id)
        updated = type(self).model_validate(refreshed.model_dump())
        for key, value in updated.__dict__.items():
            setattr(self, key, value)

    async def _refresh_async(self) -> None:
        refreshed = await self._api.aget(self.id)
        updated = type(self).model_validate(refreshed.model_dump())
        for key, value in updated.__dict__.items():
            setattr(self, key, value)

    @staticmethod
    def compute_chain_hash(parent_chain_hash: str, effect_identifier: str) -> str:
        """
        Computes a chain hash based on the parent's chain hash and an effect identifier.
        The effect identifier is typically derived from the function name and its arguments.
        """
        hasher = hashlib.sha256()
        hasher.update(parent_chain_hash.encode("utf-8"))
        hasher.update(b"\n")
        hasher.update(effect_identifier.encode("utf-8"))
        return hasher.hexdigest()

    def _run_command_effect(
        self, instance: Instance, command: str, background: bool, get_pty: bool
    ) -> None:
        """
        Executes a shell command on the given instance, handling ANSI escape codes properly.
        If background is True, the command is run without waiting for completion.
        Thread-safe implementation for use in ThreadPool environments.
        """
        import re
        import threading

        from rich.console import Console
        from rich.text import Text

        # Create a thread ID for logging
        thread_id = threading.get_ident()
        thread_name = f"Thread-{thread_id}"

        # Create console lock to prevent output interleaving
        if not hasattr(console, "_output_lock"):
            console._output_lock = threading.Lock()

        # ANSI escape code regex pattern
        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

        ssh_client = instance.ssh_connect()
        try:
            channel = ssh_client.get_transport().open_session()
            if get_pty:
                channel.get_pty(width=120, height=40)
            channel.exec_command(command)

            if background:
                with console._output_lock:
                    console.print(
                        f"[blue]Command is running in the background:[/blue] {command}"
                    )
                channel.close()
                return

            with console._output_lock:
                console.print(
                    f"[bold blue]🔧 {thread_name}:[/bold blue] [yellow]{command}[/yellow]"
                )

            # Buffer for collecting line-by-line output
            line_buffer = ""
            full_output = ""

            # Process the output
            while not channel.exit_status_ready():
                if channel.recv_ready():
                    data = channel.recv(1024).decode("utf-8", errors="replace")
                    if data:
                        full_output += data

                        # Process data line by line
                        line_buffer += data
                        lines = line_buffer.split("\n")

                        # All complete lines can be printed
                        if len(lines) > 1:
                            with console._output_lock:
                                for line in lines[:-1]:
                                    if line:
                                        # Strip ANSI escape codes when prefixing thread name
                                        # but pass the original line (with ANSI codes) to console.print
                                        clean_line = ansi_escape.sub("", line)
                                        # Only add prefix if line isn't empty after stripping ANSI
                                        if clean_line.strip():
                                            # Use print directly to preserve ANSI codes
                                            print(f"{thread_name}: {line}")
                                        else:
                                            print(line)
                            # Keep the last partial line in the buffer
                            line_buffer = lines[-1]
                time.sleep(0.1)

            # Get any remaining output
            while channel.recv_ready():
                data = channel.recv(1024).decode("utf-8", errors="replace")
                if data:
                    full_output += data
                    line_buffer += data

            # Print any remaining content in the line buffer
            if line_buffer:
                lines = line_buffer.split("\n")
                with console._output_lock:
                    for line in lines:
                        if line:
                            clean_line = ansi_escape.sub("", line)
                            if clean_line.strip():
                                print(f"{thread_name}: {line}")
                            else:
                                print(line)

            # Check exit code
            exit_code = channel.recv_exit_status()

            # Print a summary of the command execution
            with console._output_lock:
                if exit_code == 0:
                    console.print(
                        f"[bold green]✅ {thread_name}: Command completed successfully[/bold green]"
                    )
                else:
                    console.print(
                        f"[bold red]⚠️ {thread_name}: Command exited with code [red]{exit_code}[/red][/bold red]"
                    )

            channel.close()

            if exit_code != 0:
                raise RuntimeError(
                    f"Command `{command}` failed with exit code {exit_code}."
                )

        finally:
            ssh_client.close()

    def _cache_effect(
        self,
        fn: typing.Callable[[Instance], None],
        *args,
        **kwargs,
    ) -> Snapshot:
        """
        Generic caching mechanism based on a "chain hash":
          - Computes a unique hash from the parent's chain hash (self.digest or self.id)
            and the function name + arguments.
          - Prints out the effect function and arguments.
          - If a snapshot already exists with that chain hash in its .digest, returns it.
          - Otherwise, starts an instance from this snapshot, applies `fn` (with *args/**kwargs),
            snapshots the instance (embedding that chain hash in `digest`), and returns it.
        """

        # 1) Print out which function and args/kwargs are being applied
        console.print(
            "\n[bold black on white]Effect function:[/bold black on white] "
            f"[cyan]{fn.__name__}[/cyan]\n"
            f"[bold white]args:[/bold white] [yellow]{args}[/yellow]   "
            f"[bold white]kwargs:[/bold white] [yellow]{kwargs}[/yellow]\n"
        )

        # 2) Determine the parent chain hash:
        parent_chain_hash = self.digest or self.id

        # 3) Build an effect identifier string from the function name + the stringified arguments.
        effect_identifier = fn.__name__ + str(args) + str(kwargs)

        # 4) Compute the new chain hash
        new_chain_hash = self.compute_chain_hash(parent_chain_hash, effect_identifier)

        # 5) Check if there's already a snapshot with that digest
        candidates = self._api.list(digest=new_chain_hash)
        if candidates:
            console.print(
                f"[bold green]✅ Using cached snapshot[/bold green] "
                f"with digest [white]{new_chain_hash}[/white] "
                f"for effect [yellow]{fn.__name__}[/yellow]."
            )
            return candidates[0]

        # 6) Otherwise, apply the effect on a fresh instance from this snapshot
        console.print(
            f"[bold magenta]🚀 Building new snapshot[/bold magenta] "
            f"with digest [white]{new_chain_hash}[/white]."
        )
        instance = self._api._client.instances.start(self.id)
        try:
            instance.wait_until_ready(timeout=300)
            fn(instance, *args, **kwargs)  # Actually run the effect
            # 7) Snapshot the instance, passing digest=new_chain_hash to store the chain hash
            new_snapshot = instance.snapshot(digest=new_chain_hash)
        finally:
            instance.stop()

        # 8) Return the newly created snapshot
        console.print(
            f"[bold blue]🎉 New snapshot created[/bold blue] "
            f"with digest [white]{new_chain_hash}[/white].\n"
        )
        return new_snapshot

    def setup(self, command: str) -> Snapshot:
        """
        Deprecated, use `Snapshot.exec` instead
        """
        return self._cache_effect(
            fn=self._run_command_effect,
            command=command,
            background=False,
            get_pty=True,
        )

    def exec(self, command: str) -> Snapshot:
        """
        Run a command (with get_pty=True, in the foreground) on top of this snapshot.
        Returns a new snapshot that includes the modifications from that command.
        Uses _cache_effect(...) to avoid re-building if an identical effect was applied before.
        """
        return self.setup(command)

    async def aexec(self, command: str) -> Snapshot:
        return await self.asetup(command)

    async def asetup(self, command: str) -> Snapshot:
        return await asyncio.to_thread(self.setup, command)

    def upload(
        self, local_path: str, remote_path: str, recursive: bool = False
    ) -> Snapshot:
        """
        Chain-hash aware upload operation on this snapshot.
        1. Checks if a matching effect (upload with these arguments) is already cached.
        2. If not, spawns an instance, calls instance.upload(...), and snapshots the result.
        """

        def _upload_effect(instance: Instance, local_path, remote_path, recursive):
            instance.upload(local_path, remote_path, recursive=recursive)

        return self._cache_effect(
            fn=_upload_effect,
            local_path=local_path,
            remote_path=remote_path,
            recursive=recursive,
        )

    def download(
        self, remote_path: str, local_path: str, recursive: bool = False
    ) -> Snapshot:
        """
        Chain-hash aware download operation on this snapshot.
        1. Checks if a matching effect (download with these arguments) is already cached.
        2. If not, spawns an instance, calls instance.download(...), and snapshots the result.
        """

        def _download_effect(instance: Instance, remote_path, local_path, recursive):
            instance.download(remote_path, local_path, recursive=recursive)

        return self._cache_effect(
            fn=_download_effect,
            remote_path=remote_path,
            local_path=local_path,
            recursive=recursive,
        )

    async def aupload(
        self, local_path: str, remote_path: str, recursive: bool = False
    ) -> Snapshot:
        """
        Asynchronously perform a chain-hash aware upload operation on this snapshot.
        Internally calls the synchronous self.upload(...) in a background thread.
        """
        return await asyncio.to_thread(self.upload, local_path, remote_path, recursive)

    async def adownload(
        self, remote_path: str, local_path: str, recursive: bool = False
    ) -> Snapshot:
        """
        Asynchronously perform a chain-hash aware download operation on this snapshot.
        Internally calls the synchronous self.download(...) in a background thread.
        """
        return await asyncio.to_thread(
            self.download, remote_path, local_path, recursive
        )

    def as_container(
        self,
        image: str,
        container_name: str = "container",
        command: str = "tail -f /dev/null",
        container_args: typing.Optional[typing.List[str]] = None,
        ports: typing.Optional[typing.Dict[int, int]] = None,
        volumes: typing.Optional[typing.List[str]] = None,
        env: typing.Optional[typing.Dict[str, str]] = None,
        restart_policy: str = "unless-stopped",
    ) -> Snapshot:
        """
        Configure a snapshot so that instances started from it will automatically
        redirect all SSH connections to a Docker container.

        This method:
        1. Starts a temporary instance from this snapshot
        2. Ensures Docker is running on the instance
        3. Runs the specified Docker container
        4. Configures SSH to redirect all commands to the container
        5. Creates a new snapshot with these changes
        6. Returns the new snapshot

        After starting an instance from the returned snapshot, all SSH connections
        and commands will be passed through to the container rather than the host VM.

        Parameters:
            image: The Docker image to run (e.g. "ubuntu:latest", "postgres:13")
            container_name: The name to give the container (default: "container")
            command: The command to run in the container (default: "tail -f /dev/null")
            container_args: Additional arguments to pass to "docker run"
            ports: Dictionary mapping host ports to container ports
            volumes: List of volume mounts (e.g. ["/host/path:/container/path"])
            env: Dictionary of environment variables to set in the container
            restart_policy: Container restart policy (default: "unless-stopped")

        Returns:
            A new snapshot configured to automatically start and use the container
        """

        # The function to apply on the instance that will be used for caching
        def _container_effect(
            instance: Instance,
            image,
            container_name="container",
            command="tail -f /dev/null",
            container_args=None,
            ports=None,
            volumes=None,
            env=None,
            restart_policy="unless-stopped",
        ):
            # Call the existing instance.as_container method
            instance.as_container(
                image=image,
                container_name=container_name,
                command=command,
                container_args=container_args,
                ports=ports,
                volumes=volumes,
                env=env,
                restart_policy=restart_policy,
            )

        # Use the existing caching mechanism to avoid rebuilding the same snapshot
        # All parameters are passed to _cache_effect to ensure proper cache hashing
        return self._cache_effect(
            fn=_container_effect,
            image=image,
            container_name=container_name,
            command=command,
            container_args=container_args,
            ports=ports,
            volumes=volumes,
            env=env,
            restart_policy=restart_policy,
        )

    async def aas_container(
        self,
        image: str,
        container_name: str = "container",
        command: str = "tail -f /dev/null",
        container_args: typing.Optional[typing.List[str]] = None,
        ports: typing.Optional[typing.Dict[int, int]] = None,
        volumes: typing.Optional[typing.List[str]] = None,
        env: typing.Optional[typing.Dict[str, str]] = None,
        restart_policy: str = "unless-stopped",
    ) -> Snapshot:
        """
        Asynchronous version: Configure a snapshot so that instances started from it will
        automatically redirect all SSH connections to a Docker container.

        This method:
        1. Starts a temporary instance from this snapshot
        2. Ensures Docker is running on the instance
        3. Runs the specified Docker container
        4. Configures SSH to redirect all commands to the container
        5. Creates a new snapshot with these changes
        6. Returns the new snapshot

        After starting an instance from the returned snapshot, all SSH connections
        and commands will be passed through to the container rather than the host VM.

        Parameters:
            image: The Docker image to run (e.g. "ubuntu:latest", "postgres:13")
            container_name: The name to give the container (default: "container")
            command: The command to run in the container (default: "tail -f /dev/null")
            container_args: Additional arguments to pass to "docker run"
            ports: Dictionary mapping host ports to container ports
            volumes: List of volume mounts (e.g. ["/host/path:/container/path"])
            env: Dictionary of environment variables to set in the container
            restart_policy: Container restart policy (default: "unless-stopped")

        Returns:
            A new snapshot configured to automatically start and use the container
        """
        # Run the synchronous version in a thread
        return await asyncio.to_thread(
            self.as_container,
            image=image,
            container_name=container_name,
            command=command,
            container_args=container_args,
            ports=ports,
            volumes=volumes,
            env=env,
            restart_policy=restart_policy,
        )


class InstanceStatus(StrEnum):
    PENDING = "pending"
    READY = "ready"
    PAUSED = "paused"
    SAVING = "saving"
    ERROR = "error"


class InstanceHttpService(BaseModel):
    name: str
    port: int
    url: str


class InstanceNetworking(BaseModel):
    internal_ip: typing.Optional[str] = None
    http_services: typing.List[InstanceHttpService] = Field(default_factory=list)


class InstanceRefs(BaseModel):
    snapshot_id: str
    image_id: str


class InstanceExecResponse(BaseModel):
    exit_code: int
    stdout: str
    stderr: str


class InstanceAPI(BaseAPI):
    def list(
        self, metadata: typing.Optional[typing.Dict[str, str]] = None
    ) -> typing.List[Instance]:
        """List all instances available to the user.

        Parameters:
            metadata: Optional metadata to filter instances by."""
        response = self._client._http_client.get(
            "/instance",
            params={f"metadata[{k}]": v for k, v in (metadata or {}).items()},
        )
        return [
            Instance.model_validate(instance)._set_api(self)
            for instance in response.json()["data"]
        ]

    async def alist(
        self, metadata: typing.Optional[typing.Dict[str, str]] = None
    ) -> typing.List[Instance]:
        """List all instances available to the user.

        Parameters:
            metadata: Optional metadata to filter instances by."""
        response = await self._client._async_http_client.get(
            "/instance",
            params={f"metadata[{k}]": v for k, v in (metadata or {}).items()},
        )
        return [
            Instance.model_validate(instance)._set_api(self)
            for instance in response.json()["data"]
        ]

    def start(
        self,
        snapshot_id: str,
        metadata: typing.Optional[typing.Dict[str, str]] = None,
        ttl_seconds: typing.Optional[int] = None,
        ttl_action: typing.Union[None, typing.Literal["stop", "pause"]] = None,
    ) -> Instance:
        """Create a new instance from a snapshot.

        Parameters:
            snapshot_id: The ID of the snapshot to start from.
            metadata: Optional metadata to attach to the instance.
            ttl_seconds: Optional time-to-live in seconds for the instance.
            ttl_action: Optional action to take when the TTL expires. Can be "stop" or "pause".
        """
        response = self._client._http_client.post(
            "/instance",
            params={"snapshot_id": snapshot_id},
            json={
                "metadata": metadata,
                "ttl_seconds": ttl_seconds,
                "ttl_action": ttl_action,
            },
        )
        return Instance.model_validate(response.json())._set_api(self)

    async def astart(
        self,
        snapshot_id: str,
        metadata: typing.Optional[typing.Dict[str, str]] = None,
        ttl_seconds: typing.Optional[int] = None,
        ttl_action: typing.Union[None, typing.Literal["stop", "pause"]] = None,
    ) -> Instance:
        """Create a new instance from a snapshot.

        Parameters:
            snapshot_id: The ID of the snapshot to start from.
            metadata: Optional metadata to attach to the instance.
            ttl_seconds: Optional time-to-live in seconds for the instance.
            ttl_action: Optional action to take when the TTL expires. Can be "stop" or "pause".
        """

        response = await self._client._async_http_client.post(
            "/instance",
            params={"snapshot_id": snapshot_id},
            json={
                "metadata": metadata,
                "ttl_seconds": ttl_seconds,
                "ttl_action": ttl_action,
            },
        )
        return Instance.model_validate(response.json())._set_api(self)

    def get(self, instance_id: str) -> Instance:
        """Get an instance by its ID."""
        response = self._client._http_client.get(f"/instance/{instance_id}")
        return Instance.model_validate(response.json())._set_api(self)

    async def aget(self, instance_id: str) -> Instance:
        """Get an instance by its ID."""
        response = await self._client._async_http_client.get(f"/instance/{instance_id}")
        return Instance.model_validate(response.json())._set_api(self)

    def stop(self, instance_id: str) -> None:
        """Stop an instance by its ID."""
        response = self._client._http_client.delete(f"/instance/{instance_id}")
        response.raise_for_status()

    async def astop(self, instance_id: str) -> None:
        """Stop an instance by its ID."""
        response = await self._client._async_http_client.delete(
            f"/instance/{instance_id}"
        )
        response.raise_for_status()

    def boot(
        self,
        snapshot_id: str,
        vcpus: typing.Optional[int] = None,
        memory: typing.Optional[int] = None,
        disk_size: typing.Optional[int] = None,
        metadata: typing.Optional[typing.Dict[str, str]] = None,
    ) -> Instance:
        """Boot an instance from a snapshot."""
        body = {}
        if vcpus is not None:
            body["vcpus"] = vcpus
        if memory is not None:
            body["memory"] = memory
        if disk_size is not None:
            body["disk_size"] = disk_size
        if metadata is not None:
            body["metadata"] = metadata
        response = self._client._http_client.post(
            f"/snapshot/{snapshot_id}/boot",
            json=body,
        )
        return Instance.model_validate(response.json())._set_api(self)

    async def aboot(
        self,
        snapshot_id: str,
        vcpus: typing.Optional[int] = None,
        memory: typing.Optional[int] = None,
        disk_size: typing.Optional[int] = None,
        metadata: typing.Optional[typing.Dict[str, str]] = None,
    ) -> Instance:
        """Boot an instance from a snapshot."""
        body = {}
        if vcpus is not None:
            body["vcpus"] = vcpus
        if memory is not None:
            body["memory"] = memory
        if disk_size is not None:
            body["disk_size"] = disk_size
        if metadata is not None:
            body["metadata"] = metadata
        response = await self._client._async_http_client.post(
            f"/snapshot/{snapshot_id}/boot",
            json=body,
        )
        return Instance.model_validate(response.json())._set_api(self)


class Instance(BaseModel):
    _api: InstanceAPI = PrivateAttr()
    id: str
    object: typing.Literal["instance"] = "instance"
    created: int
    status: InstanceStatus = InstanceStatus.PENDING
    spec: ResourceSpec
    refs: InstanceRefs
    networking: InstanceNetworking
    metadata: typing.Dict[str, str] = Field(
        default_factory=dict,
        description="User provided metadata for the instance",
    )

    def _set_api(self, api: InstanceAPI) -> Instance:
        self._api = api
        return self

    def stop(self) -> None:
        """Stop the instance."""
        self._api.stop(self.id)

    async def astop(self) -> None:
        """Stop the instance."""
        await self._api.astop(self.id)

    def pause(self) -> None:
        """Pause the instance."""
        response = self._api._client._http_client.post(f"/instance/{self.id}/pause")
        response.raise_for_status()
        self._refresh()

    async def apause(self) -> None:
        """Pause the instance."""
        response = await self._api._client._async_http_client.post(
            f"/instance/{self.id}/pause"
        )
        response.raise_for_status()
        await self._refresh_async()

    def resume(self) -> None:
        """Resume the instance."""
        response = self._api._client._http_client.post(f"/instance/{self.id}/resume")
        response.raise_for_status()
        self._refresh()

    async def aresume(self) -> None:
        """Resume the instance."""
        response = await self._api._client._async_http_client.post(
            f"/instance/{self.id}/resume"
        )
        response.raise_for_status()
        await self._refresh_async()

    def snapshot(
        self,
        digest: typing.Optional[str] = None,
        metadata: typing.Optional[typing.Dict[str, str]] = None,
    ) -> Snapshot:
        """Save the instance as a snapshot."""
        params = {}
        if digest is not None:
            params["digest"] = digest
        response = self._api._client._http_client.post(
            f"/instance/{self.id}/snapshot", params=params, json=dict(metadata=metadata)
        )
        return Snapshot.model_validate(response.json())._set_api(
            self._api._client.snapshots,
        )

    async def asnapshot(
        self,
        digest: typing.Optional[str] = None,
        metadata: typing.Optional[typing.Dict[str, str]] = None,
    ) -> Snapshot:
        """Save the instance as a snapshot."""
        params = {}
        if digest is not None:
            params = {"digest": digest}
        response = await self._api._client._async_http_client.post(
            f"/instance/{self.id}/snapshot", params=params, json=dict(metadata=metadata)
        )
        return Snapshot.model_validate(response.json())._set_api(
            self._api._client.snapshots
        )

    def reboot(self) -> None:
        """Reboot the instance."""
        response = self._api._client._http_client.post(f"/instance/{self.id}/reboot")
        response.raise_for_status()
        self._refresh()

    async def areboot(self) -> None:
        """Reboot the instance."""
        response = await self._api._client._async_http_client.post(
            f"/instance/{self.id}/reboot"
        )
        response.raise_for_status()
        await self._refresh_async()

    def branch(self, count: int) -> typing.Tuple[Snapshot, typing.List[Instance]]:
        """Branch the instance into multiple copies in parallel."""
        response = self._api._client._http_client.post(
            f"/instance/{self.id}/branch", params={"count": count}
        )
        _json = response.json()
        snapshot = Snapshot.model_validate(_json["snapshot"])._set_api(
            self._api._client.snapshots
        )

        instance_ids = [instance["id"] for instance in _json["instances"]]

        def start_and_wait(instance_id: str) -> Instance:
            instance = Instance.model_validate(
                {
                    "id": instance_id,
                    "status": InstanceStatus.PENDING,
                    **_json["instances"][instance_ids.index(instance_id)],
                }
            )._set_api(self._api)
            instance.wait_until_ready()
            return instance

        with ThreadPoolExecutor(max_workers=min(count, 10)) as executor:
            instances = list(executor.map(start_and_wait, instance_ids))

        return snapshot, instances

    async def abranch(
        self, count: int
    ) -> typing.Tuple[Snapshot, typing.List[Instance]]:
        """Branch the instance into multiple copies in parallel using asyncio."""
        response = await self._api._client._async_http_client.post(
            f"/instance/{self.id}/branch", params={"count": count}
        )
        _json = response.json()
        snapshot = Snapshot.model_validate(_json["snapshot"])._set_api(
            self._api._client.snapshots
        )

        instance_ids = [instance["id"] for instance in _json["instances"]]

        async def start_and_wait(instance_id: str) -> Instance:
            instance = Instance.model_validate(
                {
                    "id": instance_id,
                    "status": InstanceStatus.PENDING,
                    **_json["instances"][instance_ids.index(instance_id)],
                }
            )._set_api(self._api)
            await instance.await_until_ready()
            return instance

        instances = await asyncio.gather(
            *(start_and_wait(instance_id) for instance_id in instance_ids)
        )

        return snapshot, instances

    def expose_http_service(
        self, name: str, port: int, auth_mode: typing.Optional[str] = None
    ) -> str:
        """
        Expose an HTTP service.

        Parameters:
            name: The name of the service.
            port: The port to expose.
            auth_mode: Optional authentication mode. Use "api_key" to require API key authentication.

        Returns:
            The URL of the exposed service.
        """
        payload = {"name": name, "port": port}
        if auth_mode is not None:
            payload["auth_mode"] = auth_mode

        response = self._api._client._http_client.post(
            f"/instance/{self.id}/http",
            json=payload,
        )
        response.raise_for_status()
        self._refresh()
        url = next(
            service.url
            for service in self.networking.http_services
            if service.name == name
        )
        return url

    async def aexpose_http_service(
        self, name: str, port: int, auth_mode: typing.Optional[str] = None
    ) -> str:
        """
        Expose an HTTP service asynchronously.

        Parameters:
            name: The name of the service.
            port: The port to expose.
            auth_mode: Optional authentication mode. Use "api_key" to require API key authentication.

        Returns:
            The URL of the exposed service
        """
        payload = {"name": name, "port": port}
        if auth_mode is not None:
            payload["auth_mode"] = auth_mode

        response = await self._api._client._async_http_client.post(
            f"/instance/{self.id}/http",
            json=payload,
        )
        response.raise_for_status()
        await self._refresh_async()
        url = next(
            service.url
            for service in self.networking.http_services
            if service.name == name
        )
        return url

    def hide_http_service(self, name: str) -> None:
        """Unexpose an HTTP service."""
        response = self._api._client._http_client.delete(
            f"/instance/{self.id}/http/{name}"
        )
        response.raise_for_status()
        self._refresh()

    async def ahide_http_service(self, name: str) -> None:
        """Unexpose an HTTP service."""
        response = await self._api._client._async_http_client.delete(
            f"/instance/{self.id}/http/{name}"
        )
        response.raise_for_status()
        await self._refresh_async()

    def exec(
        self, command: typing.Union[str, typing.List[str]]
    ) -> InstanceExecResponse:
        """Execute a command on the instance."""
        command = [command] if isinstance(command, str) else command
        response = self._api._client._http_client.post(
            f"/instance/{self.id}/exec",
            json={"command": command},
        )
        return InstanceExecResponse.model_validate(response.json())

    async def aexec(
        self, command: typing.Union[str, typing.List[str]]
    ) -> InstanceExecResponse:
        """Execute a command on the instance."""
        command = [command] if isinstance(command, str) else command
        response = await self._api._client._async_http_client.post(
            f"/instance/{self.id}/exec",
            json={"command": command},
        )
        return InstanceExecResponse.model_validate(response.json())

    def wait_until_ready(self, timeout: typing.Optional[float] = None) -> None:
        """Wait until the instance is ready."""
        start_time = time.time()
        while self.status != InstanceStatus.READY:
            if timeout is not None and time.time() - start_time > timeout:
                raise TimeoutError("Instance did not become ready before timeout")
            time.sleep(1)
            self._refresh()
            if self.status == InstanceStatus.ERROR:
                raise RuntimeError("Instance encountered an error")

    async def await_until_ready(self, timeout: typing.Optional[float] = None) -> None:
        """Wait until the instance is ready."""
        start_time = time.time()
        while self.status != InstanceStatus.READY:
            if timeout is not None and time.time() - start_time > timeout:
                raise TimeoutError("Instance did not become ready before timeout")
            await asyncio.sleep(1)
            await self._refresh_async()
            if self.status == InstanceStatus.ERROR:
                raise RuntimeError("Instance encountered an error")

    def set_metadata(self, metadata: typing.Dict[str, str]) -> None:
        """Set metadata for the instance."""
        response = self._api._client._http_client.post(
            f"/instance/{self.id}/metadata",
            json=metadata,
        )
        response.raise_for_status()
        self._refresh()

    async def aset_metadata(self, metadata: typing.Dict[str, str]) -> None:
        """Set metadata for the instance."""
        response = await self._api._client._async_http_client.post(
            f"/instance/{self.id}/metadata",
            json=metadata,
        )
        response.raise_for_status()
        await self._refresh_async()

    def _refresh(self) -> None:
        refreshed = self._api.get(self.id)
        updated = type(self).model_validate(refreshed.model_dump())
        for key, value in updated.__dict__.items():
            setattr(self, key, value)

    async def _refresh_async(self) -> None:
        refreshed = await self._api.aget(self.id)
        updated = type(self).model_validate(refreshed.model_dump())
        for key, value in updated.__dict__.items():
            setattr(self, key, value)

    def ssh_connect(self):
        """Create a paramiko SSHClient and connect to the instance"""
        import paramiko

        hostname = os.environ.get("MORPH_SSH_HOSTNAME", "ssh.cloud.morph.so")
        port = int(os.environ.get("MORPH_SSH_PORT") or 22)

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if self._api._client.api_key is None:
            raise ValueError("API key must be provided to connect to the instance")

        username = self.id + ":" + self._api._client.api_key

        client.connect(
            hostname,
            port=port,
            username=username,
            pkey=_dummy_key(),
            look_for_keys=False,
            allow_agent=False,
        )
        return client

    def ssh(self):
        """Return an SSHClient instance for this instance"""
        from morphcloud._ssh import SSHClient  # as in your snippet

        return SSHClient(self.ssh_connect())

    def upload(
        self, local_path: str, remote_path: str, recursive: bool = False
    ) -> None:
        """
        Synchronously upload a local file/directory to 'remote_path' on this instance.
        If 'recursive' is True and local_path is a directory, upload that entire directory.
        """
        self.wait_until_ready()  # Ensure instance is READY for SFTP
        copy_into_or_from_instance(
            instance_obj=self,
            local_path=local_path,
            remote_path=remote_path,
            uploading=True,
            recursive=recursive,
        )

    def download(
        self, remote_path: str, local_path: str, recursive: bool = False
    ) -> None:
        """
        Synchronously download from 'remote_path' on this instance to a local path.
        If 'recursive' is True, treat 'remote_path' as a directory and download everything inside it.
        """
        self.wait_until_ready()
        copy_into_or_from_instance(
            instance_obj=self,
            local_path=local_path,
            remote_path=remote_path,
            uploading=False,
            recursive=recursive,
        )

    async def aupload(
        self, local_path: str, remote_path: str, recursive: bool = False
    ) -> None:
        """
        Asynchronously upload a local file/directory to 'remote_path' on this instance.
        If 'recursive' is True and local_path is a directory, upload that entire directory.
        Runs in a background thread so it doesn't block the event loop.
        """
        await self.await_until_ready()
        await asyncio.to_thread(
            copy_into_or_from_instance, self, local_path, remote_path, True, recursive
        )

    async def adownload(
        self, remote_path: str, local_path: str, recursive: bool = False
    ) -> None:
        """
        Asynchronously download from 'remote_path' on this instance to a local path.
        If 'recursive' is True, treat 'remote_path' as a directory and download everything inside it.
        Runs in a background thread so it doesn't block the event loop.
        """
        await self.await_until_ready()
        await asyncio.to_thread(
            copy_into_or_from_instance, self, local_path, remote_path, False, recursive
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.astop()

    def as_container(
        self,
        image: str,
        container_name: str = "container",
        command: str = "tail -f /dev/null",
        container_args: typing.Optional[typing.List[str]] = None,
        ports: typing.Optional[typing.Dict[int, int]] = None,
        volumes: typing.Optional[typing.List[str]] = None,
        env: typing.Optional[typing.Dict[str, str]] = None,
        restart_policy: str = "unless-stopped",
    ) -> None:
        """
        Configure the instance to redirect all SSH connections to a Docker container.

        This method:
        1. Ensures Docker is running on the instance
        2. Runs the specified Docker container
        3. Configures SSH to redirect all commands to the container

        After calling this method, all SSH connections and commands will be passed
        through to the container rather than the host VM.

        Parameters:
            image: The Docker image to run (e.g. "ubuntu:latest", "postgres:13")
            container_name: The name to give the container (default: "container")
            command: The command to run in the container (default: "tail -f /dev/null")
            container_args: Additional arguments to pass to "docker run"
            ports: Dictionary mapping host ports to container ports
            volumes: List of volume mounts (e.g. ["/host/path:/container/path"])
            env: Dictionary of environment variables to set in the container
            restart_policy: Container restart policy (default: "unless-stopped")

        Returns:
            None
        """
        # Make sure the instance is ready
        self.wait_until_ready()

        # Establish SSH connection
        with self.ssh() as ssh:
            # --- Start: Added Package Check and Installation ---
            required_packages = ["docker.io", "git", "curl"]
            missing_packages = []
            console.print("[blue]Checking for required packages...[/blue]")
            for pkg in required_packages:
                # Use dpkg -s which exits non-zero if package is not installed or unknown
                result = ssh.run(["dpkg", "-s", pkg])
                if result.exit_code != 0:
                    console.print(f"[yellow]Package '{pkg}' not found.[/yellow]")
                    missing_packages.append(pkg)
                # else: # Optional: uncomment for more verbosity
                #     console.print(f"[green]Package '{pkg}' found.[/green]")

            if missing_packages:
                console.print(
                    "[yellow]Updating package lists (apt-get update)...[/yellow]"
                )
                # Run apt-get update first
                update_result = ssh.run(["apt-get", "update", "-y"])
                if update_result.exit_code != 0:
                    error_msg = (
                        f"Failed to update apt package lists: {update_result.stderr}"
                    )
                    console.print(f"[bold red]{error_msg}[/bold red]")
                    raise RuntimeError(error_msg)

                # Install all missing packages at once
                console.print(
                    f"[yellow]Installing missing packages: {', '.join(missing_packages)}...[/yellow]"
                )
                install_cmd = ["apt-get", "install", "-y"] + missing_packages
                install_result = ssh.run(install_cmd)
                if install_result.exit_code != 0:
                    error_msg = f"Failed to install packages ({', '.join(missing_packages)}): {install_result.stderr}"
                    console.print(f"[bold red]{error_msg}[/bold red]")
                    raise RuntimeError(error_msg)
                console.print(
                    "[green]Required packages installed successfully.[/green]"
                )
            else:
                console.print(
                    "[green]All required packages are already installed.[/green]"
                )
            # --- End: Added Package Check and Installation ---

            # Verify docker service is running
            result = ssh.run(["systemctl", "is-active", "docker"])
            if result.exit_code != 0:
                console.print(
                    "[yellow]Docker service not active, attempting to start...[/yellow]"
                )
                # Attempt to start services (might fail if installation just happened and needs reboot, but usually works)
                ssh.run(
                    ["systemctl", "start", "containerd.service"]
                )  # Best effort start
                ssh.run(["systemctl", "start", "docker.service"])  # Best effort start

                # Re-check docker status after attempting to start
                time.sleep(2)  # Give services a moment to start
                result = ssh.run(["systemctl", "is-active", "docker"])
                if result.exit_code != 0:
                    error_msg = f"Docker service failed to start or is not installed correctly. Status check stderr: {result.stderr}"
                    console.print(f"[bold red]{error_msg}[/bold red]")
                    # Consider checking for common issues like needing a reboot after install
                    console.print(
                        "[bold yellow]Hint: A system reboot might be required after Docker installation.[/bold yellow]"
                    )
                    raise RuntimeError(error_msg)
                else:
                    console.print("[green]Docker service started successfully.[/green]")
            else:
                console.print("[green]Docker service is active.[/green]")

            # Build docker run command
            docker_cmd = ["docker", "run", "-d", "--name", container_name]

            # Add restart policy
            docker_cmd.extend(["--restart", restart_policy])

            # Add port mappings if provided
            if ports:
                for host_port, container_port in ports.items():
                    docker_cmd.extend(["-p", f"{host_port}:{container_port}"])

            # Add volume mounts if provided
            if volumes:
                for volume in volumes:
                    docker_cmd.extend(["-v", volume])

            # Add environment variables if provided
            if env:
                for key, value in env.items():
                    docker_cmd.extend(["-e", f"{key}={value}"])

            # Add any additional docker run arguments
            if container_args:
                docker_cmd.extend(container_args)

            # Add the image and command
            docker_cmd.append(image)

            # Split the command if it's a string
            if isinstance(command, str):
                docker_cmd.extend(command.split())
            else:
                docker_cmd.extend(command)

            # Run the docker container
            console.print(
                f"[blue]Starting container '{container_name}' from image '{image}'...[/blue]"
            )
            console.print(f"[blue]{docker_cmd=}[/blue]")
            result = ssh.run(docker_cmd)
            if result.exit_code != 0:
                error_msg = f"Failed to start container: {result.stderr}"
                console.print(f"[bold red]{error_msg}[/bold red]")
                raise RuntimeError(error_msg)

            # Create improved container.sh script with TTY detection
            container_script = (
                f"""#!/bin/bash

# container.sh - Redirects SSH commands to the Docker container
CONTAINER_NAME={container_name}"""
                + """

# Function to check if the container has the specified shell
check_shell() {
    if docker exec "$CONTAINER_NAME" which "$1" >/dev/null 2>&1; then
        echo "$1"
        return 0
    fi
    return 1
}

# Determine the best shell available in the container
SHELL_TO_USE=""
for shell in bash sh ash; do
    if SHELL_PATH=$(check_shell "$shell"); then
        SHELL_TO_USE="$SHELL_PATH"
        break
    fi
done

# If no shell was found, fail gracefully
if [ -z "$SHELL_TO_USE" ]; then
    echo "Error: No usable shell found in container. Container might be too minimal." >&2
    exit 1
fi

if [ -z "$SSH_ORIGINAL_COMMAND" ]; then
    # Interactive login shell - use -it flags but WITHOUT -l
    # This is for when users SSH in directly without a command
    exec docker exec -it "$CONTAINER_NAME" "$SHELL_TO_USE"
else
    # Command execution - detect if TTY is available
    if [ -t 0 ]; then
        # TTY is available, use interactive mode WITHOUT -l
        # This makes it a non-login interactive shell
        exec docker exec -it "$CONTAINER_NAME" "$SHELL_TO_USE" -c "$SSH_ORIGINAL_COMMAND"
    else
        # No TTY available, run without -it flags and without -l
        # This makes it a non-login, non-interactive shell
        exec docker exec "$CONTAINER_NAME" "$SHELL_TO_USE" -c "$SSH_ORIGINAL_COMMAND"
    fi
fi"""
            )

            # Write the container.sh script to the instance using our new write_file method
            console.print("[blue]Installing container redirection script...[/blue]")
            ssh.write_file(
                "/root/container.sh", container_script, mode=0o755
            )  # Using 0o755 to make it executable

            # Update SSH configuration to force commands through the script
            console.print("[blue]Configuring SSH to redirect to container...[/blue]")

            # Check if ForceCommand already exists in sshd_config
            grep_result = ssh.run("grep -q '^ForceCommand' /etc/ssh/sshd_config")

            if grep_result.returncode == 0:
                # ForceCommand already exists, update it
                ssh.run(
                    "sed -i 's|^ForceCommand.*|ForceCommand /root/container.sh|' /etc/ssh/sshd_config"
                )
            else:
                # Add ForceCommand to the end of sshd_config
                ssh.run(
                    'echo "ForceCommand /root/container.sh" >> /etc/ssh/sshd_config'
                )

            # Restart SSH service
            console.print("[blue]Restarting SSH service...[/blue]")
            ssh.run(["systemctl", "restart", "sshd"])

            # Test the container setup
            console.print("[blue]Testing container connectivity...[/blue]")
            test_result = ssh.run('echo "Container setup test"')
            if test_result.returncode != 0:
                console.print(
                    "[yellow]Warning: Container setup test returned non-zero exit code. Check container configuration.[/yellow]"
                )

        console.print(
            f"[bold green]✅ Instance now redirects all SSH sessions to the '{container_name}' container[/bold green]"
        )
        console.print(
            "[dim]Note: This change cannot be easily reversed. Consider creating a snapshot before using this method.[/dim]"
        )

    async def aas_container(
        self,
        image: str,
        container_name: str = "container",
        command: str = "tail -f /dev/null",
        container_args: typing.Optional[typing.List[str]] = None,
        ports: typing.Optional[typing.Dict[int, int]] = None,
        volumes: typing.Optional[typing.List[str]] = None,
        env: typing.Optional[typing.Dict[str, str]] = None,
        restart_policy: str = "unless-stopped",
    ) -> None:
        """
        Async version of as_container. Configure the instance to redirect all SSH connections to a Docker container.

        This method:
        1. Ensures Docker is running on the instance
        2. Runs the specified Docker container
        3. Configures SSH to redirect all commands to the container

        After calling this method, all SSH connections and commands will be passed
        through to the container rather than the host VM.

        Parameters:
            image: The Docker image to run (e.g. "ubuntu:latest", "postgres:13")
            container_name: The name to give the container (default: "container")
            command: The command to run in the container (default: "tail -f /dev/null")
            container_args: Additional arguments to pass to "docker run"
            ports: Dictionary mapping host ports to container ports
            volumes: List of volume mounts (e.g. ["/host/path:/container/path"])
            env: Dictionary of environment variables to set in the container
            restart_policy: Container restart policy (default: "unless-stopped")

        Returns:
            None
        """
        await self.await_until_ready()

        # Run the synchronous version in a thread pool
        return await asyncio.to_thread(
            self.as_container,
            image=image,
            container_name=container_name,
            command=command,
            container_args=container_args,
            ports=ports,
            volumes=volumes,
            env=env,
            restart_policy=restart_policy,
        )

    def set_ttl(
        self,
        ttl_seconds: int,
        ttl_action: typing.Optional[typing.Literal["stop", "pause"]] = None,
    ) -> None:
        """
        Update the TTL (Time To Live) for the instance.

        This method allows you to reset the expiration time for an instance, which will be
        calculated as the current server time plus the provided TTL seconds.

        Parameters:
            ttl_seconds: New TTL in seconds
            ttl_action: Optional action to take when the TTL expires. Can be "stop" or "pause".
                       If not provided, the current action will be maintained.

        Returns:
            None
        """
        payload = {"ttl_seconds": ttl_seconds}
        if ttl_action is not None:
            payload["ttl_action"] = ttl_action

        response = self._api._client._http_client.post(
            f"/instance/{self.id}/ttl",
            json=payload,
        )
        response.raise_for_status()
        self._refresh()

    async def aset_ttl(
        self,
        ttl_seconds: int,
        ttl_action: typing.Optional[typing.Literal["stop", "pause"]] = None,
    ) -> None:
        """
        Asynchronously update the TTL (Time To Live) for the instance.

        This method allows you to reset the expiration time for an instance, which will be
        calculated as the current server time plus the provided TTL seconds.

        Parameters:
            ttl_seconds: New TTL in seconds
            ttl_action: Optional action to take when the TTL expires. Can be "stop" or "pause".
                       If not provided, the current action will be maintained.

        Returns:
            None
        """
        payload = {"ttl_seconds": ttl_seconds}
        if ttl_action is not None:
            payload["ttl_action"] = ttl_action

        response = await self._api._client._async_http_client.post(
            f"/instance/{self.id}/ttl",
            json=payload,
        )
        response.raise_for_status()
        await self._refresh_async()


# Helper functions
import click


def copy_into_or_from_instance(
    instance_obj,
    local_path,
    remote_path,
    uploading,
    recursive=False,
    verbose=False,
):
    """
    Generic helper to copy files/directories between 'local_path' and
    'remote_path' on an already-ready instance via SFTP.

    :param instance_obj: The instance on which to operate (must be READY).
    :param local_path:   A string to a local file/directory path.
    :param remote_path:  A string to a remote file/directory path on the instance.
    :param uploading:    If True, copy local → remote; if False, copy remote → local.
    :param recursive:    If True, copy entire directories recursively.
    """

    import os
    import os.path
    import pathlib
    import stat

    from tqdm import tqdm

    def sftp_exists(sftp, path):
        try:
            sftp.stat(path)
            return True
        except FileNotFoundError:
            return False
        except IOError:
            return False

    def sftp_isdir(sftp, path):
        try:
            return stat.S_ISDIR(sftp.stat(path).st_mode)
        except (FileNotFoundError, IOError):
            return False

    def sftp_makedirs(sftp, path):
        dirs = []
        while path not in ["/", "."]:
            if sftp_exists(sftp, path):
                if not sftp_isdir(sftp, path):
                    raise IOError(f"Remote path {path} exists but is not a directory.")
                break
            dirs.append(path)
            path = os.path.dirname(path)
        for d in reversed(dirs):
            sftp.mkdir(d)

    def upload_directory(sftp, local_dir, remote_dir):
        items = list(local_dir.rglob("*"))
        total_files = len([i for i in items if i.is_file()])
        with tqdm(
            total=total_files, unit="file", desc=f"Uploading {local_dir.name}"
        ) as pbar:
            sftp_makedirs(sftp, remote_dir)
            for item in items:
                relative_path = item.relative_to(local_dir)
                remote_item_path = os.path.join(
                    remote_dir, *relative_path.parts
                ).replace("\\", "/")
                if item.is_dir():
                    sftp_makedirs(sftp, remote_item_path)
                else:
                    sftp.put(str(item), remote_item_path)
                    pbar.update(1)

    def upload_file(sftp, local_file, remote_file):
        parent = os.path.dirname(remote_file)
        if parent and parent != ".":
            sftp_makedirs(sftp, parent)
        sftp.put(str(local_file), remote_file)

    def download_directory(sftp, remote_dir, local_dir):
        items_to_explore = [remote_dir]
        files_to_download = []

        # Gather items from the remote directory
        while items_to_explore:
            current_dir = items_to_explore.pop()
            try:
                for entry in sftp.listdir_attr(current_dir):
                    full_remote = os.path.join(current_dir, entry.filename).replace(
                        "\\", "/"
                    )
                    if stat.S_ISDIR(entry.st_mode):
                        items_to_explore.append(full_remote)
                    else:
                        files_to_download.append(full_remote)
            except FileNotFoundError:
                click.echo(
                    f"Warning: Remote directory {current_dir} not found.", err=True
                )
            except IOError as e:
                click.echo(
                    f"Warning: Error listing remote directory {current_dir}: {e}",
                    err=True,
                )

        # Create local subdirs and download files
        with tqdm(
            total=len(files_to_download),
            unit="file",
            desc=f"Downloading {os.path.basename(remote_dir)}",
        ) as pbar:
            for file_path in files_to_download:
                rel = os.path.relpath(file_path, remote_dir)
                local_file = local_dir / rel
                local_file.parent.mkdir(parents=True, exist_ok=True)
                sftp.get(file_path, str(local_file))
                pbar.update(1)

    def download_file(sftp, remote_file, local_file):
        local_file_path = pathlib.Path(local_file)
        local_file_path.parent.mkdir(parents=True, exist_ok=True)
        sftp.get(remote_file, str(local_file_path))

    with instance_obj.ssh() as ssh:
        sftp = ssh._client.open_sftp()

        if uploading:
            # local → remote
            local_path_obj = pathlib.Path(local_path).resolve()

            if recursive:
                if local_path_obj.is_file():
                    raise click.UsageError(
                        "Cannot recursively upload a single file without a directory."
                    )
                if not local_path_obj.exists():
                    raise click.UsageError(
                        f"Local path does not exist: {local_path_obj}"
                    )
                upload_directory(sftp, local_path_obj, remote_path)
            else:
                if local_path_obj.is_dir():
                    raise click.UsageError(
                        f"Source '{local_path_obj}' is a directory. Use --recursive."
                    )
                if not local_path_obj.exists():
                    raise click.UsageError(f"Local file not found: {local_path_obj}")
                upload_file(sftp, local_path_obj, remote_path)

        else:
            # remote → local
            local_path_obj = pathlib.Path(local_path).resolve()

            if recursive:
                # We consider remote_path to be a directory or a non-existent path we treat as directory
                download_directory(sftp, remote_path, local_path_obj)
            else:
                # Single-file download
                # If remote_path is a directory, error out (user must supply --recursive).
                if sftp_isdir(sftp, remote_path):
                    raise click.UsageError(
                        f"Remote source '{remote_path}' is a directory. Use --recursive."
                    )
                download_file(sftp, remote_path, local_path_obj)

        sftp.close()

    if verbose:
        click.echo("\nCopy complete.")
