from __future__ import annotations

import os
import enum
import json
import time
import typing
import asyncio

from functools import lru_cache

import httpx

from pydantic import BaseModel, Field, PrivateAttr
from concurrent.futures import ThreadPoolExecutor


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


class SnapshotStatus(enum.StrEnum):
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


class SnapshotAPI(BaseAPI):
    def list(
        self,
        digest: typing.Optional[str] = None,
        metadata: typing.Optional[typing.Dict[str, str]] = None,
    ) -> typing.List[Snapshot]:
        """List all snapshots available to the user."""
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
        """List all snapshots available to the user."""
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
        """Create a new snapshot from a base image and a machine configuration."""
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
        response = self._client._http_client.post(
            "/snapshot",
            json=body,
        )
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
        """Create a new snapshot from a base image and a machine configuration."""
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
        response = await self._client._async_http_client.post(
            "/snapshot",
            json=body,
        )
        return Snapshot.model_validate(response.json())._set_api(self)

    def get(self, snapshot_id: str) -> Snapshot:
        """Get a snapshot by ID."""
        response = self._client._http_client.get(f"/snapshot/{snapshot_id}")
        return Snapshot.model_validate(response.json())._set_api(self)

    async def aget(self, snapshot_id: str) -> Snapshot:
        """Get a snapshot by ID."""
        response = await self._client._async_http_client.get(f"/snapshot/{snapshot_id}")
        return Snapshot.model_validate(response.json())._set_api(self)


class Snapshot(BaseModel):
    id: str = Field(
        ..., description="Unique identifier for the snapshot, like snapshot_xxxx"
    )
    object: typing.Literal["snapshot"] = Field(
        "snapshot", description="Object type, always 'snapshot'"
    )
    created: int = Field(
        ..., description="Unix timestamp of when the snapshot was created"
    )
    status: SnapshotStatus = Field(..., description="Status of the snapshot")
    spec: ResourceSpec = Field(..., description="Resource specifications")
    refs: SnapshotRefs = Field(..., description="Referenced resources")
    digest: typing.Optional[str] = Field(
        default=None, description="User provided digest of the snapshot content"
    )
    metadata: typing.Dict[str, str] = Field(
        default_factory=dict,
        description="User provided metadata for the snapshot",
    )

    _api: SnapshotAPI = PrivateAttr()

    def _set_api(self, api: SnapshotAPI) -> Snapshot:
        self._api = api
        return self

    def delete(self) -> None:
        """Delete the snapshot."""
        response = self._api._client._http_client.delete(f"/snapshot/{self.id}")
        response.raise_for_status()

    async def adelete(self) -> None:
        """Delete the snapshot."""
        response = await self._api._client._async_http_client.delete(
            f"/snapshot/{self.id}"
        )
        response.raise_for_status()

    def set_metadata(self, metadata: typing.Dict[str, str]) -> None:
        """Set metadata for the snapshot."""
        response = self._api._client._http_client.post(
            f"/snapshot/{self.id}/metadata",
            json=metadata,
        )
        response.raise_for_status()
        self._refresh()

    async def aset_metadata(self, metadata: typing.Dict[str, str]) -> None:
        """Set metadata for the snapshot."""
        response = await self._api._client._async_http_client.post(
            f"/snapshot/{self.id}/metadata",
            json=metadata,
        )
        response.raise_for_status()
        await self._refresh_async()

    def _refresh(self) -> None:
        refreshed = self._api.get(self.id)
        # Use pydantic's parse_obj to ensure fields remain typed
        updated = type(self).model_validate(refreshed.model_dump())

        # Now 'updated' is a fully validated model. Update self with these fields:
        for key, value in updated.__dict__.items():
            setattr(self, key, value)

    async def _refresh_async(self) -> None:
        """Refresh the snapshot data."""
        refreshed = await self._api.aget(self.id)
        updated = type(self).model_validate(refreshed.model_dump())
        for key, value in updated.__dict__.items():
            setattr(self, key, value)


class InstanceStatus(enum.StrEnum):
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
        """List all instances available to the user."""
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
        """List all instances available to the user."""
        response = await self._client._async_http_client.get(
            "/instance",
            params={f"metadata[{k}]": v for k, v in (metadata or {}).items()},
        )
        return [
            Instance.model_validate(instance)._set_api(self)
            for instance in response.json()["data"]
        ]

    def start(self, snapshot_id: str) -> Instance:
        """Create a new instance from a snapshot."""
        response = self._client._http_client.post(
            "/instance",
            params={"snapshot_id": snapshot_id},
        )
        return Instance.model_validate(response.json())._set_api(self)

    async def astart(self, snapshot_id: str) -> Instance:
        """Create a new instance from a snapshot."""
        response = await self._client._async_http_client.post(
            "/instance",
            params={"snapshot_id": snapshot_id},
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

    def snapshot(self, digest: typing.Optional[str] = None) -> Snapshot:
        """Save the instance as a snapshot."""
        params = {}
        if digest is not None:
            params["digest"] = digest
        response = self._api._client._http_client.post(
            f"/instance/{self.id}/snapshot", params=params
        )
        return Snapshot.model_validate(response.json())._set_api(
            self._api._client.snapshots
        )

    async def asnapshot(self, digest: typing.Optional[str] = None) -> Snapshot:
        """Save the instance as a snapshot."""
        params = {}
        if digest is not None:
            params = {"digest": digest}
        response = await self._api._client._async_http_client.post(
            f"/instance/{self.id}/snapshot", params=params
        )
        return Snapshot.model_validate(response.json())._set_api(
            self._api._client.snapshots
        )

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

    
    def expose_http_service(self, name: str, port: int, auth_mode: Optional[str] = None) -> None:
        """
        Expose an HTTP service.
        
        Parameters:
            name: The name of the service.
            port: The port to expose.
            auth_mode: Optional authentication mode. Use "api_key" to require API key authentication.
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

    async def aexpose_http_service(self, name: str, port: int, auth_mode: Optional[str] = None) -> None:
        """
        Expose an HTTP service asynchronously.
        
        Parameters:
            name: The name of the service.
            port: The port to expose.
            auth_mode: Optional authentication mode. Use "api_key" to require API key authentication.
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
        from morphcloud._ssh import SSHClient  # as in your snippet

        return SSHClient(self.ssh_connect())

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()

    def sync(
        self,
        source_path: str,
        dest_path: str,
        delete: bool = False,
        dry_run: bool = False,
        respect_gitignore: bool = True,
        max_workers: int = 8,
    ) -> None:
        """
        Synchronize a local directory to a remote directory (or vice versa) in parallel,
        using multiple SSH connections to avoid Paramiko concurrency deadlocks.

        Args:
            source_path:  Local or remote path for the source. e.g. "/path" or "instance_id:/path"
            dest_path:    Local or remote path for the destination.
            delete:       If True, delete extraneous files in the destination.
            dry_run:      If True, just show the actions without changing anything.
            respect_gitignore: If True, skip local files that match .gitignore
            max_workers:  Number of parallel worker threads & SSH connections.
        """
        import pathlib
        import logging
        import threading
        import queue
        from typing import Dict, Tuple, Optional, List
        from concurrent.futures import ThreadPoolExecutor, as_completed
        from tqdm import tqdm
        import pathspec
        import subprocess
        import stat

        logger = logging.getLogger("morph.sync")
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            # logger.setLevel(logging.DEBUG)

        logger.info(f"Starting sync from {source_path} to {dest_path}")
        logger.info(
            f"Parameters: delete={delete}, dry_run={dry_run}, "
            f"respect_gitignore={respect_gitignore}, max_workers={max_workers}"
        )

        # ---------------------------------------------------------------------
        # 1) HELPER FUNCTIONS
        # ---------------------------------------------------------------------
        def parse_instance_path(path: str):
            if ":" not in path:
                return None, path
            instance_id, remote_path = path.split(":", 1)
            return instance_id, remote_path

        def format_size(size: int) -> str:
            for unit in ["B", "KB", "MB", "GB"]:
                if size < 1024:
                    return f"{size:.1f}{unit}"
                size /= 1024
            return f"{size:.1f}TB"

        def get_gitignore_spec(dir_path: str) -> Optional[pathspec.PathSpec]:
            gitignore_path = os.path.join(dir_path, ".gitignore")
            try:
                with open(gitignore_path) as f:
                    return pathspec.PathSpec.from_lines("gitwildmatch", f)
            except FileNotFoundError:
                return None

        def should_ignore(
            path: str, base_dir: str, ignore_spec: Optional[pathspec.PathSpec]
        ) -> bool:
            if not ignore_spec:
                return False
            rel_path = os.path.relpath(path, base_dir)
            return ignore_spec.match_file(rel_path)

        # ---------------------------------------------------------------------
        # 2) LOCAL SCANNING USING "ls -lR" (POSIX only) OR FALLBACK
        # ---------------------------------------------------------------------
        def get_local_info_fallback(local_path: str) -> Dict[str, Tuple[int, float]]:
            """Fallback using Python's rglob (slower for large trees)."""
            info = {}
            base_path = pathlib.Path(local_path)
            if not base_path.exists():
                logger.warning(f"Local path does not exist: {local_path}")
                return info

            ignore_spec = None
            if respect_gitignore:
                ignore_spec = get_gitignore_spec(str(base_path))

            for item in base_path.rglob("*"):
                if item.is_file():
                    if should_ignore(str(item), str(base_path), ignore_spec):
                        logger.debug(f"Ignoring file (gitignore): {item}")
                        continue
                    st = item.stat()
                    info[str(item)] = (st.st_size, st.st_mtime)
            return info

        def get_local_info_via_ls(local_path: str) -> Dict[str, Tuple[int, float]]:
            """
            Retrieve local file info by calling `ls -lR {local_path}` and parsing output.
            Returns {full_path: (size, mtime)}.
            """
            logger.debug("getting local info via ls")
            info = {}
            if not os.path.exists(local_path):
                logger.warning(f"Local path does not exist: {local_path}")
                return info

            ignore_spec = None
            if respect_gitignore:
                ignore_spec = get_gitignore_spec(local_path)

            cmd = ["ls", "-lR", local_path]
            try:
                logger.debug("running proc")
                proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
                stdout = proc.stdout or ""
                stderr = proc.stderr or ""
                logger.debug(f"got stdout and stderr {stderr=} {stdout=}")
                if stderr.strip():
                    logger.debug(f"[ls -lR stderr] {stderr.strip()}")

                lines = stdout.split("\n")
                current_dir = None

                for line in lines:
                    logger.debug("iterlines")
                    line = line.strip()
                    # Lines ending with ":" indicate a new directory section
                    if line.endswith(":"):
                        # e.g. "/some/path:" -> remove trailing colon
                        current_dir = line[:-1]
                        continue
                    if not line or line.startswith("total"):
                        continue

                    # Example lines from ls -l: `-rw-r--r--  1 user  staff   1533 May 11  2022 filename.py`
                    parts = line.split(None, 8)
                    if len(parts) >= 9 and parts[0][0] != "d":
                        # parts[4] -> size, parts[8] -> filename
                        size_str = parts[4]
                        name = parts[8]
                        try:
                            size = int(size_str)
                        except ValueError:
                            logger.warning(f"Could not parse size from line: {line}")
                            continue

                        if current_dir:
                            full_path = os.path.join(current_dir, name)
                            if os.path.isfile(full_path):
                                # respect .gitignore if needed
                                logger.debug("triggering?")
                                if ignore_spec and should_ignore(
                                    full_path, local_path, ignore_spec
                                ):
                                    logger.debug(f"Ignoring (gitignore) {full_path}")
                                    continue
                                try:
                                    st = os.stat(full_path)
                                    info[full_path] = (st.st_size, st.st_mtime)
                                except FileNotFoundError:
                                    logger.debug(
                                        f"File not found while stat()'ing: {full_path}"
                                    )

            except Exception as e:
                logger.warning(
                    f"Failed to retrieve local file info via `ls -lR`. {e}",
                    exc_info=True,
                )
                # fallback
                return get_local_info_fallback(local_path)

            logger.debug("RETURNING")
            return info

        def get_local_info(local_path: str) -> Dict[str, Tuple[int, float]]:
            """Attempt fast scanning with `ls -lR` on POSIX. Otherwise fallback to rglob."""
            if os.name == "posix":
                return get_local_info_via_ls(local_path)
            else:
                logger.info(
                    "Non-POSIX OS detected; falling back to Python's rglob for local scanning."
                )
                return get_local_info_fallback(local_path)

        # ---------------------------------------------------------------------
        # 3) REMOTE SCANNING VIA "ls -lR" (fast)
        # ---------------------------------------------------------------------
        def get_file_info_via_ssh(
            ssh_client, remote_path: str
        ) -> Dict[str, Tuple[int, float]]:
            """
            Retrieve remote file info using 'ls -lR' (fast single-pass).
            Return {full_remote_path: (size, 0.0 or mtime)}. We'll store 0.0 as placeholder for mtime,
            or skip real mtime since paramiko won't give it directly from 'ls -lR'.
            """
            file_info = {}
            try:
                logger.info(f"Running 'ls -lR' on remote path: {remote_path}")
                cmd = f"ls -lR '{remote_path}'"
                result = ssh_client.run(cmd)

                stdout = result.stdout or ""
                stderr = result.stderr or ""
                lines = stdout.splitlines()
                current_dir = None
                for line in lines:
                    line = line.strip()
                    if line.endswith(":"):
                        current_dir = line[:-1]
                        continue
                    if not line or line.startswith("total"):
                        continue

                    # -rw-r--r-- 1 root root 1533 May 11  2022 filename
                    parts = line.split(None, 8)
                    if len(parts) >= 9 and parts[0][0] != "d":
                        size_str = parts[4]
                        name = parts[8]
                        try:
                            size = int(size_str)
                        except ValueError:
                            logger.warning(
                                f"Could not parse size '{size_str}' from line: {line}"
                            )
                            continue
                        if current_dir:
                            full_path = os.path.join(current_dir, name).replace(
                                "\\", "/"
                            )
                            file_info[full_path] = (size, 0.0)  # ignoring actual mtime
                if stderr.strip():
                    logger.debug(f"Error from ls -lR: {stderr.strip()}")

            except Exception as e:
                logger.error(
                    f"Failed to retrieve remote file info via SSH: {e}", exc_info=True
                )
                raise
            logger.info(f"Found {len(file_info)} remote files via ls -lR.")
            return file_info

        # ---------------------------------------------------------------------
        # 4) REMOTE SCANNING VIA SFTP (slower, can loop on symlinks!)
        #    We'll skip symlinks to avoid infinite recursion.
        # ---------------------------------------------------------------------
        # def get_remote_file_info_sftp(sftp, remote_path: str) -> Dict[str, Tuple[int, float]]:
        #     """
        #     Recursively gather {full_remote_path: (size, mtime)} via SFTP listdir_attr(),
        #     skipping symlinks to avoid potential infinite loops.
        #     """
        #     info = {}
        #     visited = set()  # track visited dirs to avoid cycles

        #     def _recurse(dir_path: str):
        #         if dir_path in visited:
        #             return
        #         visited.add(dir_path)

        #         try:
        #             items = sftp.listdir_attr(dir_path)
        #             for it in items:
        #                 full_path = os.path.join(dir_path, it.filename).replace("\\", "/")
        #                 # Skip symlinks
        #                 if stat.S_ISLNK(it.st_mode):
        #                     continue
        #                 if stat.S_ISDIR(it.st_mode):
        #                     _recurse(full_path)
        #                 else:
        #                     info[full_path] = (it.st_size, float(it.st_mtime))
        #         except Exception as e:
        #             logger.error(f"Error listing {dir_path} via SFTP: {e}")

        #     _recurse(remote_path)
        #     logger.info(f"SFTP found {len(info)} remote files under {remote_path}")
        #     return info

        # ---------------------------------------------------------------------
        # 5) SSH CONNECTION POOL
        # ---------------------------------------------------------------------
        def create_ssh_pool(num_connections: int):
            """
            Create and return a queue of distinct SSH clients in parallel using ThreadPoolExecutor.
            Each thread will create one SSH client via self.ssh().
            """
            conn_queue = queue.Queue()
            # Limit the pool size so we don't spawn too many threads at once (16 is arbitrary).
            max_concurrent_creates = min(num_connections, 16)

            # We first spawn tasks that call self.ssh() in parallel
            with ThreadPoolExecutor(max_concurrent_creates) as pool:
                # pool.map(...) returns an iterator of results in the same order
                ssh_clients = list(
                    pool.map(lambda _: self.ssh(), range(num_connections))
                )

            # Now we’ve created all the SSH connections, place them into the queue
            for i, cli in enumerate(ssh_clients, start=1):
                logger.debug(f"Created SSH connection #{i}/{num_connections}")
                conn_queue.put(cli)

            return conn_queue

        def close_ssh_pool(conn_queue: queue.Queue):
            """
            Drain the queue and forcibly close each SSHClient.
            This should close underlying Paramiko transports to avoid hanging.
            """
            while not conn_queue.empty():
                cli = conn_queue.get_nowait()
                try:
                    # If your SSHClient wrapper exposes the raw Paramiko client as cli._client,
                    # ensure we close both the client and its Transport.
                    transport = cli._client.get_transport()
                    if transport and transport.is_active():
                        transport.close()

                    # Finally close the high-level SSHClient wrapper
                    cli.close()

                except Exception as e:
                    logger.warning(f"Error closing SSH client: {e}")

        # ---------------------------------------------------------------------
        # 6) MAKE REMOTE DIRS
        # ---------------------------------------------------------------------
        def make_remote_dirs(sftp, remote_dir: str):
            if not remote_dir or remote_dir in ("/", "."):
                return
            try:
                sftp.stat(remote_dir)
            except IOError:
                parent = os.path.dirname(remote_dir)
                if parent and parent not in ("/", "."):
                    make_remote_dirs(sftp, parent)
                try:
                    sftp.mkdir(remote_dir)
                except IOError as e:
                    # If it already exists or some other benign error, ignore
                    if "Failure" not in str(e):
                        raise

        # ---------------------------------------------------------------------
        # 7) PARALLEL EXECUTION (REMOTE->LOCAL)
        # ---------------------------------------------------------------------
        def parallel_remote_downloads(
            actions: List[Tuple[str, str, str, int, float]],
            total_size: int,
            ssh_queue: queue.Queue,
        ):
            """
            Each thread: retrieve an SSH client from the pool, open SFTP, perform
            copy/delete, and return the client. sftp.get doesn't have a `confirm`
            parameter, so no changes are needed there to avoid small-file hangs.
            """
            from tqdm import tqdm

            pbar_lock = threading.Lock()

            if not actions:
                logger.info("No remote->local actions to process.")
                return

            logger.info(
                f"Processing {len(actions)} remote->local actions with {max_workers} parallel workers."
            )
            with tqdm(total=total_size, unit="B", unit_scale=True) as pbar:

                def worker(action):
                    ssh_client = ssh_queue.get()
                    try:
                        atype, src, dst, size, mtime = action
                        thread_id = threading.get_ident()
                        logger.info(
                            f"[Thread {thread_id}] remote->local {atype} src={src}, dst={dst}"
                        )

                        sftp = ssh_client._client.open_sftp()
                        try:
                            if atype == "copy":
                                with pbar_lock:
                                    pbar.set_description(
                                        f"Downloading {os.path.basename(dst)}"
                                    )
                                os.makedirs(os.path.dirname(dst), exist_ok=True)

                                # sftp.get does not provide a 'confirm' param, so we rely on normal completion
                                sftp.get(src, dst)

                                # Restore original mtime locally
                                os.utime(dst, (mtime, mtime))

                                with pbar_lock:
                                    pbar.update(size)

                            elif atype == "delete":
                                with pbar_lock:
                                    pbar.set_description(
                                        f"Deleting (local) {os.path.basename(dst)}"
                                    )
                                try:
                                    os.remove(dst)
                                except FileNotFoundError:
                                    logger.warning(
                                        f"Local file not found for delete: {dst}"
                                    )
                        finally:
                            sftp.close()
                    finally:
                        ssh_queue.put(ssh_client)

                futures = []
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    for act in actions:
                        futures.append(executor.submit(worker, act))

                    # Wait for all downloads/deletes to complete
                    for fut in as_completed(futures):
                        exc = fut.exception()
                        if exc:
                            logger.error(
                                "Download worker encountered an error:", exc_info=True
                            )
                            raise exc

            logger.info("All remote->local actions completed successfully.")

        # ---------------------------------------------------------------------
        # 8) PARALLEL EXECUTION (LOCAL->REMOTE)
        # ---------------------------------------------------------------------

        def parallel_remote_uploads(
            actions: List[Tuple[str, str, str, int, float]],
            total_size: int,
            ssh_queue: queue.Queue,
        ):
            """
            Parallel local->remote uploads with a 30-second per-file timeout.
            If sftp.put() doesn't complete in 30s, we retry up to 3 total attempts
            before raising an exception.

            'in_flight_actions' tracks which uploads are ongoing (src, dst).
            """

            import time
            import threading
            from tqdm import tqdm
            from concurrent.futures import ThreadPoolExecutor, as_completed

            pbar_lock = threading.Lock()

            # Track all in-flight uploads: set of (src, dst)
            in_flight_lock = threading.Lock()
            in_flight_actions = set()

            # If no actions, we're done
            if not actions:
                logger.info("No local->remote actions to process.")
                return

            logger.info(
                f"Starting parallel_remote_uploads:\n"
                f"  - Number of actions: {len(actions)}\n"
                f"  - Total upload size: {total_size} bytes\n"
                f"  - ThreadPool max_workers: {max_workers}"
            )

            batch_start_time = time.time()

            # ----------------------------------------------------------------------
            # HELPER: SFTP put with a 30-second timeout in a separate thread
            # ----------------------------------------------------------------------
            def sftp_put_with_timeout(
                sftp: "paramiko.SFTPClient",
                src: str,
                dst: str,
                confirm: bool,
                timeout: float,
            ):
                """
                Calls sftp.put(src, dst, confirm=confirm) in a separate thread and waits
                up to `timeout` seconds. Raises TimeoutError if it doesn't finish in time.
                """

                def do_put():
                    sftp.put(src, dst, confirm=confirm)

                upload_thread = threading.Thread(target=do_put, daemon=True)
                upload_thread.start()
                upload_thread.join(timeout)
                if upload_thread.is_alive():
                    # Timed out
                    raise TimeoutError(
                        f"SFTP put timed out after {timeout} seconds: {src} -> {dst}"
                    )

            # ----------------------------------------------------------------------
            # WORKER FUNCTION
            # ----------------------------------------------------------------------
            def worker(action):
                atype, src, dst, size, mtime = action
                thread_id = threading.get_ident()
                thread_name = threading.current_thread().name

                if atype != "copy":
                    # For a "delete" action, we just do a single attempt
                    # (though you could add retry logic similarly if needed)
                    return do_delete(action)

                # (1) Mark this file as in-flight
                with in_flight_lock:
                    in_flight_actions.add((src, dst))
                    logger.debug(
                        f"[Thread {thread_name}/{thread_id}] ADDED in-flight: (src={src}, dst={dst})"
                    )

                # We'll retry up to 3 times if we hit a TimeoutError
                attempts = 3
                error: Optional[BaseException] = None

                for attempt_num in range(1, attempts + 1):
                    start_time = time.time()
                    logger.info(
                        f"[Thread {thread_name}/{thread_id}] -> START COPY (attempt {attempt_num}/{attempts}):\n"
                        f"    src={src}\n"
                        f"    dst={dst}\n"
                        f"    size={size} bytes\n"
                        f"    mtime={mtime}\n"
                    )

                    # (2) Get an SSH client from the queue
                    ssh_client = ssh_queue.get()
                    sftp = None
                    try:
                        try:
                            # Open fresh SFTP
                            sftp = ssh_client._client.open_sftp()
                            logger.debug(
                                f"[Thread {thread_name}/{thread_id}] SFTP session opened for attempt {attempt_num}."
                            )

                            # Show which file is being processed in tqdm
                            with pbar_lock:
                                pbar.set_description(
                                    f"Uploading {os.path.basename(src)}"
                                )

                            # Ensure remote dir
                            remote_dir = os.path.dirname(dst)
                            make_remote_dirs(sftp, remote_dir)

                            # (3) Actually do the upload with a 30s timeout
                            sftp_put_with_timeout(
                                sftp, src, dst, confirm=False, timeout=30.0
                            )

                            # If you want, you can set remote file times, but be aware some servers hang on setstat:
                            # sftp.utime(dst, (mtime, mtime))

                            # Update progress
                            with pbar_lock:
                                pbar.update(size)

                            # Success: break out of the attempts loop
                            error = None
                            logger.debug(
                                f"[Thread {thread_name}/{thread_id}] Upload succeeded on attempt {attempt_num}."
                            )
                            break

                        except TimeoutError as te:
                            error = te
                            logger.warning(
                                f"[Thread {thread_name}/{thread_id}] Timeout uploading file {src} -> {dst}, "
                                f"attempt {attempt_num}/{attempts}."
                            )

                        finally:
                            # (4) Always close SFTP
                            if sftp:
                                try:
                                    sftp.close()
                                    logger.debug(
                                        f"[Thread {thread_name}/{thread_id}] SFTP session closed."
                                    )
                                except Exception as e:
                                    logger.warning(
                                        f"[Thread {thread_name}/{thread_id}] Error closing SFTP session: {e}",
                                        exc_info=True,
                                    )
                            # Return the SSH client
                            ssh_queue.put(ssh_client)

                    except Exception as ex:
                        # Catch any other Paramiko or I/O errors
                        error = ex
                        logger.warning(
                            f"[Thread {thread_name}/{thread_id}] Unknown error in attempt {attempt_num}/{attempts}: {ex}",
                            exc_info=True,
                        )
                        # Decide if you want to retry or break immediately
                        # For safety, let's break after a non-timeout error
                        break

                    # If we timed out or had an error, let's keep looping unless we've exhausted attempts
                    if attempt_num < attempts:
                        logger.info(
                            f"[Thread {thread_name}/{thread_id}] Retrying file after error/time-out: "
                            f"{src} -> {dst}, attempt {attempt_num+1}/{attempts}"
                        )
                    else:
                        # We'll exit the for-loop if attempts are exhausted
                        pass

                # (5) Remove from in-flight
                with in_flight_lock:
                    if (src, dst) in in_flight_actions:
                        in_flight_actions.remove((src, dst))
                        logger.debug(
                            f"[Thread {thread_name}/{thread_id}] REMOVED in-flight: (src={src}, dst={dst})"
                        )

                # (6) If we have a leftover error after the final attempt, raise it
                # so the sync operation fails and doesn't silently skip the file.
                elapsed = time.time() - start_time
                if error is not None:
                    logger.error(
                        f"[Thread {thread_name}/{thread_id}] -> COPY FAILED after {attempts} attempts:\n"
                        f"    src={src}\n"
                        f"    dst={dst}\n"
                        f"    Last error: {error}"
                    )
                    raise error
                else:
                    logger.info(
                        f"[Thread {thread_name}/{thread_id}] -> END COPY (SUCCESS):\n"
                        f"    Elapsed: {elapsed:.2f} seconds (final attempt)\n"
                        f"    src={src}\n"
                        f"    dst={dst}"
                    )

            def do_delete(action):
                """Handle a 'delete' action quickly (no retry logic)."""
                atype, src, dst, size, mtime = action
                thread_id = threading.get_ident()
                thread_name = threading.current_thread().name

                ssh_client = ssh_queue.get()
                logger.info(
                    f"[Thread {thread_name}/{thread_id}] -> START DELETE:\n"
                    f"    dst={dst}"
                )
                sftp = None
                try:
                    sftp = ssh_client._client.open_sftp()
                    with pbar_lock:
                        pbar.set_description(
                            f"Deleting (remote) {os.path.basename(dst)}"
                        )
                    try:
                        sftp.remove(dst)
                    except IOError:
                        logger.warning(
                            f"[Thread {thread_name}/{thread_id}] Remote file not found for delete: {dst}"
                        )
                finally:
                    if sftp:
                        sftp.close()
                    ssh_queue.put(ssh_client)

                logger.info(f"[Thread {thread_name}/{thread_id}] -> END DELETE: {dst}")

            # ----------------------------------------------------------------------
            # MAIN EXECUTION
            # ----------------------------------------------------------------------
            from concurrent.futures import ThreadPoolExecutor, as_completed

            with tqdm(total=total_size, unit="B", unit_scale=True) as pbar:
                futures = []
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    for act in actions:
                        fut = executor.submit(worker, act)
                        futures.append(fut)

                    for i, fut in enumerate(as_completed(futures), start=1):
                        exc = fut.exception()
                        if exc:
                            logger.error(
                                f"[parallel_remote_uploads] Worker #{i} encountered an error:",
                                exc_info=True,
                            )
                            raise exc
                        else:
                            # At this point, the worker completed
                            with in_flight_lock:
                                if in_flight_actions:
                                    logger.debug(
                                        f"[parallel_remote_uploads] Worker #{i} done. "
                                        f"Still in flight: {list(in_flight_actions)}"
                                    )
                                else:
                                    logger.debug(
                                        f"[parallel_remote_uploads] Worker #{i} done. No remaining in-flight actions."
                                    )

            batch_elapsed = time.time() - batch_start_time
            logger.info(
                f"[parallel_remote_uploads] All actions completed.\n"
                f"Total elapsed: {batch_elapsed:.2f} seconds"
            )

        # ---------------------------------------------------------------------
        # 9) SYNC REMOTE->LOCAL
        # ---------------------------------------------------------------------
        def sync_from_remote(ssh_queue: queue.Queue, remote_path: str, local_path: str):
            """
            1) Use fast 'ls -lR' to gather remote info
            2) Gather local info
            3) Build copy/delete actions
            4) parallel_remote_downloads
            """
            import os

            # Let the first SSH client do the scanning
            ssh_client = ssh_queue.get()
            try:
                remote_info = get_file_info_via_ssh(ssh_client, remote_path)
            finally:
                ssh_queue.put(ssh_client)

            local_info = get_local_info(local_path)
            actions = []
            if not os.path.exists(local_path):
                logger.info(f"Creating local dir {local_path}")
                os.makedirs(local_path, exist_ok=True)

            # Build copy list
            for rfile, (rsize, rmtime) in remote_info.items():
                rel_path = os.path.relpath(rfile, remote_path)
                lfile = os.path.join(local_path, rel_path)
                copy_needed = True
                if lfile in local_info:
                    lsize, lmtime = local_info[lfile]
                    # mtime is 0.0 from remote if using `ls -lR` approach, so we only rely on size
                    if rsize == lsize:
                        copy_needed = False
                if copy_needed:
                    actions.append(("copy", rfile, lfile, rsize, rmtime))

            # Build delete list
            if delete:
                # If something is in local but not in remote_info, we remove it
                remote_files = set(
                    os.path.join(local_path, os.path.relpath(k, remote_path))
                    for k in remote_info.keys()
                )
                for lfile in local_info:
                    if lfile not in remote_files:
                        actions.append(("delete", None, lfile, 0, 0))

            total_copies = sum(1 for a in actions if a[0] == "copy")
            total_deletes = sum(1 for a in actions if a[0] == "delete")
            total_size_to_copy = sum(a[3] for a in actions if a[0] == "copy")

            logger.info("REMOTE->LOCAL Changes to be made:")
            logger.info(
                f"  Copy:   {total_copies} files ({format_size(total_size_to_copy)})"
            )
            if delete:
                logger.info(f"  Delete: {total_deletes} files")

            if not actions:
                logger.info("No changes needed (remote->local).")
                return

            if dry_run:
                logger.info("[DRY RUN] (remote->local) Actions:")
                for atype, src, dst, size, mtime in actions:
                    if atype == "copy":
                        logger.info(
                            f"  Would copy: {src} -> {dst} ({format_size(size)})"
                        )
                    else:
                        logger.info(f"  Would delete: {dst}")
                return

            parallel_remote_downloads(actions, total_size_to_copy, ssh_queue)

        # ---------------------------------------------------------------------
        # 10) SYNC LOCAL->REMOTE
        # ---------------------------------------------------------------------
        def sync_to_remote(ssh_queue: queue.Queue, local_path: str, remote_path: str):
            """
            Sync local_path -> remote_path using a single 'ls -lR' pass on the remote side.
            We also create the remote_path if it doesn't exist yet.
            """
            import os

            logger.info("Gathering local file info...")
            local_info = get_local_info(local_path)
            logger.debug(f"Local file info found: {len(local_info)} files.")

            # Acquire a single SSH client from the pool to do the remote 'ls -lR' scan
            ssh_client = ssh_queue.get()
            try:
                # Ensure the top-level remote_path directory exists
                sftp = ssh_client._client.open_sftp()
                make_remote_dirs(sftp, remote_path)
                sftp.close()

                # Gather remote info via 'ls -lR'
                logger.info(
                    f"Gathering remote file info via ls -lR on '{remote_path}'..."
                )
                try:
                    remote_info = get_file_info_via_ssh(ssh_client, remote_path)
                except Exception as e:
                    logger.warning(
                        f"Could not retrieve remote file info for '{remote_path}'. "
                        f"Assuming empty directory. Error: {e}"
                    )
                    remote_info = {}
            finally:
                # Return the SSH client to the pool
                ssh_queue.put(ssh_client)

            # Build copy/delete actions
            actions = []
            for lfile, (lsize, lmtime) in local_info.items():
                rel_path = os.path.relpath(lfile, local_path).replace("\\", "/")
                rfile = os.path.join(remote_path, rel_path).replace("\\", "/")
                copy_needed = True
                # If remote file exists and sizes match, skip
                if rfile in remote_info:
                    rsize, _ = remote_info[rfile]
                    if lsize == rsize:
                        copy_needed = False
                if copy_needed:
                    actions.append(("copy", lfile, rfile, lsize, lmtime))

            if delete:
                # Delete files on remote if they don't exist locally
                local_targets = {
                    os.path.join(remote_path, os.path.relpath(k, local_path)).replace(
                        "\\", "/"
                    )
                    for k in local_info.keys()
                }
                for rfile in remote_info:
                    if rfile not in local_targets:
                        actions.append(("delete", None, rfile, 0, 0))

            total_copies = sum(1 for a in actions if a[0] == "copy")
            total_deletes = sum(1 for a in actions if a[0] == "delete")
            total_size_to_copy = sum(a[3] for a in actions if a[0] == "copy")

            logger.info("LOCAL->REMOTE Changes to be made:")
            logger.info(
                f"  Copy:   {total_copies} files ({format_size(total_size_to_copy)})"
            )
            if delete:
                logger.info(f"  Delete: {total_deletes} files")

            if not actions:
                logger.info("No changes needed (local->remote).")
                return

            # Dry run?
            if dry_run:
                logger.info("[DRY RUN] (local->remote) Actions:")
                for atype, src, dst, size, _ in actions:
                    if atype == "copy":
                        logger.info(
                            f"  Would copy: {src} -> {dst} ({format_size(size)})"
                        )
                    else:
                        logger.info(f"  Would delete: {dst}")
                return

            # Perform uploads/deletes in parallel
            parallel_remote_uploads(actions, total_size_to_copy, ssh_queue)

        # ---------------------------------------------------------------------
        # 11) MAIN LOGIC
        # ---------------------------------------------------------------------
        try:
            src_inst, src_path_ = parse_instance_path(source_path)
            dst_inst, dst_path_ = parse_instance_path(dest_path)

            # Exactly one must be remote
            if (src_inst and dst_inst) or (not src_inst and not dst_inst):
                raise ValueError(
                    "One (and only one) path must be remote (instance_id:/path)"
                )

            instance_id = src_inst or dst_inst
            if instance_id != self.id:
                raise ValueError(f"Instance ID mismatch: {instance_id} != {self.id}")

            # Create a pool of SSH connections
            ssh_pool = create_ssh_pool(max_workers)
            try:
                if src_inst:
                    # remote->local
                    logger.info(
                        f"{'[DRY RUN] ' if dry_run else ''}Syncing FROM remote -> local, parallel."
                    )
                    sync_from_remote(ssh_pool, src_path_, dst_path_)
                else:
                    # local->remote
                    logger.info(
                        f"{'[DRY RUN] ' if dry_run else ''}Syncing TO remote <- local, parallel."
                    )
                    sync_to_remote(ssh_pool, src_path_, dst_path_)
            finally:
                close_ssh_pool(ssh_pool)

        except Exception as e:
            logger.error(f"Sync operation failed: {e}", exc_info=True)
            raise
