from __future__ import annotations

import os
import time
import enum
import json
import typing
import logging

import httpx

from pydantic import BaseModel, Field, PrivateAttr


logger = logging.getLogger("morphcloud.api")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter(
    "%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s"
)
handler.setFormatter(formatter)
logger.addHandler(handler)


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


class MorphCloudClient:
    def __init__(
        self,
        api_key: typing.Optional[str] = None,
        base_url: typing.Optional[str] = None,
    ):
        self.base_url = base_url or os.environ.get("MORPH_BASE_URL", "https://cloud.morph.so/api")
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
        return [Image(**image)._set_api(self) for image in response.json()["data"]]


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
    def list(self, digest: typing.Optional[str] = None) -> typing.List[Snapshot]:
        """List all snapshots available to the user."""
        params = {}
        if digest is not None:
            params["digest"] = digest
        response = self._client._http_client.get("/snapshot", params=params)
        return [Snapshot(**snapshot)._set_api(self) for snapshot in response.json()["data"]]

    def create(
        self,
        image_id: typing.Optional[str] = None,
        vcpus: typing.Optional[int] = None,
        memory: typing.Optional[int] = None,
        disk_size: typing.Optional[int] = None,
        digest: typing.Optional[str] = None,
    ) -> Snapshot:
        """Create a new snapshot from a base image and a machine configuration."""
        response = self._client._http_client.post(
            "/snapshot",
            json={
                "image_id": image_id,
                "vcpus": vcpus,
                "memory": memory,
                "disk_size": disk_size,
                "digest": digest,
                "readiness_check": {"type": "timeout", "timeout": 10.0},
            },
        )
        return Snapshot(**response.json())._set_api(self)

    def get(self, snapshot_id: str) -> Snapshot:
        """Get a snapshot by ID."""
        response = self._client._http_client.get(f"/snapshot/{snapshot_id}")
        return Snapshot(**response.json())._set_api(self)


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

    _api: SnapshotAPI = PrivateAttr()

    def _set_api(self, api: SnapshotAPI) -> Snapshot:
        self._api = api
        return self

    def delete(self) -> None:
        """Delete the snapshot."""
        response = self._api._client._http_client.delete(f"/snapshot/{self.id}")
        if response.status_code == 409:
            logger.error(response.json())
            raise RuntimeError("Snapshot is in use and cannot be deleted")


class InstanceStatus(enum.StrEnum):
    PENDING = "pending"
    READY = "ready"
    SAVING = "saving"
    ERROR = "error"


class InstanceHttpService(BaseModel):
    name: str
    port: int


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
    def list(self) -> typing.List[Instance]:
        """List all instances available to the user."""
        response = self._client._http_client.get("/instance")
        return [Instance(**instance)._set_api(self) for instance in response.json()["data"]]

    def start(self, snapshot_id: str) -> Instance:
        """Create a new instance from a snapshot."""
        response = self._client._http_client.post(
            "/instance",
            params={"snapshot_id": snapshot_id},
        )
        return Instance(**response.json())._set_api(self)

    def get(self, instance_id: str) -> Instance:
        """Get an instance by its ID."""
        response = self._client._http_client.get(f"/instance/{instance_id}")
        return Instance(**response.json())._set_api(self)

    def stop(self, instance_id: str) -> None:
        """Stop an instance by its ID."""
        response = self._client._http_client.delete(f"/instance/{instance_id}")
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

    def _set_api(self, api: InstanceAPI) -> Instance:
        self._api = api
        return self

    def stop(self) -> None:
        """Stop the instance."""
        self._api.stop(self.id)

    def snapshot(self) -> Snapshot:
        """Save the instance as a snapshot."""
        response = self._api._client._http_client.post(f"/instance/{self.id}/snapshot")
        return Snapshot(**response.json())._set_api(self._api._client.snapshots)

    def branch(self, count: int) -> typing.Tuple[Snapshot, typing.List[Instance]]:
        """Branch the instance into multiple copies."""
        response = self._api._client._http_client.post(
            f"/instance/{self.id}/branch", params={"count": count}
        )
        _json = response.json()
        snapshot = Snapshot(**_json["snapshot"])._set_api(
            self._api._client.snapshots
        )
        instances = [
            Instance(**instance)._set_api(self._api)
            for instance in _json["instances"]
        ]
        return snapshot, instances

    def expose_http_service(self, name: str, port: int) -> None:
        """Expose an HTTP service."""
        response = self._api._client._http_client.post(
            f"/instance/{self.id}/http",
            json={"name": name, "port": port},
        )
        response.raise_for_status()
        self._refresh()

    def hide_http_service(self, name: str) -> None:
        """Unexpose an HTTP service."""
        response = self._api._client._http_client.delete(
            f"/instance/{self.id}/http/{name}"
        )
        response.raise_for_status()
        self._refresh()

    def exec(
        self, command: typing.Union[str, typing.List[str]]
    ) -> InstanceExecResponse:
        """Execute a command on the instance."""
        command = [command] if isinstance(command, str) else command
        response = self._api._client._http_client.post(
            f"/instance/{self.id}/exec",
            json={"command": command},
        )
        return InstanceExecResponse(**response.json())

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

    def _refresh(self) -> None:
        """Refresh the instance data."""
        instance = self._api.get(self.id)
        for key, value in instance.model_dump().items():
            setattr(self, key, value)
