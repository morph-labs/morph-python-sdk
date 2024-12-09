from __future__ import annotations

import os
import time
import enum
import typing
import logging

import httpx

from pydantic import BaseModel, Field

logger = logging.getLogger("morphcloud.api")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

MORPH_API_BASE_URL = os.environ.get("MORPH_BASE_URL", "https://cloud.morph.so/api")
MORPH_API_KEY = os.environ.get("MORPH_API_KEY")

morph_api_client = httpx.Client(
    base_url=MORPH_API_BASE_URL,
    headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {MORPH_API_KEY}",
    },
    timeout=None
)

class Image(BaseModel):
    id: str = Field(..., description="Unique identifier for the base image, like img_xxxx")
    object: typing.Literal["image"] = Field("image", description="Object type, always 'image'")
    name: str = Field(..., description="Name of the base image")
    description: typing.Optional[str] = Field(None, description="Description of the base image")
    disk_size: int = Field(..., description="Size of the base image in bytes")
    created: int = Field(..., description="Unix timestamp of when the base image was created")

    @classmethod
    def list(cls) -> typing.List[Image]:
        """List all base images available to the user."""
        response = morph_api_client.get("/image")
        response.raise_for_status()
        return [Image(**image) for image in response.json()["data"]]

class SnapshotStatus(enum.StrEnum):
    # the snapshot is being created and is not yet ready
    PENDING = "pending"
    # the snapshot is ready to be used
    READY = "ready"
    # the snapshot creation job failed
    FAILED = "failed"
    # the snapshot is being deleted
    DELETING = "deleting"
    # the snapshot has been deleted
    DELETED = "deleted"

class ResourceSpec(BaseModel):
    vcpus: int = Field(..., description="VCPU Count of the snapshot")
    memory: int = Field(..., description="Memory of the snapshot in megabytes")
    disk_size: int = Field(..., description="Size of the snapshot in megabytes")

class SnapshotRefs(BaseModel):
    image_id: str

class Snapshot(BaseModel):
    id: str = Field(..., description="Unique identifier for the snapshot, like snapshot_xxxx")
    object: typing.Literal["snapshot"] = Field("snapshot", description="Object type, always 'snapshot'")
    created: int = Field(..., description="Unix timestamp of when the snapshot was created")
    status: SnapshotStatus = Field(..., description="Status of the snapshot")
    spec: ResourceSpec = Field(..., description="Resource specifications")
    refs: SnapshotRefs = Field(..., description="Referenced resources")
    digest: typing.Optional[str] = Field(default=None, description="User provided digest of the snapshot content")

    @classmethod
    def list(cls, digest: typing.Optional[str] = None) -> typing.List[Snapshot]:
        """List all snapshots available to the user."""
        params = {}
        if digest is not None:
            params["digest"] = digest
        response = morph_api_client.get("/snapshot", params=params)
        response.raise_for_status()
        return [Snapshot(**snapshot) for snapshot in response.json()["data"]]

    @classmethod
    def create(cls,
        image_id: typing.Optional[str] = None,
        vcpus: typing.Optional[int] = None,
        memory: typing.Optional[int] = None,
        disk_size: typing.Optional[int] = None,
        digest: typing.Optional[str] = None,
    ) -> Snapshot:
        """Create a new snapshot from a base image and a machine configuration."""
        response = morph_api_client.post(
            "/snapshot",
            json={
                "image_id": image_id,
                "vcpus": vcpus,
                "memory": memory,
                "disk_size": disk_size,
                "digest": digest,
                "readiness_check": {
                    "type": "timeout",
                    "timeout": 10.0
                }
            },
        )
        response.raise_for_status()
        return Snapshot(**response.json())

    def delete(self) -> None:
        """Delete the snapshot."""
        response = morph_api_client.delete(f"/snapshot/{self.id}")
        if response.status_code == 409:
            logger.error(response.json())
            raise RuntimeError("Snapshot is in use and cannot be deleted")
        response.raise_for_status()

class InstanceStatus(enum.StrEnum):
    # the instance is being created and is not yet ready
    PENDING = "pending"
    # the instance is ready to be used
    READY = "ready"
    # the instance is being saved and is not yet ready to be used
    SAVING = "saving"
    # the instance encountered an error during
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

class Instance(BaseModel):
    id: str
    object: typing.Literal["instance"] = "instance"
    created: int
    status: InstanceStatus = InstanceStatus.PENDING
    spec: ResourceSpec
    refs: InstanceRefs
    networking: InstanceNetworking

    @classmethod
    def list(cls) -> typing.List[Instance]:
        """List all instances available to the user."""
        response = morph_api_client.get("/instance")
        response.raise_for_status()
        return [Instance(**instance) for instance in response.json()["data"]]

    @classmethod
    def start(
        cls,
        snapshot_id: str,
    ) -> Instance:
        """Create a new instance from a snapshot and a machine configuration."""
        response = morph_api_client.post(
            "/instance",
            params={
                "snapshot_id": snapshot_id,
            },
        )
        response.raise_for_status()
        return Instance(**response.json())

    @classmethod
    def get(cls, instance_id: str) -> Instance:
        """Get an instance by its ID."""
        response = morph_api_client.get(f"/instance/{instance_id}")
        response.raise_for_status()
        return Instance(**response.json())

    def stop(self) -> None:
        """Stop the instance."""
        response = morph_api_client.delete(f"/instance/{self.id}")
        response.raise_for_status()

    @staticmethod
    def stop_by_id(snapshot_id: str) -> None:
        """Stop the instance by its ID."""
        response = morph_api_client.delete(f"/instance/{snapshot_id}")
        response.raise_for_status()

    def snapshot(self) -> Snapshot:
        """Save the instance as a snapshot."""
        response = morph_api_client.post(f"/instance/{self.id}/snapshot")
        response.raise_for_status()
        return Snapshot(**response.json())

    def clone(self, count: int) -> typing.List[Instance]:
        """Clone the instance."""
        response = morph_api_client.post(f"/instance/{self.id}/clone", json={"count": count})
        response.raise_for_status()
        return [Instance(**instance) for instance in response.json()]

    def expose_http_service(self, name: str, port: int) -> None:
        """Expose an HTTP service."""
        response = morph_api_client.post(
            f"/instance/{self.id}/http",
            json={"name": name, "port": port},
        )
        response.raise_for_status()

    def unexpose_http_service(self, name: str) -> None:
        """Unexpose an HTTP service."""
        response = morph_api_client.delete(f"/instance/{self.id}/http/{name}")
        response.raise_for_status()

    def exec(self, command: typing.Union[str, typing.List[str]]) -> InstanceExecResponse:
        """Execute a command on the instance."""
        command = [command] if isinstance(command, str) else command
        response = morph_api_client.post(
            f"/instance/{self.id}/exec",
            json={"command": command},
        )
        response.raise_for_status()
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
        instance = Instance.get(self.id)
        self.__dict__.update(instance.__dict__)
