from __future__ import annotations

import os
import enum
import time
import logging
import hashlib
import subprocess

from datetime import datetime
from typing import Any, Dict, Optional, Union, List, Literal

import fire
import httpx

from pydantic import BaseModel

logger = logging.getLogger("morphcloud")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Constants
BASE_URL = os.getenv("MORPH_BASE_URL", "https://cloud.morph.so/api")
SSH_PORTAL_HOST = BASE_URL.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
SSH_PORTAL_PORT = os.getenv("SSH_PORTAL_PORT", "2222")

API_ENDPOINT = "/instance/{instance_id}/codelink"


def _default_snapshot():
    return {
        "image_id": "morphvm-minimal",
        "vcpus": 1,
        "memory": 128,
        "disk_size": 700,
        "readiness_check": {
            "type": "timeout",
            "timeout": 5,
        },
    }


def _get_headers(api_key: Optional[str] = None):
    return {
        "Authorization": f'Bearer {api_key or os.getenv("MORPH_API_KEY")}',
        "Content-Type": "application/json",
    }

morph_base_url = BASE_URL
morph_api_base_vm = 'morphvm'
morphvm_http_client = httpx.Client(
    base_url=f"{morph_base_url}/{morph_api_base_vm}",
    follow_redirects=True,
    headers=_get_headers(),
    timeout=None
)

class SnapshotStatus(enum.Enum):
    PENDING = "pending"
    READY = "ready"
    FAILED = "failed"
    DELETING = "deleting"
    DELETED = "deleted"

class VmSnapshot(BaseModel):
    id: str
    object: Literal["snapshot"] = "snapshot"
    image_id: str
    created: datetime
    status: SnapshotStatus
    vcpus: float
    memory: float
    user_id: str
    digest: Optional[str] = None
    instances: Optional[List[Any]] = None
    owner: Optional[Any] = None

    def __post_init__(self):
        if self.instances is None:
            self.instances = []

    @staticmethod
    def create(vm: MorphVm, digest: Optional[str] = None):
        """
        Create a snapshot from an instance or configuration.

        Args:
            vm: MorphVM instance containing client configuration
            digest: Optional digest string for the snapshot

        Returns:
            Dict containing the created snapshot details
        """
        if not vm.id:
            raise ValueError("No instance_id specified")

        # If no digest provided, create one based on instance_id and timestamp
        if not digest:
            timestamp = str(int(time.time()))
            unique_string = f"{vm.id}_{timestamp}"
            digest = hashlib.sha256(unique_string.encode()).hexdigest()

        response = morphvm_http_client.post(
            f"/instance/{vm.id}/snapshot",
            headers=_get_headers(),
            params={"digest": digest},
        )
        response.raise_for_status()
        return VmSnapshot(**response.json())

    @classmethod
    def _create_from_image(
        cls,
        image_id: str,
        vcpus: int,
        memory: int,
        disk_size: int,
        readiness_check: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> "VmSnapshot":
        resp = morphvm_http_client.post(
            "/snapshot",
            json={
                "image_id": image_id,
                "vcpus": vcpus,
                "memory": memory,
                "disk_size": disk_size,
                "readiness_check": readiness_check,
            },
            headers=_get_headers(api_key=kwargs.get("api_key")),
        )
        resp.raise_for_status()
        return cls(**resp.json())

    @staticmethod
    def list(api_key: Optional[str] = None) -> List["VmSnapshot"]:
        """
        List all available snapshots

        Returns:
            List of snapshot objects
        """
        response = morphvm_http_client.get(
            "/snapshot",
            headers=_get_headers(api_key=api_key),
        )
        response.raise_for_status()
        return [VmSnapshot(**x) for x in response.json()]

    @staticmethod
    def delete(snapshot_id: str, api_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Delete a snapshot by ID.

        Args:
            snapshot_id: ID of the snapshot to delete

        Returns:
            Dict containing the deletion response
        """
        response = morphvm_http_client.delete(
            f"/snapshot/{snapshot_id}",
            headers=_get_headers(api_key=api_key),
        )
        response.raise_for_status()
        return response.json()


class MorphVm(BaseModel):
    """A MorphVM instance"""

    # Core configuration
    id: str
    object: Literal["instance"] = "instance"
    # base_url: str = BASE_URL
    # timeout: int = 30

    @property
    def instance_id(self):
        return self.id

    def snapshot(self) -> VmSnapshot:
        return VmSnapshot.create(self)

    def exec(self, command: Union[str, List[str]]):
        """
        Execute a command or list of commands on the Morph VM instance.

        Args:
            command: A single command string or list of command strings to execute

        Returns:
            Dict containing the execution response

        Example:
            >>> vm.exec("ls -la")
            >>> vm.exec(["cd /tmp", "touch test.txt"])
        """
        if isinstance(command, str):
            command = [command]

        response = morphvm_http_client.post(
            f"/instance/{self.id}/exec",
            json={"command": command},
            headers=_get_headers(),
        )
        response.raise_for_status()
        output = response.json()
        return {
            "stdout": output["stdout"],
            "stderr": output["stderr"],
            "exit_code": output["exit_code"],
        }

    def upload_file(self, local_file_path: str, remote_file_path: str, **kwargs):
        """Upload a file to the Morph VM instance"""
        if not os.path.exists(local_file_path):
            raise FileNotFoundError(f"Local file does not exist: {local_file_path}")

        ssh_host = SSH_PORTAL_HOST
        ssh_port = SSH_PORTAL_PORT
        ssh_user = f"{self.id}:{kwargs.get('api_key', os.getenv('MORPH_API_KEY'))}"

        ssh_key_path = os.path.expanduser("~/.ssh/id_ed25519")
        if not os.path.exists(ssh_key_path):
            ssh_key_path = os.path.expanduser("~/.ssh/id_rsa")
        if not os.path.exists(ssh_key_path):
            raise FileNotFoundError(
                f"You don't have an SSH key in your ~/.ssh directory. Please create one with `ssh-keygen`. This is required for uploading files to the vm."
            )

        scp_command = f'scp -o StrictHostKeyChecking=no -o "User={ssh_user}" -i {ssh_key_path} -P {ssh_port} {local_file_path} {ssh_host}:{remote_file_path}'
        logger.info(f"Uploading file to vm: {scp_command}")
        return subprocess.run(scp_command, shell=True)

    @classmethod
    def create(
        cls,
        vcpus: Optional[int] = None,
        memory: Optional[int] = None,
        disk_size: Optional[int] = None,
        snapshot_id: Optional[str] = None,
        digest: Optional[str] = None,
        ports: Optional[List[Dict[str, Any]]] = None,
        **kwargs,
    ) -> MorphVm:
        """Create a new MorphVM instance"""
        default_snapshot = _default_snapshot()

        vcpus = vcpus or default_snapshot["vcpus"]
        memory = memory or default_snapshot["memory"]
        disk_size = disk_size or default_snapshot["disk_size"]
        
        if snapshot_id:
            # create a morphVM from the existing snapshot

            resp = morphvm_http_client.post(
                "/instance",
                params={
                    "snapshot_id": snapshot_id,
                    "http_services": ports,
                },
                headers=_get_headers(api_key=kwargs.get("api_key")),
            )
            resp.raise_for_status()

            runtime = cls(**resp.json())
            runtime._wait_ready()

            return runtime

        # hash vcpus, memory, and setup to create a unique snapshot digest
        snapshot_digest = digest or "sha256:" + hashlib.sha256(
            f"{vcpus}-{memory}-{disk_size}".encode()
        ).hexdigest()

        # try to create a snapshot with the given digest
        snapshot = next(
            (
                s
                for s in VmSnapshot.list(kwargs.get("api_key"))
                if s.digest == snapshot_digest
            ),
            None,
        )

        if snapshot:
            # create a VM from the existing snapshot
            snapshot_id = snapshot.id

            resp = morphvm_http_client.post(
                "/instance",
                params={
                    "snapshot_id": snapshot_id,
                    "http_services": ports,
                },
                headers=_get_headers(api_key=kwargs.get("api_key")),
            )
            resp.raise_for_status()

            vm = cls(**resp.json())
            vm._wait_ready()

            return vm

        config = _default_snapshot()

        if vcpus:
            config["vcpus"] = vcpus

        if memory:
            config["memory"] = memory

        if disk_size:
            config["disk_size"] = disk_size

        initial_snapshot = VmSnapshot._create_from_image(
            image_id=config["image_id"],
            vcpus=vcpus,
            memory=memory,
            disk_size=disk_size,
            readiness_check=config.get("readiness_check"),
            api_key=kwargs.get("api_key"),
        )
        snapshot_id = initial_snapshot.id

        resp = morphvm_http_client.post(
            "/instance",
            params={
                "snapshot_id": snapshot_id,
                "http_services": ports,
            },
            headers=_get_headers(api_key=kwargs.get("api_key")),
        )
        resp.raise_for_status()

        vm = cls(**resp.json())
        vm._wait_ready()

        # save snapshot
        snapshot = VmSnapshot.create(vm, snapshot_digest)

        # cleanup initial snapshot
        VmSnapshot.delete(snapshot_id, api_key=kwargs.get("api_key"))

        return vm

    def clone(
        self, num_clones: int = 1, api_key: Optional[str] = None
    ) -> List[MorphVm]:
        """Create a clone of this MorphVM"""
        resp = morphvm_http_client.post(
            f"/instance/{self.instance_id}/clone",
            json={"num_clones": num_clones},
            headers=_get_headers(api_key=api_key),
        )
        resp.raise_for_status()

        return [
            MorphVm(
                **vm
            )
            for vm in resp.json()
        ]

    def __enter__(self) -> MorphVm:
        return self

    def __exit__(self, *_):
        self.stop()

    def stop(self):
        """Stop the MorphVM instance"""
        if self.instance_id:
            try:
                morphvm_http_client.delete(f"/instance/{self.instance_id}")
            finally:
                pass

    @classmethod
    def list(cls, **kwargs) -> List[MorphVm]:
        """List all MorphVM instances"""
        resp = morphvm_http_client.get(
            "/instance", headers=_get_headers(api_key=kwargs.get("api_key"))
        )
        resp.raise_for_status()
        return [MorphVm(**r) for r in resp.json()]

    def _wait_ready(self, timeout: Optional[int] = None):
        """Wait for MorphVM to be ready"""
        wait_timeout = (timeout or 30)
        deadline = time.time() + wait_timeout
        while time.time() < deadline:
            if self.status == "ready":
                return
            time.sleep(2.0)
        raise TimeoutError(f"MorphVM failed to become ready within {wait_timeout=}s")

    @property
    def status(self) -> Optional[str]:
        try:
            return morphvm_http_client.get(f"/instance/{self.instance_id}").json().get("status")
        except Exception as e:
            logger.error(f"[MorphVm.status] caught {e=}")
            return None

    def _execute(self, command: List[str]) -> Dict[str, Any]:
        resp = morphvm_http_client.post(
            f"/instance/{self.instance_id}/exec",
            json={"command": command},
            headers=self.headers,
        )
        resp.raise_for_status()
        return resp.json()


if __name__ == "__main__":
    fire.Fire(locals())

