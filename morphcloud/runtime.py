from __future__ import annotations

import os
import enum
import json
import time
import hashlib
import subprocess

from datetime import datetime
from functools import wraps
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Union, List, Literal

from morphcloud.utils import (
    get_iframe_object_from_instance_id,
    to_camel_case,
    to_snake_case,
)
from morphcloud.actions import ide_actions

import fire
import httpx

from pydantic import BaseModel

# Constants
BASE_URL = os.getenv("MORPH_BASE_URL", "https://cloud.morph.so")
SSH_PORTAL_HOST = os.getenv("SSH_PORTAL_HOST", "127.0.0.1")
SSH_PORTAL_PORT = os.getenv("SSH_PORTAL_PORT", "2224")

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


class SnapshotStatus(enum.Enum):
    PENDING = "pending"
    READY = "ready"
    FAILED = "failed"
    DELETING = "deleting"
    DELETED = "deleted"


def get_headers(api_key: Optional[str] = None):
    return {
        "Authorization": f'Bearer {api_key or os.getenv("MORPH_API_KEY")}',
        "Content-Type": "application/json",
    }

_base_url = BASE_URL
_http = httpx.Client(
    base_url=_base_url,
    follow_redirects=True,
    headers=get_headers(),
    timeout=None
)


class Snapshot(BaseModel):
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
    def create(runtime: Runtime, digest: Optional[str] = None):
        """
        Create a snapshot from an instance or configuration.

        Args:
            runtime: Runtime instance containing client configuration
            digest: Optional digest string for the snapshot

        Returns:
            Dict containing the created snapshot details
        """
        if not runtime.instance_id:
            raise ValueError("No instance_id specified")

        # If no digest provided, create one based on instance_id and timestamp
        if not digest:
            timestamp = str(int(time.time()))
            unique_string = f"{runtime.instance_id}_{timestamp}"
            digest = hashlib.sha256(unique_string.encode()).hexdigest()

        response = _http.post(
            f"/instance/{runtime.instance_id}/snapshot",
            headers=runtime.headers,
            params={"digest": digest},
        )
        response.raise_for_status()
        return Snapshot(**response.json())

    @classmethod
    def _create_from_image(
        cls,
        image_id: str,
        vcpus: int,
        memory: int,
        disk_size: int,
        readiness_check: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> "Snapshot":
        resp = _http.post(
            "/snapshot",
            json={
                "image_id": image_id,
                "vcpus": vcpus,
                "memory": memory,
                "disk_size": disk_size,
                "readiness_check": readiness_check,
            },
            headers=get_headers(api_key=kwargs.get("api_key")),
        )
        resp.raise_for_status()
        return cls(**resp.json())

    @staticmethod
    def list(api_key: Optional[str] = None) -> List["Snapshot"]:
        """
        List all available snapshots.

        Args:
            runtime: Runtime instance containing client configuration

        Returns:
            List of snapshot objects
        """
        response = _http.get(
            "/snapshot",
            headers=get_headers(api_key=api_key),
        )
        response.raise_for_status()
        return [Snapshot(**x) for x in response.json()]

    @staticmethod
    def delete(snapshot_id: str, api_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Delete a snapshot by ID.

        Args:
            runtime: Runtime instance containing client configuration
            snapshot_id: ID of the snapshot to delete

        Returns:
            Dict containing the deletion response
        """
        response = _http.delete(
            f"{_base_url}/snapshot/{snapshot_id}",
            headers=get_headers(api_key=api_key),
        )
        response.raise_for_status()
        return response.json()


class RuntimeInterface:
    def __init__(self, runtime):
        self._runtime = runtime
        self._load_actions()

    def _format_docstring(self, action: Dict[str, Any]) -> str:
        """Create formatted markdown docstring from action details"""
        params = [
            {**p, "name": to_snake_case(p["name"])}
            for p in action.get("parameters", [])
        ]

        doc = f"{action['description']}\n\n"

        if params:
            doc += "Parameters:\n"
            for param in params:
                optional_str = " (optional)" if param.get("optional", False) else ""
                doc += f"- {param['name']}{optional_str}: {param['type']}\n    {param['description']}\n"

        if "returns" in action:
            doc += "\nReturns:\n"
            doc += f"    {json.dumps(action['returns'], indent=4)}\n"

        if "examples" in action:
            doc += "\nExamples:\n"
            for example in action["examples"]:
                doc += f"    {example}\n"

        return doc

    def _create_interface_wrapper(self, action_details: Dict[str, Any]):
        """Create an execution wrapper that handles camelCase conversion"""

        @wraps(self._runtime._run)
        def wrapper(*args, **kwargs):
            camel_kwargs = {to_camel_case(k): v for k, v in kwargs.items()}

            action_request = {
                "action_type": action_details["name"],
                "parameters": camel_kwargs,
            }

            return self._runtime._run(action_request)

        return wrapper

    def _load_actions(self):
        """Load actions from actions.py and create corresponding methods"""
        for action in ide_actions["actions"]:
            snake_name = to_snake_case(action["name"])
            interface_method = self._create_interface_wrapper(action)
            interface_method.__doc__ = self._format_docstring(action)
            setattr(self, snake_name, interface_method)

    def render(self, target: str = "anthropic") -> List[Dict[str, Any]]:
        """
        Render actions in specified target format.

        Args:
            target: Format to render as ('anthropic' or 'openai')
        """
        seen_names = set()
        tools = []

        for action in ide_actions["actions"]:
            name = to_snake_case(action["name"])
            if name in seen_names:
                continue
            seen_names.add(name)

            properties = {}
            required = []

            for param in action.get("parameters", []):
                param_name = to_snake_case(param["name"])
                prop = {
                    "type": param["type"],
                    "description": param.get("description", ""),
                }

                if target == "openai":
                    if "enum" in param:
                        prop["enum"] = param["enum"]
                    if param.get("type") == "array" and "items" in param:
                        prop["items"] = {
                            "type": param["items"].get("type"),
                        }
                        if "enum" in param["items"]:
                            prop["items"]["enum"] = param["items"]["enum"]

                properties[param_name] = prop

                if not param.get("optional", False):
                    required.append(param_name)

            if target == "anthropic":
                tools.append(
                    {
                        "name": name,
                        "description": action["description"],
                        "input_schema": {
                            "type": "object",
                            "properties": properties,
                            "required": required,
                        },
                    }
                )
            else:  # openai
                parameters = {
                    "type": "object",
                    "properties": properties,
                }
                if required:
                    parameters["required"] = required

                tools.append(
                    {
                        "type": "function",
                        "function": {
                            "name": name,
                            "description": action["description"],
                            "parameters": parameters,
                        },
                    }
                )

        return tools


@dataclass
class Runtime:
    """A Morph runtime instance"""

    # Core configuration
    instance_id: Optional[str] = None
    api_key: Optional[str] = field(default_factory=lambda: os.getenv("MORPH_API_KEY"))
    base_url: str = BASE_URL
    timeout: int = 30

    # Internal state
    interface: Optional[RuntimeInterface] = None

    def __post_init__(self):
        """Initialize HTTP client and sub-clients after dataclass initialization"""
        if not self.api_key:
            raise ValueError(
                "API key required. Provide api_key or set MORPH_API_KEY environment variable"
            )

        self.interface = RuntimeInterface(self)

    @property
    def headers(self):
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def snapshot(self) -> Snapshot:
        return Snapshot.create(self)

    def exec(self, command: Union[str, List[str]]) -> Dict[str, Any]:
        """
        Execute a command or list of commands on the runtime instance.

        Args:
            command: A single command string or list of command strings to execute

        Returns:
            Dict containing the execution response

        Example:
            >>> runtime.exec("ls -la")
            >>> runtime.exec(["cd /tmp", "touch test.txt"])
        """
        if isinstance(command, str):
            command = [command]

        response = _http.post(
            f"/instance/{self.instance_id}/exec",
            json={"command": command},
            headers=self.headers,
        )
        response.raise_for_status()
        return response.json()

    @property
    def remote_desktop_url(self):
        return f"{self.base_url}/ui/instance/{self.instance_id}"

    @property
    def remote_desktop_iframe(self):
        if not self.instance_id:
            raise ValueError("instance_id is required to get the remote desktop iframe")
        return get_iframe_object_from_instance_id(self.base_url, self.instance_id)

    def upload_file(self, local_file_path: str, remote_file_path: str):
        """Upload a file to the runtime instance"""
        if not os.path.exists(local_file_path):
            raise FileNotFoundError(f"Local file does not exist: {local_file_path}")

        ssh_host = SSH_PORTAL_HOST
        ssh_port = SSH_PORTAL_PORT
        ssh_user = f"{self.instance_id}:{self.api_key}"

        ssh_key_path = os.path.expanduser("~/.ssh/id_ed25519")
        if not os.path.exists(ssh_key_path):
            ssh_key_path = os.path.expanduser("~/.ssh/id_rsa")
        if not os.path.exists(ssh_key_path):
            raise FileNotFoundError(
                f"You don't have an SSH key in your ~/.ssh directory. Please create one with `ssh-keygen`. This is required for uploading files to the runtime."
            )

        scp_command = f'scp -o "User={ssh_user}" -i {ssh_key_path} -P {ssh_port} {local_file_path} {ssh_host}:{remote_file_path}'
        print(f"Uploading file to runtime: {scp_command}")
        return subprocess.run(scp_command, shell=True)

    def _prepare_custom_container(self, local_rootfs_path: str, init_cmd: str):
        # Check if local rootfs path exists
        if not os.path.exists(local_rootfs_path):
            raise FileNotFoundError(
                f"Local rootfs path does not exist: {local_rootfs_path}"
            )

        # Upload rootfs to runtime using SCP
        self.upload_file(local_rootfs_path, "/rootfs.tar")

        # Extract rootfs
        self.exec(["tar -xvf /rootfs.tar -C /rootfs"])

        old_init_script = self.exec(["cat /config.json"])["stdout"]

        # Update init script
        json_data = json.loads(old_init_script)
        json_data["process"]["terminal"] = False
        json_data["process"]["args"] = init_cmd.split(" ")
        new_init_script = json.dumps(json_data)
        self.exec([f"echo '{new_init_script}' > /config.json"])

        # Start systemd service
        self.exec(["systemctl stop runc.service"])
        self.exec(["systemctl start runc.service"])

        # Cleanup
        self.exec(["rm /rootfs.tar"])

    @classmethod
    def create(
        cls,
        vcpus: Optional[int] = None,
        memory: Optional[int] = None,
        disk_size: Optional[int] = None,
        setup: Optional[Union[str, List[str]]] = None,
        snapshot_id: Optional[str] = None,
        rootfs_path: Optional[str] = None,
        init_cmd: Optional[str] = None,
        **kwargs,
    ) -> "Runtime":
        """Create a new runtime instance"""
        # Process setup commands
        if isinstance(setup, str):
            setup = (
                [setup]
                if not os.path.exists(setup)
                else [line.strip() for line in open(setup) if line.strip()]
            )

        if rootfs_path and not init_cmd:
            raise ValueError("init_cmd is required when providing a rootfs_path")

        runtime = cls(**kwargs)

        default_snapshot = _default_snapshot()

        vcpus = vcpus or default_snapshot["vcpus"]
        memory = memory or default_snapshot["memory"]
        disk_size = disk_size or default_snapshot["disk_size"]

        # hash vcpus, memory, and setup to create a unique snapshot digest
        snapshot_digest = hashlib.sha256(
            f"{vcpus}_{memory}_{disk_size}_{setup}_{rootfs_path}".encode()
        ).hexdigest()

        # try to create a snapshot with the given digest
        snapshot = next(
            (
                s
                for s in Snapshot.list(kwargs.get("api_key"))
                if s.digest == snapshot_digest
            ),
            None,
        )

        if snapshot:
            # create a runtime from the existing snapshot
            snapshot_id = snapshot.id

            resp = _http.post("/instance", params={"snapshot_id": snapshot_id}, headers=get_headers(api_key=kwargs.get("api_key")))
            resp.raise_for_status()

            runtime.instance_id = resp.json()["id"]
            runtime._wait_ready()

            print(f"\nRemote desktop available at: {runtime.remote_desktop_url}\n")
            return runtime

        config = _default_snapshot()

        if vcpus:
            config["vcpus"] = vcpus

        if memory:
            config["memory"] = memory

        if disk_size:
            config["disk_size"] = disk_size

        if setup:
            config["setup"] = setup

        initial_snapshot = Snapshot._create_from_image(
            image_id=config["image_id"],
            vcpus=vcpus,
            memory=memory,
            disk_size=disk_size,
            readiness_check=config.get("readiness_check"),
            api_key=kwargs.get("api_key"),
        )
        snapshot_id = initial_snapshot.id

        resp = _http.post("/instance", params={"snapshot_id": snapshot_id}, headers=get_headers(api_key=kwargs.get("api_key")))
        resp.raise_for_status()

        runtime.instance_id = resp.json()["id"]
        runtime._wait_ready()

        for command in setup or []:
            runtime._execute([command])

        if rootfs_path:
            if not init_cmd:
                raise ValueError("init_cmd is required when providing a rootfs_path")

            runtime._prepare_custom_container(
                local_rootfs_path=rootfs_path, init_cmd=init_cmd
            )

        # save snapshot
        snapshot = Snapshot.create(runtime, snapshot_digest)

        # cleanup initial snapshot
        Snapshot.delete(snapshot_id, api_key=kwargs.get("api_key"))

        print(f"\nRemote desktop available at: {runtime.remote_desktop_url}\n")
        return runtime

    def clone(
        self, num_clones: int = 1, api_key: Optional[str] = None
    ) -> List["Runtime"]:
        """Create a clone of this runtime"""
        resp = _http.post(
            f"/instance/{self.instance_id}/clone",
            json={"num_clones": num_clones},
            headers=get_headers(api_key=api_key),
        )
        resp.raise_for_status()

        return [
            Runtime(
                instance_id=runtime["id"],
                api_key=api_key or self.api_key,
                base_url=self.base_url,
                timeout=self.timeout,
            )
            for runtime in resp.json()
        ]

    def __enter__(self) -> Runtime:
        return self

    def __exit__(self, *_):
        self.stop()

    def stop(self):
        """Stop the runtime instance"""
        if self.instance_id:
            try:
                _http.delete(f"/instance/{self.instance_id}")
            finally:
                pass

    @classmethod
    def list(cls, **kwargs) -> List[Dict]:
        """List all runtime instances"""
        try:
            resp = _http.get(
                "/instance", headers=get_headers(api_key=kwargs.get("api_key"))
            )
            resp.raise_for_status()
            return resp.json()
        finally:
            _http.close()

    def _wait_ready(self, timeout: Optional[int] = None):
        """Wait for runtime to be ready"""
        deadline = time.time() + (timeout or self.timeout)
        while time.time() < deadline:
            if self.status == "ready":
                return
            time.sleep(2.0)
        raise TimeoutError(f"Runtime failed to become ready within {timeout=}s")

    @property
    def status(self) -> Optional[str]:
        try:
            return _http.get(f"/instance/{self.instance_id}").json().get("status")
        except Exception as e:
            print(f"[Runtime.status] caught {e=}")
            return None

    def _run(
        self, action: Dict[str, Any], timeout: int = 30, max_retries: int = 3
    ):
        """
        Execute an action on the runtime instance.

        Args:
            action: The action to interface
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts

        Returns:
            Dict containing the action response

        Raises:
            ValueError: If instance_id or API key is not set
            RuntimeError: If the action execution fails after all retries
            httpx.HTTPError: For any unhandled HTTP errors
        """
        endpoint_url = self.get_endpoint_url()

        # Extract action name and parameters
        action_name = action["action_type"]
        action_args = action["parameters"]

        # Format request data according to API requirements
        request_data = {"action": action_name, "params": action_args}

        # Add instance_id for specific action types
        if (
            action_name.startswith("Vercel")
            or action_name.startswith("Db")
            or action_name.startswith("Git")
        ):
            request_data["params"]["id"] = self.instance_id

        for attempt in range(max_retries):
            try:
                response = _http.post(
                    endpoint_url,
                    json=request_data,
                    timeout=timeout,
                )
                response.raise_for_status()
                # refresh the actions
                self.interface._load_actions()
                return response.json()

            except httpx.HTTPError as e:
                if attempt == max_retries - 1:
                    return {
                        "success": False,
                        "result": {},
                        "formattedActionOutput": f"Failed to execute action after {max_retries} attempts: {str(e)}",
                        "message": f"Failed to execute action after {max_retries} attempts: {str(e)}",
                    }
                time.sleep(2)

    def _execute(self, command: List[str]) -> Dict[str, Any]:
        resp = _http.post(
            f"/instance/{self.instance_id}/exec",
            json={"command": command},
            headers=self.headers,
        )
        resp.raise_for_status()
        return resp.json()


if __name__ == "__main__":
    fire.Fire(locals())

