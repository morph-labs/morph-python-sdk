from __future__ import annotations

import os
import enum
import json
import time
import logging
import hashlib
import subprocess

from functools import wraps
from datetime import datetime
from typing import Any, Dict, Optional, Union, List, Literal

from morphcloud.utils import (
    get_iframe_object_from_instance_id,
    to_camel_case,
    to_snake_case,
)
from morphcloud.actions import ide_actions
from morphcloud.utils import (get_iframe_object_from_instance_id,
                              to_camel_case, to_snake_case)

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
BASE_URL = os.getenv("MORPH_BASE_URL", "https://cloud.morph.so")
SSH_PORTAL_HOST = BASE_URL.replace("https://", "").replace("http://", "")
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
morph_http_client = httpx.Client(
    base_url=morph_base_url,
    follow_redirects=True,
    headers=_get_headers(),
    timeout=None
)

from morphcloud.vm import MorphVm, SnapshotStatus, VmSnapshot

class Snapshot(VmSnapshot):
    """A snapshot that forwards all operations to VmSnapshot"""

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
        raise NotImplementedError("This method is not implemented for Snapshot")
        
        if not runtime.id:
            raise ValueError("No instance_id specified")

        # If no digest provided, create one based on instance_id and timestamp
        if not digest:
            timestamp = str(int(time.time()))
            unique_string = f"{runtime.id}_{timestamp}"
            digest = hashlib.sha256(unique_string.encode()).hexdigest()

        response = morph_http_client.post(
            f"/instance/{runtime.id}/snapshot",
            headers=_get_headers(),
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
        # Forward to parent class but return Snapshot instead of VmSnapshot
        vm_snapshot = super()._create_from_image(
            image_id=image_id,
            vcpus=vcpus,
            memory=memory,
            disk_size=disk_size,
            readiness_check=readiness_check,
            **kwargs
        )
        return cls(**vm_snapshot.dict())

    @staticmethod
    def list(api_key: Optional[str] = None) -> List["Snapshot"]:
        """
        List all available snapshots.

        Args:
            api_key: Optional API key to use for authentication

        Returns:
            List of snapshot objects
        """
        # Forward to parent class but convert results to Snapshot
        vm_snapshots = VmSnapshot.list(api_key=api_key)
        return [Snapshot(**x.dict()) for x in vm_snapshots]

    @staticmethod
    def delete(snapshot_id: str, api_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Delete a snapshot by ID.

        Args:
            snapshot_id: ID of the snapshot to delete
            api_key: Optional API key to use for authentication

        Returns:
            Dict containing the deletion response
        """
        return VmSnapshot.delete(snapshot_id=snapshot_id, api_key=api_key)


# class RuntimeInterface:
#     def __init__(self, runtime):
#         self._runtime = runtime
#         self._load_actions()

#     def _format_docstring(self, action: Dict[str, Any]) -> str:
#         """Create formatted markdown docstring from action details"""
#         params = [
#             {**p, "name": to_snake_case(p["name"])}
#             for p in action.get("parameters", [])
#         ]

#         doc = f"{action['description']}\n\n"

#         if params:
#             doc += "Parameters:\n"
#             for param in params:
#                 optional_str = " (optional)" if param.get("optional", False) else ""
#                 doc += f"- {param['name']}{optional_str}: {param['type']}\n    {param['description']}\n"

#         if "returns" in action:
#             doc += "\nReturns:\n"
#             doc += f"    {json.dumps(action['returns'], indent=4)}\n"

#         if "examples" in action:
#             doc += "\nExamples:\n"
#             for example in action["examples"]:
#                 doc += f"    {example}\n"

#         return doc

#     def _create_interface_wrapper(self, action_details: Dict[str, Any]):
#         """Create an execution wrapper that handles camelCase conversion"""

#         @wraps(self._runtime._run)
#         def wrapper(*args, **kwargs):
#             camel_kwargs = {to_camel_case(k): v for k, v in kwargs.items()}

#             action_request = {
#                 "action_type": action_details["name"],
#                 "parameters": camel_kwargs,
#             }

#             return self._runtime._run(action_request)

#         return wrapper

#     async def execute(self, tool_name: str, **kwargs):
#         return {
#             "action_type": tool_name,
#             "parameters": {to_camel_case(k): v for k, v in kwargs.items()},
#         }

#     def _load_actions(self):
#         """Load actions from actions.py and create corresponding methods"""
#         for action in ide_actions["actions"]:
#             snake_name = to_snake_case(action["name"])
#             interface_method = self._create_interface_wrapper(action)
#             interface_method.__doc__ = self._format_docstring(action)
#             setattr(self, snake_name, interface_method)

#     def render(self, target: str = "anthropic") -> List[Dict[str, Any]]:
#         """
#         Render actions in specified target format.

#         Args:
#             target: Format to render as ('anthropic' or 'openai')
#         """
#         seen_names = set()
#         tools = []

#         for action in ide_actions["actions"]:
#             name = to_snake_case(action["name"])
#             if name in seen_names:
#                 continue
#             seen_names.add(name)

#             properties = {}
#             required = []

#             for param in action.get("parameters", []):
#                 param_name = to_snake_case(param["name"])
#                 prop = {
#                     "type": param["type"],
#                     "description": param.get("description", ""),
#                 }

#                 if target == "openai":
#                     if "enum" in param:
#                         prop["enum"] = param["enum"]
#                     if param.get("type") == "array" and "items" in param:
#                         prop["items"] = {
#                             "type": param["items"].get("type"),
#                         }
#                         if "enum" in param["items"]:
#                             prop["items"]["enum"] = param["items"]["enum"]

#                 properties[param_name] = prop

#                 if not param.get("optional", False):
#                     required.append(param_name)

#             if target == "anthropic":
#                 tools.append(
#                     {
#                         "name": name,
#                         "description": action["description"],
#                         "input_schema": {
#                             "type": "object",
#                             "properties": properties,
#                             "required": required,
#                         },
#                     }
#                 )
#             else:  # openai
#                 parameters = {
#                     "type": "object",
#                     "properties": properties,
#                 }
#                 if required:
#                     parameters["required"] = required

#                 tools.append(
#                     {
#                         "type": "function",
#                         "function": {
#                             "name": name,
#                             "description": action["description"],
#                             "parameters": parameters,
#                         },
#                     }
#                 )

#         return tools


class Runtime(BaseModel):
    """A Morph runtime instance"""

    # Core configuration
    id: str
    object: Literal["instance"] = "instance"
    vm: MorphVm
    # base_url: str = BASE_URL
    # timeout: int = 30

    @property
    def instance_id(self):
        return self.id

    def snapshot(self) -> Snapshot:
        return Snapshot.create(self.vm)

    def exec(self, command: Union[str, List[str]]):
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
        return self.vm.exec(command)

    @property
    def remote_desktop_url(self):
        return f"{morph_base_url}/web/instance/{self.id}"

    def remote_desktop_iframe(self, width: int = 1280 // 2, height: int = 720 // 2):
        return get_iframe_object_from_instance_id(
            morph_base_url, self.id, width=width, height=height
        )

    def upload_file(self, local_file_path: str, remote_file_path: str, **kwargs):
        """Upload a file to the runtime instance"""
        return self.vm.upload_file(local_file_path, remote_file_path, **kwargs)

    def _prepare_oci_container(self, local_rootfs_path: str, init_cmd: str):
        # Check if local rootfs path exists
        if not os.path.exists(local_rootfs_path):
            raise FileNotFoundError(
                f"Local rootfs path does not exist: {local_rootfs_path}"
            )

        # Upload rootfs to runtime using SCP
        self.vm.upload_file(local_rootfs_path, "/rootfs.tar")

        # Extract rootfs
        self.vm.exec(["tar -xvf /rootfs.tar -C /rootfs"])

        old_init_script = self.vm.exec(["cat /config.json"])["stdout"]

        # Update init script
        json_data = json.loads(old_init_script)
        json_data["process"]["terminal"] = False
        json_data["process"]["args"] = init_cmd.split(" ")
        new_init_script = json.dumps(json_data)
        self.vm.exec([f"echo '{new_init_script}' > /config.json"])

        # Start systemd service
        self.vm.exec(["systemctl stop runc.service"])
        self.vm.exec(["systemctl start runc.service"])

        # Cleanup
        self.vm.exec(["rm /rootfs.tar"])

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
    ) -> Runtime:
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

        default_snapshot = _default_snapshot()

        vcpus = vcpus or default_snapshot["vcpus"]
        memory = memory or default_snapshot["memory"]
        disk_size = disk_size or default_snapshot["disk_size"]
        
        if snapshot_id:
            # create a runtime from the existing snapshot
            vm = MorphVm.create(snapshot_id=snapshot_id)
            runtime = Runtime(id=vm.id, vm=vm)

            logger.info(f"Remote desktop available at: {runtime.remote_desktop_url}\n")
            return runtime

        # hash vcpus, memory, and setup to create a unique snapshot digest
        snapshot_digest = "sha256:" + hashlib.sha256(
            f"{vcpus}-{memory}-{disk_size}-{setup}-{rootfs_path}".encode()
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

            vm = MorphVm.create(snapshot_id=snapshot_id)
            runtime = Runtime(id=vm.id, vm=vm)

            logger.info(f"Remote desktop available at: {runtime.remote_desktop_url}\n")
            return runtime

        vm = MorphVm.create(
            vcpus=vcpus,
            memory=memory,
            disk_size=disk_size,
            api_key=kwargs.get("api_key"),
            digest=snapshot_digest,
        )
        
        runtime = Runtime(id=vm.id, vm=vm)

        for command in setup or []:
            vm._execute([command])

        if rootfs_path:
            if not init_cmd:
                raise ValueError("init_cmd is required when providing a rootfs_path")

            runtime._prepare_oci_container(
                local_rootfs_path=rootfs_path, init_cmd=init_cmd
            )

        logger.info(f"Remote desktop available at: {runtime.remote_desktop_url}\n")
        return runtime

    def clone(
        self, num_clones: int = 1, api_key: Optional[str] = None
    ) -> List[Runtime]:
        """Create a clone of this runtime"""
        runtimes = self.vm.clone(num_clones=num_clones, api_key=api_key)
        return [Runtime(id=r.id, vm=r) for r in runtimes]

    def __enter__(self) -> Runtime:
        return self

    def __exit__(self, *_):
        self.stop()

    def stop(self):
        """Stop the runtime instance"""
        if self.instance_id:
            self.vm.stop()

    @classmethod
    def list(cls, **kwargs) -> List[Runtime]:
        """List all runtime instances"""
        resp = morph_http_client.get(
            "/instance", headers=_get_headers(api_key=kwargs.get("api_key"))
        )
        # TODO: Figure out this API spec
        resp.raise_for_status()
        return [Runtime(**r) for r in resp.json()]

    def _wait_ready(self, timeout: Optional[int] = None):
        """Wait for runtime to be ready"""
        return self.vm.wait_ready(timeout=timeout)

    @property
    def status(self) -> Optional[str]:
        return self.vm.status

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
        raise NotImplementedError("Not implemented yet")
        # endpoint_url = self.get_endpoint_url()

        # # Extract action name and parameters
        # action_name = action["action_type"]
        # action_args = action["parameters"]

        # # Format request data according to API requirements
        # request_data = {"action": action_name, "params": action_args}

        # # Add instance_id for specific action types
        # if (
        #     action_name.startswith("Vercel")
        #     or action_name.startswith("Db")
        #     or action_name.startswith("Git")
        # ):
        #     request_data["params"]["id"] = self.instance_id

        # for attempt in range(max_retries):
        #     try:
        #         response = morph_http_client.post(
        #             endpoint_url,
        #             json=request_data,
        #             timeout=timeout,
        #         )
        #         response.raise_for_status()
        #         # refresh the actions
        #         self.interface._load_actions()
        #         return response.json()

        #     except httpx.HTTPError as e:
        #         if attempt == max_retries - 1:
        #             return {
        #                 "success": False,
        #                 "result": {},
        #                 "formattedActionOutput": f"Failed to execute action after {max_retries} attempts: {str(e)}",
        #                 "message": f"Failed to execute action after {max_retries} attempts: {str(e)}",
        #             }
        #         time.sleep(2)

    def _execute(self, command: List[str]) -> Dict[str, Any]:
        return self.vm.exec(command)


if __name__ == "__main__":
    fire.Fire(locals())

