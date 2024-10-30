"""
import morphcloud as morph

morph.Snapshot.create()
"""


import fire
from typing import Any, Dict, Optional, Union, List, Protocol
import json
import os
import time
import httpx
from functools import wraps
import hashlib
from dataclasses import dataclass, field
from morphcloud.utils import to_camel_case, to_snake_case
from morphcloud.actions import ide_actions

# Constants
BASE_URL = "https://cloud.morph.so"
API_ENDPOINT = "/instance/{instance_id}/codelink"

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional
import enum

class SnapshotStatus(enum.Enum):
    PENDING = "pending"
    READY = "ready"
    FAILED = "failed"
    DELETING = "deleting"
    DELETED = "deleted"

@dataclass
class Snapshot:
    id: str
    image_id: str
    created: datetime
    status: SnapshotStatus
    vcpus: float
    memory: float
    user_id: str
    object: Optional[str] = None
    digest: Optional[str] = None
    instances: List["Instance"] = None  # Type hint with string to avoid circular import
    owner: "User" = None  # Type hint with string to avoid circular import

    base_url: classmethod = BASE_URL
    http: classmethod = httpx.Client(timeout=None)    

    def __post_init__(self):
        if self.instances is None:
            self.instances = []

    @staticmethod
    def get_headers(api_key: Optional[str] = None):
        return {
                'Authorization': f'Bearer {api_key or os.getenv("MORPH_API_KEY")}',
                'Content-Type': 'application/json',
            }

    @staticmethod
    def create(runtime: 'Runtime', digest: Optional[str] = None) -> Dict[str, Any]:
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

        response = runtime.http.post(
            f"{runtime.base_url}/instance/{runtime.instance_id}/snapshot",
            headers=runtime.headers,
            params={"digest": digest}
        )
        response.raise_for_status()
        breakpoint()
        return Snapshot(response.json())

    @staticmethod
    def list(api_key: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List all available snapshots.

        Args:
            runtime: Runtime instance containing client configuration

        Returns:
            List of snapshot objects
        """
        response = Snapshot.http.get(
            f"{Snapshot.base_url}/snapshot",
            headers=Snapshot.get_headers(api_key=api_key)
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
        response = Snapshot.http.delete(
            f"{runtime.base_url}/snapshot/{snapshot_id}",
            headers=Snapshot.get_headers(api_key=api_key)
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
            {**p, 'name': to_snake_case(p['name'])} 
            for p in action.get('parameters', [])
        ]
        
        doc = f"{action['description']}\n\n"
        
        if params:
            doc += "Parameters:\n"
            for param in params:
                optional_str = " (optional)" if param.get('optional', False) else ""
                doc += f"- {param['name']}{optional_str}: {param['type']}\n    {param['description']}\n"
        
        if 'returns' in action:
            doc += "\nReturns:\n"
            doc += f"    {json.dumps(action['returns'], indent=4)}\n"
        
        if 'examples' in action:
            doc += "\nExamples:\n"
            for example in action['examples']:
                doc += f"    {example}\n"
        
        return doc

    def _create_interface_wrapper(self, action_details: Dict[str, Any]):
        """Create an execution wrapper that handles camelCase conversion"""
        @wraps(self._runtime._run)
        def wrapper(*args, **kwargs):
            camel_kwargs = {
                to_camel_case(k): v 
                for k, v in kwargs.items()
            }
            
            action_request = {
                'action_type': action_details['name'],
                'parameters': camel_kwargs
            }
            
            return self._runtime._run(action_request)
        
        return wrapper

    def _load_actions(self):
        """Load actions from actions.py and create corresponding methods"""
        for action in ide_actions['actions']:
            snake_name = to_snake_case(action['name'])
            interface_method = self._create_interface_wrapper(action)
            interface_method.__doc__ = self._format_docstring(action)
            setattr(self, snake_name, interface_method)

    def render(self, target: str = 'anthropic') -> List[Dict[str, Any]]:
        """
        Render actions in specified target format.
        
        Args:
            target: Format to render as ('anthropic' or 'openai')
        """
        seen_names = set()
        tools = []
        
        for action in ide_actions['actions']:
            name = to_snake_case(action["name"])
            if name in seen_names:
                continue
            seen_names.add(name)
            
            properties = {}
            required = []
            
            for param in action.get('parameters', []):
                param_name = to_snake_case(param["name"])
                prop = {
                    "type": param["type"],
                    "description": param.get("description", ""),
                }
                
                if target == 'openai':
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

            if target == 'anthropic':
                tools.append({
                    "name": name,
                    "description": action["description"],
                    "input_schema": {
                        "type": "object",
                        "properties": properties,
                        "required": required,
                    },
                })
            else:  # openai
                parameters = {
                    "type": "object",
                    "properties": properties,
                }
                if required:
                    parameters["required"] = required
                    
                tools.append({
                    "type": "function",
                    "function": {
                        "name": name,
                        "description": action["description"],
                        "parameters": parameters,
                    },
                })
        
        return tools    

@dataclass
class Runtime:
    """A Morph runtime instance"""
    # Core configuration
    instance_id: Optional[str] = None
    api_key: Optional[str] = field(default_factory=lambda: os.getenv("MORPH_API_KEY"))
    base_url: str = "https://cloud.morph.so"
    timeout: int = 30

    # Internal state
    http: classmethod = httpx.Client(timeout=None)
    interface: RuntimeInterface = None

    def __post_init__(self):
        """Initialize HTTP client and sub-clients after dataclass initialization"""
        if not self.api_key:
            raise ValueError("API key required. Provide api_key or set MORPH_API_KEY environment variable")

        self.http = httpx.Client(
            base_url=self.base_url,
            follow_redirects=True,
            timeout=self.timeout,
            headers=self.headers
        )
        self.interface = RuntimeInterface(self)

    @property
    def headers(self):
        return {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json',
            }

    def snapshot(self) -> Snapshot:
        return Snapshot.create(self)

    @property
    def remote_desktop_url(self):
        return f"{self.base_url}/ui/instance/{self.instance_id}"

    @classmethod
    def create(cls,
               vcpus: int = 2,
               memory: int = 3000,
               setup: Optional[Union[str, List[str]]] = None,
               snapshot_id: Optional[str] = None,
               **kwargs) -> 'Runtime':
        """Create a new runtime instance"""
        # Process setup commands
        if isinstance(setup, str):
            setup = [setup] if not os.path.exists(setup) else [
                line.strip() for line in open(setup) if line.strip()
            ]

        runtime = cls(**kwargs)            

        # Create instance
        if snapshot_id:
            resp = runtime.http.post("/instance", params={"snapshot_id": snapshot_id})
        else:
            resp = runtime.http.post("/instance", json={
                "vcpus": vcpus,
                "memory": memory,
                "setup_commands": setup or []
            })

        resp.raise_for_status()
        runtime.instance_id = resp.json()["id"]
        runtime._wait_ready()

        print(f"\nRemote desktop available at: {runtime.remote_desktop_url}\n")
        return runtime

    def clone(self) -> 'Runtime':
        """Create a clone of this runtime"""
        resp = self.http.post(f"/instance/{self.instance_id}/clone")
        resp.raise_for_status()

        return Runtime(
            instance_id=resp.json()["id"],
            api_key=self.api_key,
            base_url=self.base_url,
            timeout=self.timeout
        )

    def __enter__(self) -> 'Runtime':
        return self

    def __exit__(self, *_):
        self.stop()

    def stop(self):
        """Stop the runtime instance"""
        if self.instance_id:
            try:
                self.http.delete(f"/instance/{self.instance_id}")
            finally:
                self.http.close()

    @classmethod
    def list(cls, **kwargs) -> List[Dict]:
        """List all runtime instances"""
        runtime = cls(**kwargs)
        try:
            resp = runtime.http.get("/instance")
            resp.raise_for_status()
            return resp.json()
        finally:
            runtime.http.close()

    def _wait_ready(self, timeout: Optional[int] = None):
        """Wait for runtime to be ready"""
        deadline = time.time() + (timeout or self.timeout)
        while time.time() < deadline:
            if self.status == "ready":
                return
            time.sleep(2.)
        raise TimeoutError(f"Runtime failed to become ready within {timeout=}s")

    @property
    def status(self) -> Optional[str]:
        try:
            return self.http.get(f"/instance/{self.instance_id}").json().get("status")
        except Exception as e:
            print(f"[Runtime.status] caught {e=}")
            return None

    def _run(self, 
                action: Dict[str, Any], 
                timeout: int = 30, 
                max_retries: int = 3) -> Dict[str, Any]:
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
        action_name = action['action_type']
        action_args = action['parameters']

        # Format request data according to API requirements
        request_data = {
            "action": action_name,
            "params": action_args
        }

        # Add instance_id for specific action types
        if (
            action_name.startswith("Vercel") or 
            action_name.startswith("Db") or 
            action_name.startswith("Git")
        ):
            request_data["params"]["id"] = self.instance_id

        for attempt in range(max_retries):
            try:
                response = self.http_client.post(
                    endpoint_url,
                    json=request_data,
                    headers=self.get_headers(),
                    timeout=timeout
                )
                response.raise_for_status()
                # refresh the actions
                self.interface._load_actions()
                return response.json()
                
            except httpx.HTTPError as e:
                if attempt == max_retries - 1:
                    return {
                        'success': False,
                        "result": {},
                        "formattedActionOutput": f"Failed to execute action after {max_retries} attempts: {str(e)}",
                        'message': f"Failed to execute action after {max_retries} attempts: {str(e)}"
                    }
                time.sleep(2)

def main():
    print("hello world")
        
"""
TODO: this interface is a bit user-unfriendly.

as part of our distribution strategy, we should make it easy for users to specify an arbitrary docker image. this should be converted into a snapshot upon startup-time, for example,

and then the blueprint setup script should run and that should be automatically cached as a digest of the container and setup script as well
"""
def test_runtime():

    # should not need to do this
    snapshots = Snapshot.list()
    base_snapshot = snapshots[0]
    print(f"{base_snapshot=}")
    runtime = Runtime.create(
        vcpus=2,
        memory=2048,
        snapshot_id=base_snapshot.id
    )
    ss = runtime.snapshot()

    print(f"created snapshot: {ss}")
    with Runtime.create(snapshot_id=ss.id) as runtime:
        print(f"created runtime with snapshot_id={ss.id}")

if __name__ == "__main__":
    fire.Fire(locals())
