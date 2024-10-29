from typing import Any, Dict, Optional, Union, List
import json
import os
import time
import httpx
from functools import wraps
import hashlib
from morphcloud.utils import to_camel_case, to_snake_case

# Constants
BASE_URL = "https://cloud.morph.so"
API_ENDPOINT = "/instance/{instance_id}/codelink"

class RuntimeSnapshot:
    @classmethod
    def create(cls, instance_id=None, digest=None):
        """
        Create a snapshot from an instance or configuration.
        
        Args:
            instance_id: Optional ID of instance to snapshot
            digest: Optional digest string for the snapshot
            
        Returns:
            Dict containing the created snapshot details
        """
        api_key = os.getenv("MORPH_API_KEY")
        headers = Runtime._get_static_headers(api_key)
        base_url = BASE_URL

        # If no digest provided, create one based on instance_id and timestamp
        if not digest:
            timestamp = str(int(time.time()))
            unique_string = f"{instance_id}_{timestamp}"
            digest = hashlib.sha256(unique_string.encode()).hexdigest()

        if instance_id:
            # Create snapshot from existing instance
            response = httpx.post(
                f"{base_url}/instance/{instance_id}/snapshot",
                headers=headers,
                params={"digest": digest}
            )
        else:
            raise ValueError("instance_id is required")
            
        response.raise_for_status()
        return response.json()

    @classmethod
    def list(cls):
        """
        List all available snapshots.
        
        Returns:
            List of snapshot objects
        """
        api_key = os.getenv("MORPH_API_KEY")
        headers = Runtime._get_static_headers(api_key)
        
        response = httpx.get(
            f"{BASE_URL}/snapshot",
            headers=headers
        )
        response.raise_for_status()
        return response.json()

    @classmethod
    def delete(cls, snapshot_id):
        """
        Delete a snapshot by ID.
        
        Args:
            snapshot_id: ID of the snapshot to delete
            
        Returns:
            Dict containing the deletion response
        """
        api_key = os.getenv("MORPH_API_KEY")
        headers = Runtime._get_static_headers(api_key)
        
        response = httpx.delete(
            f"{BASE_URL}/snapshot/{snapshot_id}",
            headers=headers
        )
        response.raise_for_status()
        return response.json()

class RuntimeExecute:
    """Dynamic execution interface that gets populated with methods from actions.py"""
    def __init__(self, runtime):
        self._runtime = runtime
        self._load_actions()

    def _format_docstring(self, action: Dict[str, Any]) -> str:
        """Create formatted markdown docstring from action details"""
        # Convert parameter names to snake_case
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
            returns = action['returns']
            doc += f"    {json.dumps(returns, indent=4)}\n"
        
        if 'examples' in action:
            doc += "\nExamples:\n"
            for example in action['examples']:
                doc += f"    {example}\n"
        
        return doc

    def _create_execute_wrapper(self, action_details: Dict[str, Any]):
        """Create an execution wrapper that handles camelCase conversion"""
        @wraps(self._runtime._run)
        def wrapper(*args, **kwargs):
            # Convert all snake_case kwargs to camelCase
            camel_kwargs = {
                to_camel_case(k): v 
                for k, v in kwargs.items()
            }
            
            # Create action request
            action_request = {
                'action_type': action_details['name'],
                'parameters': camel_kwargs
            }
            
            return self._runtime._run(action_request)
        
        return wrapper

    def _load_actions(self):
        """Load actions from actions.py and create corresponding methods"""
        actions_path = os.path.join(os.path.dirname(__file__), 'actions.py')
        with open(actions_path) as f:
            actions_data = json.loads(f.read())

        for action in actions_data['actions']:
            # Convert action name to snake_case
            snake_name = to_snake_case(action['name'])
            
            # Create the execution method
            execute_method = self._create_execute_wrapper(action)
            
            # Set the docstring
            execute_method.__doc__ = self._format_docstring(action)
            
            # Set the method on the instance
            setattr(self, snake_name, execute_method)

class Runtime:
    def __init__(self, 
                 instance_id: Optional[str] = None, 
                 base_url: str = BASE_URL,
                 api_key: Optional[str] = None,
                 timeout: int = 30):
        """
        Initialize a Runtime instance.
        
        Args:
            instance_id: The ID of the runtime instance
            base_url: The base URL for the Morph Cloud API (defaults to https://cloud.morph.so)
            api_key: Optional API key (if not provided, will check MORPH_API_KEY env variable)
            timeout: Request timeout in seconds (default: 30)
        """
        self.instance_id = instance_id
        self.base_url = base_url.rstrip('/')  # Remove trailing slash if present
        self.api_key = api_key
        self.timeout = timeout
        self.execute = RuntimeExecute(self)
        self.http_client = httpx.Client(
            follow_redirects=True, 
            timeout=self.timeout
        )

    def get_headers(self) -> Dict[str, str]:
        """Get headers for API requests"""
        api_key = self.api_key or os.getenv("MORPH_API_KEY")
        if not api_key:
            raise ValueError("No API key provided. Either pass api_key parameter or set MORPH_API_KEY environment variable")
            
        return {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}'
        }

    def get_endpoint_url(self) -> str:
        """Get the full endpoint URL for the instance"""
        if not self.instance_id:
            raise ValueError("No instance_id specified")
            
        return f"{self.base_url}{API_ENDPOINT.format(instance_id=self.instance_id)}"

    
    @classmethod
    def create(cls, 
               setup: Optional[Union[str, list[str]]] = None,
               vcpus: int = 2,
               memory: int = 3000,
               id: Optional[str] = None,
               snapshot_id: Optional[str] = None,
               base_url: str = BASE_URL,
               api_key: Optional[str] = None,
               timeout: int = 30) -> 'Runtime':
        """
        Create a new runtime instance.
        
        Args:
            setup: Optional setup script or list of commands
            vcpus: Number of virtual CPUs
            memory: Memory in MB
            id: Optional instance ID to connect to existing instance
            snapshot_id: Optional snapshot ID to create from
            base_url: Optional custom base URL for the API
            api_key: Optional API key (if not provided, will check MORPH_API_KEY env variable)
            timeout: Request timeout in seconds (default: 30)
            
        Returns:
            Runtime: A new Runtime instance
        """
        
        # If connecting to existing instance, return immediately
        if id:
            return cls(instance_id=id, base_url=base_url, api_key=api_key, timeout=timeout)

        # Initialize client for API calls
        http_client = httpx.Client(follow_redirects=True, timeout=timeout)
        headers = cls._get_static_headers(api_key)

        # Process setup commands
        setup_commands = []
        if isinstance(setup, str):
            if os.path.exists(setup):
                with open(setup, 'r') as f:
                    setup_commands = [line.strip() for line in f if line.strip()]
            else:
                setup_commands = [setup]
        elif isinstance(setup, list):
            setup_commands = setup

        # Create configuration digest
        config = {
            "image_id": "morphvm-codelink",
            "readiness_check": {"type": "timeout", "timeout": 30},
            "vcpus": vcpus,
            "memory": memory,
            "setup_commands": setup_commands
        }
        digest = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()

        # If snapshot_id provided, use it directly
        if snapshot_id:
            instance_response = http_client.post(
                f"{base_url}/instance",
                headers=headers,
                json={"snapshot_id": snapshot_id}
            )
            instance_response.raise_for_status()
            return cls(instance_id=instance_response.json()["instance_id"], base_url=base_url, api_key=api_key, timeout=timeout)

        # Check for existing snapshots with matching digest
        snapshots_response = http_client.get(f"{base_url}/snapshot", headers=headers)
        snapshots_response.raise_for_status()
        
        existing_snapshot = next(
            (s for s in snapshots_response.json() if s.get("digest") == digest), 
            None
        )

        if existing_snapshot:
            # Use existing snapshot
            instance_response = http_client.post(
                f"{base_url}/instance",
                headers=headers,
                json={"snapshot_id": existing_snapshot["id"]}
            )
        elif setup_commands:
            # First try to find/create a base snapshot without setup commands
            base_config = {
                "image_id": "morphvm-codelink",
                "readiness_check": {"type": "timeout", "timeout": 30},
                "vcpus": vcpus,
                "memory": memory,
                "setup_commands": []  # Empty setup commands for base snapshot
            }
            base_digest = hashlib.sha256(json.dumps(base_config, sort_keys=True).encode()).hexdigest()
            
            # Look for existing base snapshot
            base_snapshot = next(
                (s for s in snapshots_response.json() if s.get("digest") == base_digest), 
                None
            )
            
            if not base_snapshot:
                # Create new base snapshot
                base_snapshot_response = http_client.post(
                    f"{base_url}/snapshot",
                    headers=headers,
                    json={
                        "image_id": base_config["image_id"],
                        "readiness_check": base_config["readiness_check"],
                        "vcpus": base_config["vcpus"],
                        "memory": base_config["memory"],
                        "digest": base_digest
                    }
                )
                base_snapshot_response.raise_for_status()
                base_snapshot = base_snapshot_response.json()
            
            # Create runtime from base snapshot
            instance_response = http_client.post(
                f"{base_url}/instance",
                headers=headers,
                json={"snapshot_id": base_snapshot["id"]}
            )
            instance_response.raise_for_status()
            
            # Initialize runtime instance
            runtime = cls(
                instance_id=instance_response.json()["instance_id"], 
                base_url=base_url, 
                api_key=api_key, 
                timeout=timeout
            )
            
            # Wait for runtime to be ready before executing setup commands
            runtime._wait()
            
            # Execute setup commands
            for command in setup_commands:
                result = runtime.execute.terminal_command(command=command)
                if not result.get('success', False):
                    raise RuntimeError(f"Setup command failed: {command}\nError: {result.get('message', 'Unknown error')}")

            # Create snapshot with setup commands included in digest
            snapshot_response = http_client.post(
                f"{base_url}/instance/{runtime.instance_id}/snapshot",
                headers=headers,
                json={"digest": digest}  # Use the original digest that includes setup commands
            )
            snapshot_response.raise_for_status()
            
            return runtime

        else:
            # Create new snapshot from base image
            snapshot_response = http_client.post(
                f"{base_url}/snapshot",
                headers=headers,
                json={
                    "image_id": config["image_id"],
                    "readiness_check": config["readiness_check"],
                    "vcpus": config["vcpus"],
                    "memory": config["memory"],
                    "digest": digest
                }
            )
            snapshot_response.raise_for_status()
            
            # Create instance from new snapshot
            instance_response = http_client.post(
                f"{base_url}/instance",
                headers=headers,
                json={"snapshot_id": snapshot_response.json()["id"]}
            )
        
        instance_response.raise_for_status()
        instance_id = instance_response.json()["instance_id"]
        runtime = cls(instance_id=instance_id, base_url=base_url, api_key=api_key, timeout=timeout)


        # Wait for readiness
        runtime._wait()
        
        return runtime

    @staticmethod
    def _get_static_headers(api_key: Optional[str] = None) -> Dict[str, str]:
        """Get headers for API requests without instance context"""
        key = api_key or os.getenv("MORPH_API_KEY")
        if not key:
            raise ValueError("No API key provided. Either pass api_key parameter or set MORPH_API_KEY environment variable")
        return {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {key}'
        }

    def _wait(self, timeout: int = 30):
        """Wait for runtime to be ready"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = self.http_client.get(
                    f"{self.base_url}/instance/{self.instance_id}",
                    headers=self.get_headers()
                )
                if response.json().get("status") == "ready":
                    return
            except httpx.HTTPError:
                pass
            time.sleep(2)
        raise TimeoutError("Runtime failed to become ready within timeout period")

    def _run(self, 
                action: Dict[str, Any], 
                timeout: int = 30, 
                max_retries: int = 3) -> Dict[str, Any]:
        """
        Execute an action on the runtime instance.
        
        Args:
            action: The action to execute
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
            request_data["params"]["instance_id"] = self.instance_id

        for attempt in range(max_retries):
            try:
                response = self.http_client.post(
                    endpoint_url,
                    json=request_data,
                    headers=self.get_headers(),
                    timeout=timeout
                )
                response.raise_for_status()
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


    def clone(self, num_clones: int = 1) -> Union['Runtime', List['Runtime']]:
        """
        Clone the current runtime instance.
        
        Args:
            num_clones: Number of clones to create (default: 1)
            
        Returns:
            If num_clones=1, returns a single Runtime instance
            If num_clones>1, returns a list of Runtime instances
        """
        if not self.instance_id:
            raise ValueError("No instance_id specified")
            
        response = self.http_client.post(
            f"{self.base_url}/instance/{self.instance_id}/clone",
            headers=self.get_headers(),
            params={"num_clones": num_clones}
        )
        response.raise_for_status()
        
        # Create Runtime instances from the response
        response_data = response.json()
        if num_clones == 1:
            return Runtime(
                instance_id=response_data["id"],
                base_url=self.base_url,
                api_key=self.api_key,
                timeout=self.timeout
            )
        else:
            return [
                Runtime(
                    instance_id=instance["id"],
                    base_url=self.base_url,
                    api_key=self.api_key,
                    timeout=self.timeout
                )
                for instance in response_data
            ]

    def __enter__(self):
        self._wait()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        self.http_client.close()

    def stop(self):
        """Stop the runtime instance"""
        if self.instance_id:
            try:
                endpoint_url = f"{self.base_url}/instance/{self.instance_id}"
                response = self.http_client.delete(
                    endpoint_url,
                    headers=self.get_headers()
                )
                response.raise_for_status()
            except httpx.HTTPError as e:
                # Log the error but don't raise - we're cleaning up
                print(f"Warning: Failed to stop instance: {str(e)}")