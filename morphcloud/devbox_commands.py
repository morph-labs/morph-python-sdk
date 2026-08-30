"""Ontology declarations for MorphCloud devbox command workflows."""
from __future__ import annotations
from pathlib import Path
from typing import Annotated, Any, Literal
from ._synapse import run_instance_synapse
from .cli_runtime import MorphRuntimeContext
from .devbox import cli as implementation
from .devbox.gen.types.devbox_response import DevboxResponse
from .devbox.gen.types.template_detail import TemplateDetail
from .devbox.gen.types.tmux_session import TmuxSession

class _DevboxSynapseTarget:

    def __init__(self, devbox: DevboxResponse, devbox_client: Any) -> None:
        self.id = devbox.id
        self.metadata = dict(devbox.metadata or {})
        self._client = devbox_client

    def set_metadata(self, metadata: dict[str, Any]) -> None:
        self._client.devboxes_actions.update_devbox_metadata(self.id, request=metadata)
        self.metadata = dict(metadata)

def _call(command: Any, **values: Any) -> None:
    command.callback(**values)

def list_devboxes(json_output: bool=False) -> None:
    """List devboxes for the authenticated account."""
    _call(implementation.list_devboxes, json_output=json_output)

def get_devbox(devbox_id: str, json_output: bool=False) -> None:
    """Get details for a specific devbox."""
    _call(implementation.get_devbox, devbox_id=devbox_id, json_output=json_output)

def list_templates(json_output: bool=False) -> None:
    """List available devbox templates."""
    _call(implementation.list_templates, json_output=json_output)

def get_template(template_id: str, json_output: bool=False) -> None:
    """Show template details."""
    _call(implementation.get_template, template_id=template_id, json_output=json_output)

def create_template(name: str, base_snapshot_option: str, yaml_file: Path, description: str | None=None, json_output: bool=False) -> None:
    """Create a new template."""
    _call(implementation.create_template, name=name, base_snapshot_option=base_snapshot_option, yaml_file=yaml_file, description=description, json_output=json_output)

def update_template(template_id: str, name: str | None=None, base_snapshot_option: str | None=None, yaml_file: Path | None=None, description: str | None=None, json_output: bool=False) -> None:
    """Update an existing template."""
    _call(implementation.update_template, template_id=template_id, name=name, base_snapshot_option=base_snapshot_option, yaml_file=yaml_file, description=description, json_output=json_output)

def delete_template(template_id: str, json_output: bool=False) -> None:
    """Delete a template and associated aliases."""
    _call(implementation.delete_template, template_id=template_id, json_output=json_output)

def cache_template(template_id: str, secret_items: tuple[str, ...]=(), json_output: bool=False) -> None:
    """Start caching/building a template."""
    _call(implementation.cache_template, template_id=template_id, secret_items=secret_items, json_output=json_output)

def cancel_template_cache(template_id: str) -> None:
    """Cancel a running template build."""
    _call(implementation.cancel_template_cache, template_id=template_id)

def template_events(template_id: str, run_id: str, force: bool=False, json_output: bool=False) -> None:
    """Fetch build events for a template run."""
    _call(implementation.template_events, template_id=template_id, run_id=run_id, force=force, json_output=json_output)

def submit_template_secrets(template_id: str, run_id: str, secret_items: tuple[str, ...]) -> None:
    """Submit secrets while a template build is awaiting input."""
    _call(implementation.submit_template_secrets, template_id=template_id, run_id=run_id, secret_items=secret_items)

def share_template(template_id: str, alias: str, description: str | None=None, json_output: bool=False) -> None:
    """Share a template via a public alias."""
    _call(implementation.share_template, template_id=template_id, alias=alias, description=description, json_output=json_output)

def run_template(target: str | None=None, param_items: tuple[str, ...]=(), secret_items: tuple[str, ...]=(), force: bool=False, attach_run_id: str | None=None, plain: bool=False, json_output: bool=False, handoff_ttl_seconds: int | None=None, handoff_ttl_action: Literal['pause', 'stop'] | None=None, experimental_run_locally: bool=False, deprecated_experimental_run_local: bool=False) -> None:
    """Run a template workflow from a template id, shared alias, or browser."""
    _call(implementation.run_template, target=target, param_items=param_items, secret_items=secret_items, force=force, attach_run_id=attach_run_id, plain=plain, json_output=json_output, handoff_ttl_seconds=handoff_ttl_seconds, handoff_ttl_action=handoff_ttl_action, experimental_run_locally=experimental_run_locally, deprecated_experimental_run_local=deprecated_experimental_run_local)

def start_devbox(template_id: str, name: str | None=None, metadata_items: tuple[str, ...]=(), json_output: bool=False) -> None:
    """Start a devbox from a template."""
    _call(implementation.start_devbox, template_id=template_id, name=name, metadata_items=metadata_items, json_output=json_output)

def ssh_devbox(devbox_id: str, remote_command: list[str]=(), timeout: int=300, keepalive: int=15) -> None:
    """Open an SSH session to a devbox or run a remote command."""
    _call(implementation.ssh_devbox, devbox_id=devbox_id, remote_command=tuple(remote_command), timeout=timeout, keepalive=keepalive)

def terminal_list(devbox_id: str, socket: str | None=None, timeout: int=300, json_output: bool=False) -> None:
    """List devbox terminals (tmux sessions)."""
    _call(implementation.terminal_list, devbox_id=devbox_id, socket=socket, timeout=timeout, json_output=json_output)

def terminal_start(devbox_id: str, session_name: str | None=None, timeout: int=300, json_output: bool=False) -> None:
    """Start a new devbox terminal (tmux session)."""
    _call(implementation.terminal_start, devbox_id=devbox_id, session_name=session_name, timeout=timeout, json_output=json_output)

def terminal_connect(devbox_id: str, session: str, initial_command: str | None=None, timeout: int=300, keepalive: int=15) -> None:
    """Connect to a devbox terminal (tmux session) over SSH."""
    _call(implementation.terminal_connect, devbox_id=devbox_id, session=session, initial_command=initial_command, timeout=timeout, keepalive=keepalive)

def chat_devbox(ctx: MorphRuntimeContext, devbox_id: str, force: bool=False, detach: bool=False) -> None:
    """Open a managed Codex chat attached to this devbox."""
    devbox_client = ctx.client.devbox
    devbox = devbox_client.devboxes_core.get_devbox(devbox_id)
    run_instance_synapse(_DevboxSynapseTarget(devbox, devbox_client), ctx.client, force=force, detach=detach, resource_kind='devbox')

def _lifecycle(command: Any, *, devbox_id: str, json_output: bool) -> None:
    _call(command, devbox_id=devbox_id, json_output=json_output)

def pause_devbox(devbox_id: str, json_output: bool=False) -> None:
    """Pause a running devbox."""
    _lifecycle(implementation.pause_devbox, devbox_id=devbox_id, json_output=json_output)

def resume_devbox(devbox_id: str, json_output: bool=False) -> None:
    """Resume a paused devbox."""
    _lifecycle(implementation.resume_devbox, devbox_id=devbox_id, json_output=json_output)

def reboot_devbox(devbox_id: str, json_output: bool=False) -> None:
    """Reboot a devbox."""
    _lifecycle(implementation.reboot_devbox, devbox_id=devbox_id, json_output=json_output)

def delete_devbox(devbox_id: str, json_output: bool=False) -> None:
    """Delete a devbox."""
    _lifecycle(implementation.delete_devbox, devbox_id=devbox_id, json_output=json_output)

def save_devbox(devbox_id: str, name: str, json_output: bool=False) -> None:
    """Create a snapshot of a devbox."""
    _call(implementation.save_devbox, devbox_id=devbox_id, name=name, json_output=json_output)

def copy_devbox_files(source: str, destination: str, recursive: bool=False) -> None:
    """Copy files or directories between the local machine and a devbox."""
    _call(implementation.copy_devbox_files, source=source, destination=destination, recursive=recursive)

def expose_http_service(devbox_id: str, name: str, port: int, auth_mode: Literal['none', 'api_key'] | None=None, json_output: bool=False) -> None:
    """Expose a local port as an HTTP service on the devbox."""
    _call(implementation.expose_http_service, devbox_id=devbox_id, name=name, port=port, auth_mode=auth_mode, json_output=json_output)

def hide_http_service(devbox_id: str, name: str, json_output: bool=False) -> None:
    """Hide an HTTP service on the devbox."""
    _call(implementation.hide_http_service, devbox_id=devbox_id, name=name, json_output=json_output)
