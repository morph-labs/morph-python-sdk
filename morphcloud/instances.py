"""Morph instance operations and terminal presentation policy."""
from __future__ import annotations
import sys
import json
from datetime import datetime, timezone
from typing import Annotated, Any, Callable, Literal
import click
from .api import DiskResizeError, DiskResizeOperation, Instance, InstanceExecResponse, InstanceSshKey, InstanceStatus, Snapshot, copy_into_or_from_instance
from .cli_helpers import format_json, print_docker_style_table
from .cli_runtime import MorphRuntimeContext

def _write_stdout(chunk: str) -> None:
    sys.stdout.write(chunk)
    sys.stdout.flush()

def _write_stderr(chunk: str) -> None:
    sys.stderr.write(chunk)
    sys.stderr.flush()

def render_instance_exec(result: InstanceExecResponse, policy: dict[str, Any], inputs: dict[str, Any]) -> None:
    """Render buffered commands with structure and leave streamed output untouched."""
    if not inputs.get('stream'):
        if result.stdout:
            click.secho('Stdout', bold=True)
            click.echo(result.stdout, nl=not result.stdout.endswith('\n'))
        if result.stderr:
            click.secho('Stderr', fg='yellow', bold=True, err=True)
            click.echo(result.stderr, nl=not result.stderr.endswith('\n'), err=True)
        color = 'green' if result.exit_code == 0 else 'red'
        click.secho(f'Exit code: {result.exit_code}', fg=color, bold=True)
    if result.exit_code:
        raise click.exceptions.Exit(result.exit_code)

def render_instance_ssh(result: dict[str, Any], policy: dict[str, Any], inputs: dict[str, Any]) -> None:
    """Keep an interactive shell transparent while polishing command-mode output."""
    if not result['interactive']:
        if result['stdout']:
            click.echo(result['stdout'], nl=not result['stdout'].endswith('\n'))
        if result['stderr']:
            click.echo(result['stderr'], nl=not result['stderr'].endswith('\n'), err=True)
        click.echo(f"Remote command exited with code {result['returncode']}")
    if result.get('snapshot_id'):
        click.echo(f"Snapshot ID: {result['snapshot_id']}")
    if result.get('stopped'):
        click.secho(f"Stopped instance {result['instance_id']}", fg='green')
    if result['returncode']:
        raise click.exceptions.Exit(result['returncode'])

def render_snapshot_summary(result: Snapshot, policy: dict[str, Any], inputs: dict[str, Any]) -> None:
    """Render the stable snapshot summary without assuming optional fields exist."""
    click.secho(f'Snapshot created: {result.id}', fg='green', bold=True)
    if result.digest:
        click.echo(f'Digest: {result.digest}')
    ttl = getattr(result, 'ttl', None)
    ttl_seconds = getattr(ttl, 'ttl_seconds', None)
    if ttl_seconds is not None:
        click.echo(f'TTL: {ttl_seconds} seconds')

def _status_text(value: Any) -> str:
    return str(getattr(value, 'value', value))

def _created_text(value: Any) -> str:
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except (OSError, TypeError, ValueError):
        return 'N/A'

def _instance_rows(instances: list[Any]) -> list[list[Any]]:
    rows: list[list[Any]] = []
    total_vcpus = 0
    total_memory_mb = 0
    total_disk_mb = 0
    for instance in instances:
        services = getattr(instance.networking, 'http_services', []) or []
        rows.append([instance.id, instance.refs.snapshot_id, _created_text(instance.created), _status_text(instance.status), instance.spec.vcpus, instance.spec.memory, f'{instance.spec.disk_size / 1024:.1f}', ', '.join((f'{service.name}:{service.port}' for service in services))])
        total_vcpus += instance.spec.vcpus
        total_memory_mb += instance.spec.memory
        total_disk_mb += instance.spec.disk_size
    if instances:
        rows.append(['─' * 10] * 8)
        rows.append([f'{len(instances)} instances', '', '', '', total_vcpus, f'{total_memory_mb / 1024:.1f} GB', f'{total_disk_mb / 1024:.1f} GB', ''])
    return rows

def render_instance_list(result: Any, policy: dict[str, Any], inputs: dict[str, Any]) -> None:
    """Render instance inventory with exact GiB formatting and aggregate totals."""
    if result is None:
        return
    paginated = hasattr(result, 'instances')
    instances = list(result.instances if paginated else result)
    if inputs.get('json_mode'):
        if paginated:
            click.echo(format_json(result))
        else:
            for instance in instances:
                click.echo(format_json(instance))
        return
    if paginated:
        click.echo(f'Total instances: {result.total} | Page {result.page} of {result.total_pages} (showing {len(instances)})')
    print_docker_style_table(['ID', 'Snapshot ID', 'Created At', 'Status', 'VCPUs', 'Memory (MB)', 'Disk Size (GB)', 'Http Services'], _instance_rows(instances))

def render_instance_branch(result: dict[str, Any], policy: dict[str, Any], inputs: dict[str, Any]) -> None:
    """Render the intermediate snapshot and every newly started branch."""
    snapshot = result['snapshot']
    instances = result['new_instances']
    click.secho(f'Created intermediate snapshot: {snapshot.id}', fg='green')
    click.echo('Started new instances:')
    for instance in instances:
        click.echo(f'- {instance.id} (Status: {_status_text(instance.status)})')

def render_instance_ttl(result: Instance, policy: dict[str, Any], inputs: dict[str, Any]) -> None:
    """Distinguish setting an instance TTL from clearing it."""
    instance_id = inputs['__identity']
    ttl_seconds = inputs['ttl_seconds']
    if ttl_seconds == -1:
        click.echo(f'TTL removed for {instance_id}')
    else:
        click.echo(f'TTL set for {instance_id}: {ttl_seconds} seconds')

def render_instance_ssh_key(result: InstanceSshKey | dict[str, Any], policy: dict[str, Any], inputs: dict[str, Any]) -> None:
    """Allow scripts to request only the password while keeping full JSON by default."""
    payload = result if isinstance(result, dict) else result.model_dump()
    if inputs.get('show_password_only'):
        password = payload.get('password')
        if password is None:
            raise click.ClickException("'password' field not found in the API response")
        click.echo(password)
        return
    click.echo(format_json(payload))

def render_instance_cleanup(result: dict[str, Any], policy: dict[str, Any], inputs: dict[str, Any]) -> None:
    """Render cleanup automation as JSON or a concise terminal conclusion."""
    if inputs.get('json_mode'):
        click.echo(json.dumps(result, indent=2))
        return
    if result.get('success'):
        if result.get('cancelled'):
            click.secho('Operation cancelled by user.', fg='cyan')
        elif result.get('processed', 0) > 0:
            action = 'stopped' if inputs['action'] == 'stop' else 'paused'
            click.secho(f"Successfully {action} {result['processed']} instances.", fg='green', bold=True)
        else:
            click.secho('No instances needed cleanup.', fg='green')
        return
    if result.get('error'):
        click.secho(f"Error: {result['error']}", fg='red', err=True)
    else:
        click.secho(f"{result.get('failed', 0)} instances failed to {inputs['action']}.", fg='red', err=True)
    raise click.exceptions.Exit(1)

def _interactive_instance_list(client: Any, *, metadata: dict[str, str], page: int, limit: int) -> None:
    """Offer bounded terminal paging while keeping presentation client-owned."""
    search: dict[str, str] = {}
    while True:
        response = client.instances.list_paginated(metadata={**metadata, **search}, page=page, limit=limit)
        click.clear()
        click.secho('MorphCloud - Instance List', bold=True)
        render_instance_list(response, {}, {'json_mode': False})
        click.echo('[n] next  [p] previous  [s] metadata search  [q] quit')
        key = click.getchar().lower()
        if key in {'q', '\x03'}:
            return
        if key == 'n' and response.has_next:
            page += 1
        elif key == 'p' and response.has_prev:
            page -= 1
        elif key == 's':
            value = click.prompt('Metadata filter (KEY=VALUE, empty to clear)', default='', show_default=False).strip()
            if not value:
                search = {}
            elif '=' not in value:
                click.echo('Invalid format. Use key=value.', err=True)
            else:
                key_name, item = value.split('=', 1)
                search = {key_name.strip(): item.strip()}
            page = 1

def list_instances(ctx: MorphRuntimeContext, metadata: dict[str, str] | None=None, page: int | None=None, limit: int | None=None, interactive: bool=False, json_mode: bool=False) -> Any:
    """List all instances."""
    if interactive:
        _interactive_instance_list(ctx.client, metadata=metadata or {}, page=page or 1, limit=limit or 50)
        return None
    if page is not None or limit is not None:
        return ctx.client.instances.list_paginated(metadata=metadata or {}, page=page or 1, limit=limit or 50)
    return ctx.client.instances.list(metadata=metadata or {})

def start_instance(ctx: MorphRuntimeContext, snapshot_id: str, metadata: dict[str, str] | None=None, ttl_seconds: int | None=None, ttl_action: Literal['stop', 'pause'] | None=None) -> Instance:
    """Start an instance from a snapshot and wait until it is ready."""
    return ctx.client.instances.start(snapshot_id, metadata=metadata, ttl_seconds=ttl_seconds, ttl_action=ttl_action)

def boot_instance(ctx: MorphRuntimeContext, snapshot_id: str, vcpus: int | None=None, memory: int | None=None, disk_size: int | None=None, metadata: dict[str, str] | None=None) -> Instance:
    """Boot a new instance from a snapshot."""
    return ctx.client.instances.boot(snapshot_id=snapshot_id, vcpus=vcpus, memory=memory, disk_size=disk_size, metadata=metadata)

def stop_instance(ctx: MorphRuntimeContext, instance_id: str) -> None:
    """Stop a running or paused instance."""
    ctx.client.instances.stop(instance_id)

def copy_instance_files(ctx: MorphRuntimeContext, source: str, destination: str, recursive: bool=False) -> None:
    """Copy files or directories between the local machine and an instance."""
    source_remote = ':' in source and (not source.startswith(':'))
    destination_remote = ':' in destination and (not destination.startswith(':'))
    if source_remote == destination_remote:
        message = "Both 'source' and 'destination' cannot be remote." if source_remote else "Neither 'source' nor 'destination' is remote."
        raise click.UsageError(message)
    if source_remote:
        instance_id, remote_path = source.split(':', 1)
        local_path = destination
        uploading = False
    else:
        instance_id, remote_path = destination.split(':', 1)
        local_path = source
        uploading = True
    instance = ctx.client.instances.get(instance_id)
    instance.wait_until_ready(timeout=300)
    copy_into_or_from_instance(instance_obj=instance, local_path=local_path, remote_path=remote_path, uploading=uploading, recursive=recursive, verbose=True)

def cleanup_instances(ctx: MorphRuntimeContext, snapshot_pattern: str | None=None, snapshot_exclude_pattern: str | None=None, service_pattern: str | None=None, service_exclude_pattern: str | None=None, exclude_paused: bool=True, action: Literal['stop', 'pause']='stop', max_workers: int=10, yes: bool=False, json_mode: bool=False) -> dict[str, Any]:
    """Clean up instances selected by snapshot and service patterns."""
    return ctx.client.instances.cleanup(snapshot_pattern=snapshot_pattern, snapshot_exclude_pattern=snapshot_exclude_pattern, service_pattern=service_pattern, service_exclude_pattern=service_exclude_pattern, exclude_paused=exclude_paused, action=action, max_workers=max_workers, confirm=not yes)

def get_instance(instance: Instance) -> Instance:
    """Get detailed information about a specific instance as JSON."""
    return instance

def branch_instance(instance: Instance, count: int=1) -> dict[str, Any]:
    """Snapshot an instance and launch one or more branches."""
    if instance.status not in {InstanceStatus.READY, InstanceStatus.PAUSED}:
        raise ValueError(f'Instance must be READY or PAUSED. Current: {instance.status.value}')
    snapshot, new_instances = instance.branch(count)
    return {'snapshot': snapshot, 'new_instances': new_instances}

def expose_instance_http(instance: Instance, name: str, port: int, auth_mode: Literal['none', 'api_key']='none') -> dict[str, str]:
    """Expose an HTTP service on a public URL."""
    if instance.status != InstanceStatus.READY:
        raise ValueError(f'Instance must be READY to expose services. Current: {instance.status.value}')
    url = instance.expose_http_service(name, port, 'api_key' if auth_mode == 'api_key' else None)
    return {'url': url, 'authentication': 'API key required' if auth_mode == 'api_key' else 'None'}

def hide_instance_http(instance: Instance, name: str) -> None:
    """Hide a previously exposed HTTP service."""
    instance.hide_http_service(name)

def port_forward_instance(instance: Instance, remote_port: int, local_port: int=None) -> None:
    """Forward a remote instance port to the local machine."""
    local_port = local_port or remote_port
    instance.wait_until_ready(timeout=300)
    click.echo('Setting up port forward…')
    try:
        with instance.ssh() as ssh, ssh.tunnel(local_port=local_port, remote_port=remote_port) as tunnel:
            click.echo(f'Forwarding remote port {remote_port} to localhost:{local_port}')
            click.echo('Press Ctrl+C to stop.')
            tunnel.wait()
    except KeyboardInterrupt:
        click.echo('\nPort forwarding stopped.')

def reboot_instance(instance: Instance, vcpus: int | None=None, memory: int | None=None, disk_size: int | None=None, ttl_seconds: int | None=None, ttl_action: Literal['stop', 'pause'] | None=None, metadata: dict[str, str] | None=None) -> Instance:
    """Reboot an instance, optionally updating resources and settings."""
    instance.reboot(vcpus=vcpus, memory=memory, disk_size=disk_size, metadata=metadata, ttl_seconds=ttl_seconds, ttl_action=ttl_action)
    return instance

def exec_instance(instance: Instance, command_args: list[str], stream: bool=False) -> InstanceExecResponse:
    """Execute a command inside an instance."""
    if not command_args:
        raise ValueError('at least one command argument is required')
    if stream:
        return instance.exec(command_args, on_stdout=_write_stdout, on_stderr=_write_stderr)
    return instance.exec(command_args)

def set_instance_metadata(instance: Instance, ctx: MorphRuntimeContext, metadata: dict[str, str] | None=None, metadata_args: list[str]=()) -> Instance:
    """Set or replace instance metadata."""
    combined: dict[str, str] = {}
    for item in metadata_args:
        if '=' not in item:
            raise click.UsageError('Metadata must be in key=value format.')
        key, value = item.split('=', 1)
        combined[key] = value
    combined.update(metadata or {})
    instance.set_metadata(combined)
    return ctx.client.instances.get(instance.id)

def set_instance_ttl(instance: Instance, ttl_seconds: int, ttl_action: Literal['stop', 'pause']='stop') -> Instance:
    """Set or remove the instance time-to-live policy."""
    if ttl_seconds == 0 or ttl_seconds < -1:
        raise click.BadParameter('must be greater than 0, or -1 to clear', param_hint="'--ttl-seconds'")
    instance.set_ttl(None if ttl_seconds == -1 else ttl_seconds, ttl_action)
    return instance

def set_instance_wake_on(instance: Instance, wake_on_ssh: bool | None=None, wake_on_http: bool | None=None) -> Instance:
    """Configure the wake-on-event settings for an instance."""
    if wake_on_ssh is None and wake_on_http is None:
        raise click.UsageError('Specify at least one of --ssh or --http.')
    instance.set_wake_on(wake_on_ssh=wake_on_ssh, wake_on_http=wake_on_http)
    return instance

def instance_ssh_key(ctx: MorphRuntimeContext, instance_id: str, show_password_only: bool=False) -> dict[str, Any]:
    """Retrieve ephemeral SSH credentials for an instance."""
    response = ctx.client._http_client.get(f'/instance/{instance_id}/ssh/key')
    return response.json()

def snapshot_instance(instance: Instance, digest: str | None=None, ttl_seconds: int | None=None, metadata: dict[str, str] | None=None) -> Snapshot:
    """Create a new snapshot from an instance."""
    if instance.status != InstanceStatus.READY:
        raise ValueError(f'Instance must be READY. Current: {instance.status.value}')
    return instance.snapshot(digest=digest, metadata=metadata, ttl_seconds=ttl_seconds)

def ssh_instance(instance: Instance, rm: bool=False, create_snapshot_on_exit: bool=False, remote_command: list[str]=()) -> dict[str, Any]:
    """Start an interactive SSH shell or run an optional remote command."""
    if instance.status == InstanceStatus.PAUSED and (not instance.wake_on.wake_on_ssh):
        raise ValueError(f"Instance {instance.id} is PAUSED and wake-on-SSH is not enabled. Run 'morphcloud instance resume {instance.id}' first.")
    if instance.status not in {InstanceStatus.READY, InstanceStatus.PAUSED, InstanceStatus.PENDING}:
        raise ValueError(f"Cannot SSH into instance with status '{instance.status.value}'.")
    interactive = not remote_command
    if interactive and (not sys.stdin.isatty()):
        raise ValueError('a command is required when stdin is not a TTY')
    returncode = 1
    stdout = ''
    stderr = ''
    snapshot_id = None
    stopped = False
    try:
        with instance.ssh() as ssh:
            if interactive:
                returncode = int(ssh.interactive_shell() or 0)
            else:
                result = ssh.run(list(remote_command))
                returncode = result.returncode
                stdout = result.stdout
                stderr = result.stderr
    finally:
        if create_snapshot_on_exit:
            snapshot_id = instance.snapshot().id
        if rm:
            instance.stop()
            stopped = True
    return {'instance_id': instance.id, 'interactive': interactive, 'returncode': returncode, 'stdout': stdout, 'stderr': stderr, 'snapshot_id': snapshot_id, 'stopped': stopped}

def render_disk_resize(result: DiskResizeOperation, policy: dict[str, Any], inputs: dict[str, Any]) -> None:
    """Show operation identity even when a resize has not completed yet."""
    if inputs.get('json_mode'):
        click.echo(format_json(result.model_dump(mode='json')))
        return
    click.echo(f'Disk resize {result.id}: {result.status}')
    click.echo(f'Capacity: {result.previous_disk_size} → {result.requested_disk_size} MiB')
    click.echo(f'Phase: {result.phase}')
    if result.idempotency_key:
        click.echo(f'Idempotency key: {result.idempotency_key}')
    if result.error:
        click.echo(f'{result.error.code}: {result.error.message}')

def _disk_resize_cli(action: Callable[[], DiskResizeOperation], json_mode: bool) -> DiskResizeOperation:
    try:
        return action()
    except DiskResizeError as exc:
        if json_mode:
            click.echo(format_json({'error': type(exc).__name__, 'message': str(exc), 'operation_id': exc.operation_id, 'status_code': getattr(exc, 'status_code', None), 'error_code': getattr(exc, 'error_code', None), 'idempotency_key': exc.idempotency_key, 'operation': exc.operation.model_dump(mode='json') if exc.operation else None}))
            raise click.exceptions.Exit(1) from exc
        raise click.ClickException(str(exc)) from exc
    except ValueError as exc:
        raise click.BadParameter(str(exc)) from exc

def resize_instance_disk(instance: Instance, disk_size: int, idempotency_key: str | None=None, wait: bool=True, timeout: float=300, json_mode: bool=False) -> DiskResizeOperation:
    """Increase or decrease eligible disk capacity without rebooting.

    A timeout stops waiting; inspect the operation or replay with the same key.
    """
    return _disk_resize_cli(lambda: instance.resize_disk(disk_size=disk_size, idempotency_key=idempotency_key, wait=wait, timeout=timeout), json_mode)

def get_instance_disk_resize(ctx: MorphRuntimeContext, instance_id: str, operation_id: str, json_mode: bool=False) -> DiskResizeOperation:
    """Inspect an existing resize, including failure or recovery state."""
    return _disk_resize_cli(lambda: ctx.client.instances.get_disk_resize(instance_id, operation_id), json_mode)

def wait_instance_disk_resize(ctx: MorphRuntimeContext, instance_id: str, operation_id: str, timeout: float=300, json_mode: bool=False) -> DiskResizeOperation:
    """Wait for an existing resize without submitting another request."""
    return _disk_resize_cli(lambda: ctx.client.instances.wait_disk_resize(instance_id, operation_id, timeout=timeout), json_mode)
